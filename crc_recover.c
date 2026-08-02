/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive CRC recovery. See crc_recover.h.
 *
 * Reconstructs the raw post-demod byte stream from each candidate
 * row's stored raw_hex (exactly as captured live, before any CRC
 * correction -- a row only reaches crc_ok=0 storage when every tier
 * available at capture time already failed), re-runs the CRC
 * bruteforce tiers against it, and on a match re-parses/re-decrypts
 * and persists via db_sqlite.h's generic (protocol-decode-free)
 * query/update pair -- same shape as meshcore_redecrypt.c.
 */

#include "crc_recover.h"

#include "db_sqlite.h"
#include "feed_meshcore_json.h"
#include "jw.h"
#include "lora.h"
#include "meshcore_decoders.h"
#include "meshcore_packet.h"

#include <stdlib.h>
#include <string.h>

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Same convention as meshcore_redecrypt.c's helper of the same name:
 * raw_hex is already capped to <= 512 hex chars (256 bytes) at
 * capture time, so truncating defensively is extra safety margin,
 * not an expected path. */
static int hex_decode(const char *hex, uint8_t *out, size_t max_out)
{
    size_t hl = strlen(hex);
    if (hl % 2) return -1;
    size_t n = hl / 2;
    if (n > max_out) n = max_out;
    for (size_t i = 0; i < n; ++i) {
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

static void capture_cb(const mesh_event_t *ev, void *user)
{
    *(mesh_event_t *)user = *ev;
}

int meshcore_crc_recover_scan(const meshcore_channelset_t *channels, crc_recover_stats_t *stats)
{
    crc_recover_stats_t local = {0};

    if (!channels) {
        if (stats) *stats = local;
        return 0;
    }

    size_t n = 0;
    db_sqlite_crc_fail_row_t *rows = db_sqlite_query_meshcore_crc_fail_rows(&n);
    if (!rows) {
        if (stats) *stats = local;
        return 0;
    }

    int fixed_total = 0;
    for (size_t i = 0; i < n; ++i) {
        ++local.total_candidates;

        uint8_t frame[256];
        int frame_len = hex_decode(rows[i].raw_hex, frame, sizeof(frame));
        if (frame_len < 4) continue;

        /* Same tiered order as lora.c's state_tick(): single-bit
         * first (always trustworthy), two-bit only if that fails. */
        int bits;
        if (lora_crc_bruteforce_correct(frame, (size_t)frame_len)) {
            bits = 1;
        } else if (lora_crc_bruteforce_correct_2bit(frame, (size_t)frame_len)) {
            bits = 2;
        } else {
            continue;   /* still genuinely unrecoverable */
        }

        mesh_event_t ev;
        memset(&ev, 0, sizeof(ev));
        int rc = meshcore_packet_decode_with_radio(frame, (size_t)frame_len,
                                                    (float)rows[i].rssi_db, (float)rows[i].snr_db,
                                                    rows[i].sf, rows[i].cr, rows[i].bw_hz,
                                                    channels, capture_cb, &ev);
        if (rc != 0) {
            ++local.decode_failed;
            continue;
        }

        ev.has_crc            = true;
        ev.payload_crc_ok     = true;
        ev.crc_corrected      = true;
        ev.crc_corrected_bits = bits;

        /* Same gate as main.c's on_mesh_event(): 2-bit fixes always
         * need independent authentication; 1-bit fixes need it too
         * when the payload type has an authentication mechanism
         * available (ADVERT/GRP_TXT/GRP_DATA) -- free extra
         * confidence against the ~1.5% a priori single-bit collision
         * odds on a ~1000-bit payload, not a new cost. Payload types
         * with no authentication mechanism at all stay trusted at
         * 1-bit, same as always. */
        bool authable = ev.mc_payload_type == MC_PAYLOAD_GRP_TXT ||
                         ev.mc_payload_type == MC_PAYLOAD_GRP_DATA ||
                         ev.mc_payload_type == MC_PAYLOAD_ADVERT;
        bool needs_gate = bits >= 2 || (bits == 1 && authable);
        bool trusted = !needs_gate || mesh_event_crc2bit_trusted(&ev);
        if (!trusted) {
            ++local.untrusted;
            continue;   /* leave the row exactly as it was: crc_ok=0 */
        }

        char buf[2048];
        jw_t j;
        jw_init(&j, buf, sizeof(buf));
        feed_serialize_event_meshcore(&j, &ev, NULL, rows[i].ts, false, 0, 0, 0);

        if (db_sqlite_apply_crc_recover(rows[i].id, bits, ev.decrypted,
                                         ev.channel_name, ev.mc_text, j.buf, j.len)) {
            if (bits == 1) ++local.fixed_1bit; else ++local.fixed_2bit;
            ++fixed_total;
        }
    }

    free(rows);
    if (stats) *stats = local;
    return fixed_total;
}
