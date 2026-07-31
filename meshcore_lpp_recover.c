/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive telemetry (CayenneLPP-over-GRP_DATA)
 * resolution. See meshcore_lpp_recover.h.
 *
 * Reconstructs each candidate row's raw over-the-air frame from its
 * stored raw_hex and re-parses/re-decodes it exactly like a live
 * frame would be -- meshcore_decode_grp_data() re-derives the AES-
 * 128-ECB+HMAC plaintext (needs the right channel secret in
 * `channels`) and, since this session's change, always attempts a
 * CayenneLPP decode of the blob as part of that same call. On a
 * newly non-empty mc_telemetry_json, persists the freshly re-
 * serialized JSON via db_sqlite.h's generic (protocol-decode-free)
 * query/update pair -- same shape as crc_recover.c/
 * meshcore_redecrypt.c/meshcore_region_recover.c.
 */

#include "meshcore_lpp_recover.h"

#include "db_sqlite.h"
#include "feed_meshcore_json.h"
#include "jw.h"
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

/* Same convention as crc_recover.c/meshcore_redecrypt.c/
 * meshcore_region_recover.c's helper of the same name: raw_hex is
 * already capped to <= 512 hex chars (256 bytes) at capture time, so
 * truncating defensively is extra safety margin, not an expected
 * path. */
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

int meshcore_lpp_recover_scan(const meshcore_channelset_t *channels, telemetry_recover_stats_t *stats)
{
    telemetry_recover_stats_t local = {0};

    if (!channels) {
        if (stats) *stats = local;
        return 0;
    }

    size_t n = 0;
    db_sqlite_telemetry_candidate_row_t *rows = db_sqlite_query_telemetry_candidates(&n);
    if (!rows) {
        if (stats) *stats = local;
        return 0;
    }

    int updated_total = 0;
    for (size_t i = 0; i < n; ++i) {
        ++local.total_candidates;

        uint8_t frame[256];
        int frame_len = hex_decode(rows[i].raw_hex, frame, sizeof(frame));
        if (frame_len < 4) { ++local.decode_failed; continue; }

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

        /* Not actually GRP_DATA, or the channel needed to re-decrypt
         * it isn't loaded in `channels` -- nothing new to persist for
         * this row (the SQL filter is a superset check; the re-parsed
         * header/decrypted flag are authoritative). */
        if (ev.mc_payload_type != MC_PAYLOAD_GRP_DATA || !ev.decrypted) continue;
        if (!ev.mc_telemetry_json[0]) continue; /* still doesn't parse as CayenneLPP */

        char buf[2048];
        jw_t j;
        jw_init(&j, buf, sizeof(buf));
        feed_serialize_event_meshcore(&j, &ev, NULL, rows[i].ts);

        if (db_sqlite_apply_telemetry_recover(rows[i].id, ev.mc_telemetry_json, j.buf, j.len)) {
            ++local.resolved;
            ++updated_total;
        }
    }

    free(rows);
    if (stats) *stats = local;
    return updated_total;
}
