/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive region-scope resolution. See
 * meshcore_region_recover.h.
 *
 * Reconstructs each candidate row's raw over-the-air frame from its
 * stored raw_hex, re-parses/re-decodes it exactly like a live frame
 * would be, then -- unlike the live decode path, which only ever
 * tries meshcore_region_resolve_fast()'s small confirmed-names cache
 * to avoid blocking real-time decode (see meshcore_region_dict.h) --
 * explicitly runs the full wordlist scan (meshcore_region_resolve_
 * full()) here, since a one-shot offline pass has no such latency
 * constraint and the whole point of --region-recover is to catch
 * rows the live fast path never got a chance to resolve. On a newly
 * resolved name, persists the freshly re-serialized JSON via
 * db_sqlite.h's generic (protocol-decode-free) query/update pair --
 * same shape as crc_recover.c / meshcore_redecrypt.c.
 */

#include "meshcore_region_recover.h"

#include "db_sqlite.h"
#include "feed_meshcore_json.h"
#include "jw.h"
#include "meshcore_decoders.h"
#include "meshcore_region_dict.h"
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

/* Same convention as crc_recover.c/meshcore_redecrypt.c's helper of
 * the same name: raw_hex is already capped to <= 512 hex chars (256
 * bytes) at capture time, so truncating defensively is extra safety
 * margin, not an expected path. */
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

int meshcore_region_recover_scan(const meshcore_channelset_t *channels, region_recover_stats_t *stats)
{
    region_recover_stats_t local = {0};

    if (!channels) {
        if (stats) *stats = local;
        return 0;
    }

    size_t n = 0;
    db_sqlite_region_scope_row_t *rows = db_sqlite_query_region_scope_rows(&n);
    if (!rows) {
        if (stats) *stats = local;
        return 0;
    }

    int updated_total = 0;
    for (size_t i = 0; i < n; ++i) {
        ++local.total_candidates;

        uint8_t frame[256];
        int frame_len = hex_decode(rows[i].raw_hex, frame, sizeof(frame));
        if (frame_len < 4) continue;

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

        /* Not actually scoped (SQL filter is a superset check on
         * route_type; the header byte re-decoded from raw_hex is
         * authoritative) -- nothing to resolve for this row. */
        if (!ev.mc_has_region_scope) continue;

        /* meshcore_packet_decode_with_radio() only tried the cheap
         * fast-path cache internally (see meshcore_region_dict.h) --
         * re-parse to get at the raw payload bytes and run the full
         * wordlist scan explicitly, which is the whole point of this
         * one-shot pass. Skip it if the fast path already resolved
         * this row (ev.mc_region_name already set) -- nothing to redo. */
        if (!ev.mc_region_name[0]) {
            meshcore_packet_t pkt;
            if (meshcore_packet_parse(frame, (size_t)frame_len, &pkt) == 0 && pkt.has_transport_codes) {
                meshcore_region_resolve_full(pkt.payload_type, pkt.payload, pkt.payload_len,
                                             pkt.transport_code1, ev.mc_region_name, sizeof(ev.mc_region_name));
            }
        }
        if (!ev.mc_region_name[0]) continue; /* wordlist still doesn't have this region's name */

        char buf[2048];
        jw_t j;
        jw_init(&j, buf, sizeof(buf));
        feed_serialize_event_meshcore(&j, &ev, NULL, rows[i].ts);

        if (db_sqlite_apply_region_recover(rows[i].id, j.buf, j.len)) {
            ++local.resolved;
            ++updated_total;
        }
    }

    free(rows);
    if (stats) *stats = local;
    return updated_total;
}
