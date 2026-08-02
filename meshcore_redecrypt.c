/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive re-decrypt of historically-stored
 * MeshCore rows. See meshcore_redecrypt.h.
 *
 * Reconstructs a mesh_event_t from each candidate row's stored
 * raw_hex (the full over-the-air frame, exactly as captured live) plus
 * its stored radio metadata columns, re-parses and re-decrypts it the
 * same way meshcore_packet_decode_with_radio() does for a live frame,
 * and on success re-serializes + persists it via db_sqlite.h's
 * generic (protocol-decode-free) query/update pair.
 */

#include "meshcore_redecrypt.h"

#include "db_sqlite.h"
#include "feed_meshcore_json.h"
#include "jw.h"
#include "meshcore_decoders.h"
#include "meshcore_packet.h"
#include "meshcore_region_dict.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes hex into out, up to max_out bytes. raw_hex is already
 * capped to <= 512 hex chars (256 bytes) at capture time (see
 * meshcore_packet_decode_with_radio()'s hex_dump() call), so
 * truncating defensively here rather than failing on an oversized
 * string is just extra safety margin, not an expected path. */
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

int meshcore_redecrypt_channel(uint8_t channel_hash, const meshcore_channelset_t *channels)
{
    if (!channels) return 0;

    size_t n = 0;
    db_sqlite_undecrypted_row_t *rows = db_sqlite_query_undecrypted_channel_rows(channel_hash, &n);
    if (!rows) return 0;

    int fixed = 0;
    for (size_t i = 0; i < n; ++i) {
        uint8_t frame[256];
        int frame_len = hex_decode(rows[i].raw_hex, frame, sizeof(frame));
        if (frame_len <= 0) continue;

        meshcore_packet_t pkt;
        if (meshcore_packet_parse(frame, (size_t)frame_len, &pkt) < 0) continue;
        if (pkt.payload_type != MC_PAYLOAD_GRP_TXT && pkt.payload_type != MC_PAYLOAD_GRP_DATA)
            continue;

        mesh_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.is_meshcore     = true;
        ev.rssi_db         = (float)rows[i].rssi_db;
        ev.snr_db          = (float)rows[i].snr_db;
        ev.sf              = rows[i].sf;
        ev.cr              = rows[i].cr;
        ev.bw_hz           = rows[i].bw_hz;
        ev.slot_id         = -1;
        ev.mc_route_type   = pkt.route_type;
        ev.mc_payload_type = pkt.payload_type;
        ev.mc_payload_ver  = pkt.payload_ver;
        ev.mc_hdr_path_hash_count = pkt.path_hash_count;
        ev.mc_hdr_path_hash_size  = pkt.path_hash_size;
        ev.mc_hdr_path_len = pkt.path_len < sizeof(ev.mc_hdr_path)
                            ? (int)pkt.path_len : (int)sizeof(ev.mc_hdr_path);
        memcpy(ev.mc_hdr_path, pkt.path, (size_t)ev.mc_hdr_path_len);
        ev.mc_has_region_scope = pkt.has_transport_codes;
        if (pkt.has_transport_codes) {
            ev.mc_region_code1 = pkt.transport_code1;
            ev.mc_region_code2 = pkt.transport_code2;
            /* Fast-only here too -- this can run over many rows in a
             * burst when a channel is newly cracked; see
             * meshcore_region_dict.h. */
            if (!meshcore_region_resolve_fast(pkt.payload_type, pkt.payload, pkt.payload_len,
                                              pkt.transport_code1, ev.mc_region_name, sizeof(ev.mc_region_name)))
                meshcore_region_dict_enqueue(pkt.payload_type, pkt.payload, pkt.payload_len, pkt.transport_code1);
        }
        snprintf(ev.raw_hex, sizeof(ev.raw_hex), "%s", rows[i].raw_hex);

        bool ok = (pkt.payload_type == MC_PAYLOAD_GRP_TXT)
                ? meshcore_decode_grp_txt(&pkt, channels, &ev)
                : meshcore_decode_grp_data(&pkt, channels, &ev);
        if (!ok || !ev.decrypted) continue;

        char buf[2048];
        jw_t j;
        jw_init(&j, buf, sizeof(buf));
        feed_serialize_event_meshcore(&j, &ev, NULL, rows[i].ts, false, 0, 0, 0);

        if (db_sqlite_apply_redecrypt(rows[i].id, ev.channel_name, ev.mc_text, j.buf, j.len))
            ++fixed;
    }

    free(rows);
    return fixed;
}
