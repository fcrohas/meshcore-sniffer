/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive CONTROL node-discovery resolution.
 * See meshcore_control_recover.h.
 *
 * Reconstructs each candidate row's raw over-the-air frame from its
 * stored raw_hex and re-decodes it exactly like a live frame would
 * be -- decode_control() in meshcore_decoders.c did not exist (or
 * this specific row's CONTROL sub-type wasn't recognized) when the
 * row was first captured, so it was stored opaque (decrypted=0). On
 * a newly resolved NODE_DISCOVER_REQ/_RESP, persists the freshly
 * re-serialized JSON (and, for _RESP, the node's derived pseudo-id)
 * via db_sqlite_apply_control_recover() -- same shape as
 * crc_recover.c / meshcore_redecrypt.c / meshcore_region_recover.c.
 */

#include "meshcore_control_recover.h"

#include "db_sqlite.h"
#include "feed_meshcore_json.h"
#include "jw.h"
#include "meshcore_decoders.h"
#include "meshcore_packet.h"

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

/* Same convention as crc_recover.c/meshcore_redecrypt.c/meshcore_
 * region_recover.c's helper of the same name. */
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

/* Same derivation as the (independently-maintained) static
 * mc_derive_from_id()/mc_node_id() in feed_meshcore_json.c/
 * db_sqlite.c -- first 4 bytes of the responder's public key. Only
 * needed here for NODE_DISCOVER_RESP; REQ carries no pubkey. */
static uint32_t control_resp_node_id(const mesh_event_t *ev)
{
    return ((uint32_t)ev->mc_pubkey[0] << 24) |
           ((uint32_t)ev->mc_pubkey[1] << 16) |
           ((uint32_t)ev->mc_pubkey[2] << 8)  |
            (uint32_t)ev->mc_pubkey[3];
}

int meshcore_control_recover_scan(control_recover_stats_t *stats)
{
    control_recover_stats_t local = {0};

    size_t n = 0;
    db_sqlite_control_candidate_row_t *rows = db_sqlite_query_control_candidates(&n);
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
        /* No channelset needed -- CONTROL carries no channel-keyed
         * encryption of its own (see meshcore_control_recover.h). */
        int rc = meshcore_packet_decode_with_radio(frame, (size_t)frame_len,
                                                    (float)rows[i].rssi_db, (float)rows[i].snr_db,
                                                    rows[i].sf, rows[i].cr, rows[i].bw_hz,
                                                    NULL, capture_cb, &ev);
        if (rc != 0) {
            ++local.decode_failed;
            continue;
        }

        if (ev.mc_payload_type != MC_PAYLOAD_CONTROL || !ev.decrypted || !ev.mc_ctl_subtype[0])
            continue; /* still doesn't match the NODE_DISCOVER_REQ/_RESP convention */

        char node_id_buf[16];
        const char *node_id = NULL;
        if (!strcmp(ev.mc_ctl_subtype, "NODE_DISCOVER_RESP")) {
            snprintf(node_id_buf, sizeof(node_id_buf), "!%08x", control_resp_node_id(&ev));
            node_id = node_id_buf;
        }

        char buf[2048];
        jw_t j;
        jw_init(&j, buf, sizeof(buf));
        feed_serialize_event_meshcore(&j, &ev, NULL, rows[i].ts, false, 0, 0, 0);

        if (db_sqlite_apply_control_recover(rows[i].id, node_id, j.buf, j.len)) {
            ++local.resolved;
            ++updated_total;
        }
    }

    free(rows);
    if (stats) *stats = local;
    return updated_total;
}
