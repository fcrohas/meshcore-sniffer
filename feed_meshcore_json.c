/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: JSON serialization of MeshCore mesh_event_t
 * events. Split out of feed.c so it can be unit tested directly
 * without linking mqtt/zmq/cot/gpsd/geofence/options.
 *
 * Also owns the MeshCore -> node_db wiring: node_db.c/web.c are
 * protocol-agnostic (keyed by a uint32 "from" id), but until now only
 * the Meshtastic NODEINFO_APP path ever called node_db_remember(), and
 * no MeshCore event ever emitted a generic "from" JSON field. The
 * built-in web dashboard's JS gates almost all per-event handling
 * (map markers, node list, message log, per-channel stats) behind
 * `if (!p.from) return;` -- so MeshCore events, having no "from" at
 * all, were silently invisible to the dashboard even though they were
 * fully decoded and reached feed_publish_event(). See mc_derive_from_id().
 */

#include "feed_meshcore_json.h"

#include "meshcore.h"
#include "node_db.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/* Derive a stable pseudo node-id (Meshtastic-style 32-bit "from") for
 * a MeshCore event, so the existing generic-"from"-keyed node_db /
 * web dashboard machinery works unmodified for MeshCore too, exactly
 * like it already does for the Meshtastic path -- no new parallel
 * mechanism needed.
 *
 *   - ADVERT / ANON_REQ carry a 32-byte Ed25519 pubkey: use its first
 *     4 bytes as the id. Stable per physical node across packets.
 *     CONTROL's NODE_DISCOVER_RESP sub-type (application convention,
 *     see MC_CTL_TYPE_NODE_DISCOVER_RESP in meshcore.h) reveals the
 *     same kind of pubkey in the clear -- reuses mc_pubkey/the same
 *     id derivation, so a responding repeater lights up the node
 *     list/map exactly like an ADVERT would.
 *   - GRP_TXT / GRP_DATA (channel broadcast) carry no sender identity
 *     visible to a passive sniffer -- group by channel hash instead
 *     (tagged with the top bit set) so messages on the same channel
 *     stay visible under one dashboard entry rather than being
 *     dropped entirely.
 *   - Envelope-only types (REQ/RESPONSE/PATH) that exposed a
 *     dest/src hash get a low-quality id from those bytes (tagged
 *     with a different high bit) so they're at least visible.
 *   - Everything else (ACK, MULTIPART, CONTROL's other sub-types,
 *     unknown frames) has no usable identity; returns 0, and the
 *     caller omits "from" for those, matching prior behavior (they
 *     were never actionable sightings).
 */
static uint32_t mc_derive_from_id(const mesh_event_t *ev)
{
    if (ev->mc_payload_type == MC_PAYLOAD_ADVERT ||
        ev->mc_payload_type == MC_PAYLOAD_ANON_REQ ||
        (ev->mc_payload_type == MC_PAYLOAD_CONTROL && ev->decrypted &&
         !strcmp(ev->mc_ctl_subtype, "NODE_DISCOVER_RESP"))) {
        return ((uint32_t)ev->mc_pubkey[0] << 24) |
               ((uint32_t)ev->mc_pubkey[1] << 16) |
               ((uint32_t)ev->mc_pubkey[2] << 8)  |
                (uint32_t)ev->mc_pubkey[3];
    }
    if (ev->mc_payload_type == MC_PAYLOAD_GRP_TXT ||
        ev->mc_payload_type == MC_PAYLOAD_GRP_DATA) {
        return 0x80000000u | ev->mc_channel_hash;
    }
    if (ev->mc_dest_hash || ev->mc_src_hash) {
        return 0x40000000u | ((uint32_t)ev->mc_dest_hash << 8) | ev->mc_src_hash;
    }
    return 0;
}

void feed_serialize_event_meshcore(jw_t *j, const mesh_event_t *ev,
                                   const char *station_id, double ts_override,
                                   bool have_station, double station_lat,
                                   double station_lon, double station_alt_m)
{
    jw_open(j);
    if (station_id) jw_field_str(j, "station", station_id);

    double ts = ts_override;
    if (ts <= 0.0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        ts = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
    }
    jw_field_f64(j, "ts", ts);

    /* Station GPS, mirroring feed.c's Meshtastic path -- see this
     * function's doc comment in feed_meshcore_json.h for why this
     * arrives as parameters instead of reading gpsd.h/options.h
     * globals directly. */
    if (have_station) {
        jw_field_f64(j, "station_lat", station_lat);
        jw_field_f64(j, "station_lon", station_lon);
        if (station_alt_m != 0.0) jw_field_f32(j, "station_alt_m", (float)station_alt_m);
    }

    jw_field_str(j, "protocol",     "meshcore");
    jw_field_str(j, "mc_type",      ev->mc_type_name[0] ? ev->mc_type_name : "UNKNOWN");
    jw_field_u32(j, "route_type",   (uint32_t)ev->mc_route_type);
    {
        static const char *route_type_names[] = {
            "transport_flood", "flood", "direct", "transport_direct",
        };
        const char *rtn = (ev->mc_route_type >= 0 && ev->mc_route_type < 4)
                         ? route_type_names[ev->mc_route_type] : "unknown";
        jw_field_str(j, "route_type_name", rtn);
    }
    if (ev->mc_has_region_scope) {
        jw_field_bool(j, "region_scope", true);
        jw_field_u32(j, "region_code1", (uint32_t)ev->mc_region_code1);
        jw_field_u32(j, "region_code2", (uint32_t)ev->mc_region_code2);
        if (ev->mc_region_name[0])
            jw_field_str(j, "region_name", ev->mc_region_name);
    }
    /* Header-level routing path: present on every payload_type's
     * packet framing, but its MEANING differs for TRACE. For every
     * other payload_type it's the accumulated relay-hash trail (FLOOD)
     * or intended hop sequence (DIRECT) -- emitted below as
     * route_path_hex. For TRACE, this same header path[] field is
     * repurposed by the firmware to carry accumulated per-hop SNR
     * bytes, not hashes (see meshcore_decode_trace() in
     * meshcore_decoders.c) -- emitting those under "route_path_hex"
     * would mislead a consumer into treating SNR bytes as routing
     * hashes, so TRACE gets its own field names instead. */
    if (ev->mc_payload_type == MC_PAYLOAD_TRACE) {
        if (ev->decrypted && ev->mc_path_hop_count > 0) {
            int n = ev->mc_path_hop_count;
            if (n > MC_MAX_PATH_SIZE) n = MC_MAX_PATH_SIZE;
            char hashes_hex[2 * MC_MAX_PATH_SIZE + 1];
            char snrs_hex[2 * MC_MAX_PATH_SIZE + 1];
            static const char H[] = "0123456789abcdef";
            for (int k = 0; k < n; ++k) {
                hashes_hex[2*k]     = H[(ev->mc_path_hashes[k] >> 4) & 0xF];
                hashes_hex[2*k + 1] = H[ ev->mc_path_hashes[k]       & 0xF];
                snrs_hex[2*k]       = H[(ev->mc_path_snrs[k] >> 4) & 0xF];
                snrs_hex[2*k + 1]   = H[ ev->mc_path_snrs[k]       & 0xF];
            }
            hashes_hex[2 * n] = '\0';
            snrs_hex[2 * n]   = '\0';
            jw_field_str(j, "trace_route_hashes_hex", hashes_hex);
            jw_field_str(j, "trace_snrs_hex", snrs_hex);
        }
    } else if (ev->mc_hdr_path_hash_count > 0) {
        jw_field_u32(j, "route_path_hash_count", (uint32_t)ev->mc_hdr_path_hash_count);
        jw_field_u32(j, "route_path_hash_size",  (uint32_t)ev->mc_hdr_path_hash_size);
        char hex[2 * sizeof(ev->mc_hdr_path) + 1];
        static const char H[] = "0123456789abcdef";
        int n = ev->mc_hdr_path_len;
        for (int k = 0; k < n; ++k) {
            hex[2*k]     = H[(ev->mc_hdr_path[k] >> 4) & 0xF];
            hex[2*k + 1] = H[ ev->mc_hdr_path[k]       & 0xF];
        }
        hex[2 * n] = '\0';
        jw_field_str(j, "route_path_hex", hex);
    }
    jw_field_u32(j, "payload_type", (uint32_t)ev->mc_payload_type);
    jw_field_u32(j, "payload_ver",  (uint32_t)ev->mc_payload_ver);
    jw_field_bool(j, "decrypted",   ev->decrypted);

    /* Generic node-identity field, consumed the same way the
     * Meshtastic path's "from" is consumed by node_db.c / web.c. See
     * mc_derive_from_id() above for why this was missing entirely. */
    uint32_t from_id = mc_derive_from_id(ev);
    if (from_id) {
        char id_buf[16];
        snprintf(id_buf, sizeof(id_buf), "!%08x", from_id);
        jw_field_str(j, "from", id_buf);
    }

    if (ev->slot_id >= 0)
        jw_field_u32(j, "slot_id", (uint32_t)ev->slot_id);
    if (ev->rssi_db != 0.0f) jw_field_f32(j, "rssi_db", ev->rssi_db);
    if (ev->snr_db  != 0.0f) jw_field_f32(j, "snr_db",  ev->snr_db);
    /* has_crc/payload_crc_ok mirror the Meshtastic path's fields (see
     * serialize_event() in feed.c); crc_corrected additionally flags a
     * frame recovered via lora_crc_bruteforce_correct()'s single-bit
     * search or the two-bit fallback (crc_corrected_bits==2 only ever
     * reaches here after main.c's on_mesh_event has confirmed
     * independent authentication -- mesh_event_crc2bit_trusted()). */
    if (ev->has_crc) {
        jw_field_bool(j, "payload_crc_ok", ev->payload_crc_ok);
        if (ev->payload_crc_ok && ev->crc_corrected) {
            jw_field_bool(j, "crc_corrected", true);
            jw_field_u32(j, "crc_corrected_bits", (uint32_t)ev->crc_corrected_bits);
        }
    }
    if (ev->sf > 0) {
        jw_field_u32(j, "sf",    (uint32_t)ev->sf);
        jw_field_u32(j, "cr",    (uint32_t)ev->cr);
        jw_field_u32(j, "bw_hz", (uint32_t)ev->bw_hz);
        if (ev->freq_hz) jw_field_u64(j, "freq_hz", ev->freq_hz);
    }
    if (ev->channel_name[0]) jw_field_str(j, "channel_name", ev->channel_name);
    if (ev->mc_channel_hash) jw_field_u32(j, "channel_hash", ev->mc_channel_hash);
    if (ev->mc_dest_hash)    jw_field_u32(j, "dest_hash", ev->mc_dest_hash);
    if (ev->mc_src_hash)     jw_field_u32(j, "src_hash",  ev->mc_src_hash);
    if (ev->mc_timestamp)    jw_field_u32(j, "mc_timestamp", ev->mc_timestamp);
    if (ev->raw_hex[0])      jw_field_str(j, "raw_hex", ev->raw_hex);
    /* CRC-failed frames have corrupt bytes by definition (see on_mesh_event
     * in main.c, which forces decrypted=false on payload_crc_ok==false).
     * ADVERT/TRACE/ACK are normally "decrypted=true" because there is
     * nothing to decrypt -- but the parser still ran on the corrupt bytes
     * and mc_adv_type/mc_node_name/mc_lat/mc_lon/mc_extra1/mc_extra2/
     * mc_sig_valid are just as fictitious as a bogus Meshtastic protobuf
     * decode would be. Gate every field earned only by parsing payload
     * bytes behind ev->decrypted, mirroring the Meshtastic per-port
     * decoded-field guard above. */
    if (ev->decrypted && ev->mc_payload_type == MC_PAYLOAD_ADVERT) {
        static const char *adv_type_names[] = {
            "NONE", "CHAT", "REPEATER", "ROOM", "SENSOR",
        };
        const char *adv_type_name = ev->mc_adv_type < 5
            ? adv_type_names[ev->mc_adv_type] : "UNKNOWN";
        jw_field_u32(j, "adv_type", (uint32_t)ev->mc_adv_type);
        jw_field_str(j, "adv_type_name", adv_type_name);
        if (ev->mc_has_latlon) {
            jw_field_f64(j, "lat", ev->mc_lat);
            jw_field_f64(j, "lon", ev->mc_lon);
        }
        if (ev->mc_extra1) jw_field_u32(j, "extra1", (uint32_t)ev->mc_extra1);
        if (ev->mc_extra2) jw_field_u32(j, "extra2", (uint32_t)ev->mc_extra2);
    }
    if (ev->decrypted && ev->mc_node_name[0]) {
        jw_field_str(j, "node_name", ev->mc_node_name);
        /* Also emit the generic "long_name" field the web dashboard's
         * JS already uses to label the Meshtastic node list/markers
         * (`if (p.long_name) n.name = ...`), so a MeshCore ADVERT's
         * name shows up there the same way, without any dashboard-JS
         * changes. */
        jw_field_str(j, "long_name", ev->mc_node_name);
    }
    if (ev->decrypted && ev->mc_text[0]) jw_field_str(j, "text", ev->mc_text);
    if (ev->decrypted && ev->mc_payload_type == MC_PAYLOAD_GRP_TXT) {
        static const char *txt_type_names[] = { "PLAIN", "CLI_DATA", "SIGNED_PLAIN" };
        jw_field_u32(j, "txt_type", (uint32_t)ev->mc_txt_type);
        jw_field_str(j, "txt_type_name",
                    ev->mc_txt_type < 3 ? txt_type_names[ev->mc_txt_type] : "UNKNOWN");
    }
    if (ev->decrypted && ev->mc_path_hop_count > 0)
        jw_field_u32(j, "path_hop_count", (uint32_t)ev->mc_path_hop_count);
    if (ev->decrypted && ev->mc_payload_type == MC_PAYLOAD_ADVERT)
        jw_field_bool(j, "sig_valid", ev->mc_sig_valid);
    if (ev->mc_payload_type == MC_PAYLOAD_GRP_DATA && ev->decrypted) {
        jw_field_u32(j, "data_type", (uint32_t)ev->mc_data_type);
        jw_field_u32(j, "data_len",  (uint32_t)ev->mc_data_len);
        /* Best-effort CayenneLPP decode of the blob (meshcore_lpp.c),
         * "" when it didn't parse as valid LPP -- see mc_telemetry_json's
         * doc comment in mesh_packet.h. Embedded raw (not string-
         * escaped): it's already a JSON array. */
        jw_field_raw(j, "telemetry", ev->mc_telemetry_json);
    }
    if (ev->mc_payload_type == MC_PAYLOAD_MULTIPART) {
        jw_field_u32(j, "multipart_remaining", (uint32_t)ev->mc_multipart_remaining);
        jw_field_str(j, "multipart_inner_type", mc_payload_type_name(ev->mc_multipart_inner_type));
        /* decrypted/timestamp only meaningful when the wrapped payload
         * was itself cleartext (ACK) -- see decode_multipart()'s doc
         * comment in meshcore_decoders.c. */
        if (ev->decrypted) jw_field_u32(j, "ack_crc", ev->mc_timestamp);
    }
    if (ev->mc_payload_type == MC_PAYLOAD_CONTROL && ev->mc_ctl_subtype[0]) {
        /* CTL_TYPE_NODE_DISCOVER_REQ/_RESP is an application convention
         * (see MC_CTL_TYPE_NODE_DISCOVER_REQ's doc comment in
         * meshcore.h), not a protocol guarantee -- mc_ctl_subtype is
         * only ever non-empty when this specific convention matched. */
        jw_field_str(j, "ctl_subtype", ev->mc_ctl_subtype);
        jw_field_u32(j, "ctl_tag", ev->mc_ctl_tag);
        if (!strcmp(ev->mc_ctl_subtype, "NODE_DISCOVER_REQ")) {
            jw_field_u32(j, "ctl_filter", (uint32_t)ev->mc_ctl_filter);
            if (ev->mc_ctl_since) jw_field_u32(j, "ctl_since", ev->mc_ctl_since);
        } else if (!strcmp(ev->mc_ctl_subtype, "NODE_DISCOVER_RESP")) {
            static const char *adv_type_names[] = {
                "NONE", "CHAT", "REPEATER", "ROOM", "SENSOR",
            };
            const char *adv_type_name = ev->mc_adv_type < 5
                ? adv_type_names[ev->mc_adv_type] : "UNKNOWN";
            jw_field_u32(j, "adv_type", (uint32_t)ev->mc_adv_type);
            jw_field_str(j, "adv_type_name", adv_type_name);
            jw_field_f32(j, "ctl_snr", ev->mc_ctl_snr);
        }
    }

    jw_close(j);

    /* node_db wiring: mirror the Meshtastic NODEINFO_APP path in
     * feed.c (node_db_remember(ev->header.from, u.long_name, ...)) so
     * an ADVERT's name (and, via node_db_lookup consumers, its
     * position) is queryable the same way for both protocols. Gated
     * on from_id != 0 -- ADVERT always derives a nonzero id from its
     * pubkey (see mc_derive_from_id), so this only no-ops for the
     * (impossible in practice) all-zero-pubkey case.
     *
     * CONTROL's NODE_DISCOVER_RESP (see mc_derive_from_id()'s doc
     * comment) reveals the same kind of pubkey/role in the clear but
     * never a name -- still worth registering (empty long_name is a
     * safe no-op in node_db_remember(), never clobbers a name learned
     * from a real ADVERT) so a repeater that only ever answers
     * discovery probes still lights up the node list/map with its
     * role, instead of staying invisible until it happens to send a
     * fresh ADVERT. */
    bool is_advert_named = ev->mc_payload_type == MC_PAYLOAD_ADVERT && ev->mc_has_name;
    bool is_ctl_discover_resp = ev->mc_payload_type == MC_PAYLOAD_CONTROL &&
                                !strcmp(ev->mc_ctl_subtype, "NODE_DISCOVER_RESP");
    if (ev->decrypted && from_id && (is_advert_named || is_ctl_discover_resp)) {
        /* role: persists mc_adv_type (NONE/CHAT/REPEATER/ROOM/SENSOR,
         * same small enum as adv_type_name above) into the nodes
         * table's generic "role" column, purely a MeshCore <-> Meshtastic
         * naming coincidence -- Meshtastic's own NODEINFO_APP role enum
         * is unrelated and larger. Not a collision in practice: a
         * running instance is always single-protocol (--protocol is
         * mutually exclusive), and node_db_remember() never overwrites
         * role with 0 (partial-update semantics), so this only ever
         * *adds* information. Read back by bootstrapNodesFromApi() in
         * web.c to style a repeater's map marker correctly from the
         * very first page load, not just after a live ADVERT arrives. */
        node_db_remember(from_id, ev->mc_node_name, "", 0, ev->mc_adv_type);
    }
}
