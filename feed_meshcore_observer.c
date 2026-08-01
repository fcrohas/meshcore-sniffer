/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: LetsMesh/MeshRank observer JSON schema. See
 * feed_meshcore_observer.h for the field-by-field rationale.
 */

#include "feed_meshcore_observer.h"

#include "meshcore.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

void feed_serialize_event_observer(jw_t *j, const mesh_event_t *ev,
                                   const char *origin, const char *origin_id)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    gmtime_r(&tv.tv_sec, &tmv);

    char timestamp[48], time_s[16], date_s[32];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02d.%06ld",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (long)tv.tv_usec);
    snprintf(time_s, sizeof(time_s), "%02d:%02d:%02d",
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    snprintf(date_s, sizeof(date_s), "%02d/%02d/%04d",
             tmv.tm_mday, tmv.tm_mon + 1, tmv.tm_year + 1900);

    /* Reference schema (chicagolandmesh.org/guides/meshcore/mqtt/) encodes
     * every field as a JSON string, including the numeric-looking ones --
     * mirrored here (via jw_field_str + snprintf) rather than jw_field_u32
     * etc. for wire compatibility with that ingestion pipeline. */
    jw_open(j);
    jw_field_str(j, "origin", origin ? origin : "observer");
    jw_field_str(j, "origin_id", origin_id ? origin_id : "");
    jw_field_str(j, "timestamp", timestamp);
    jw_field_str(j, "type", "PACKET");
    jw_field_str(j, "direction", "rx");
    jw_field_str(j, "time", time_s);
    jw_field_str(j, "date", date_s);

    char numbuf[32];
    size_t raw_len = strlen(ev->raw_hex) / 2;
    snprintf(numbuf, sizeof(numbuf), "%zu", raw_len);
    jw_field_str(j, "len", numbuf);

    snprintf(numbuf, sizeof(numbuf), "%d", ev->mc_payload_type);
    jw_field_str(j, "packet_type", numbuf);

    /* mc_route_type: 0=transport_flood, 1=flood, 2=direct,
     * 3=transport_direct (see feed_meshcore_json.c's route_type_names). */
    bool is_direct = (ev->mc_route_type == 2 || ev->mc_route_type == 3);
    jw_field_str(j, "route", is_direct ? "D" : "F");

    snprintf(numbuf, sizeof(numbuf), "%zu", ev->payload_len);
    jw_field_str(j, "payload_len", numbuf);

    jw_field_str(j, "raw", ev->raw_hex);

    if (ev->snr_db != 0.0f) {
        snprintf(numbuf, sizeof(numbuf), "%.1f", (double)ev->snr_db);
        jw_field_str(j, "SNR", numbuf);
    }
    if (ev->rssi_db != 0.0f) {
        snprintf(numbuf, sizeof(numbuf), "%.0f", (double)ev->rssi_db);
        jw_field_str(j, "RSSI", numbuf);
    }

    /* Direct-route hop path, one hop's hash bytes joined by " -> ", e.g.
     * "C2 -> E2" -- matches the reference schema's "path" field. */
    if (is_direct && ev->mc_hdr_path_hash_count > 0 && ev->mc_hdr_path_hash_size > 0) {
        static const char H[] = "0123456789ABCDEF";
        char path[6 * MC_MAX_PATH_SIZE + 1];
        size_t off = 0;
        int hops = ev->mc_hdr_path_hash_count;
        int size = ev->mc_hdr_path_hash_size;
        int avail_hops = ev->mc_hdr_path_len / size;
        if (hops > avail_hops) hops = avail_hops;
        for (int h = 0; h < hops && off + (size_t)(4 + 2 * size) < sizeof(path); ++h) {
            if (h) { path[off++] = ' '; path[off++] = '-'; path[off++] = '>'; path[off++] = ' '; }
            for (int b = 0; b < size; ++b) {
                uint8_t byte = ev->mc_hdr_path[h * size + b];
                path[off++] = H[(byte >> 4) & 0xF];
                path[off++] = H[byte & 0xF];
            }
        }
        path[off] = '\0';
        if (off) jw_field_str(j, "path", path);
    }

    jw_close(j);
}
