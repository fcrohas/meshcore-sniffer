/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: CayenneLPP decode for MeshCore GRP_DATA blobs.
 *
 * MeshCore's PAYLOAD_TYPE_GRP_DATA (0x06) carries an app-defined
 * data_type(u16 LE) + data_len(u8) + blob, decrypted by
 * meshcore_decode_grp_data() exactly like GRP_TXT (channel_hash +
 * AES-128-ECB + HMAC-SHA256 MAC -- see grp_decrypt() in
 * meshcore_decoders.c). What the *blob* means is entirely up to the
 * originating app: see MeshCore firmware's docs/number_allocations.md
 * for the data_type registry (0100 = "MeshCore Open", 0110-011F =
 * "Ripple", FF00-FFFF = dev/testing). None of that is authoritative
 * or verifiable by a passive sniffer.
 *
 * What IS confirmed from the firmware itself: MeshCore's own
 * point-to-point telemetry response (REQ_TYPE_GET_TELEMETRY_DATA,
 * undecryptable to us -- ECDH RESPONSE) is built with a vendored
 * CayenneLPP encoder/reader (electroniccats/CayenneLPP@1.6.1, plus a
 * MeshCore-local copy in src/helpers/sensors/LPPDataHelpers.h). Since
 * channel-broadcast telemetry apps in the wild (that data_type
 * registry) build on the same firmware primitives, CayenneLPP is the
 * most plausible blob format for any GRP_DATA payload that looks like
 * sensor data -- so this module attempts a best-effort CayenneLPP
 * decode of ANY GRP_DATA blob, independent of data_type, and only
 * reports success if the whole blob parses as a clean, self-
 * consistent run of LPP records (no trailing garbage, no overflow,
 * only known type codes). That validation is what keeps this from
 * false-positiving on non-telemetry app data.
 *
 * Record wire format (matches MeshCore's LPPReader/LPPWriter
 * exactly): repeating records of channel(u8, 0 = end-of-data marker
 * per firmware but this decoder just stops at end-of-buffer) + type
 * (u8) + value (N bytes, big-endian, signed/unsigned and scaled per
 * type -- see the LPP_* table in meshcore_lpp.c).
 */

#ifndef MESHCORE_LPP_H
#define MESHCORE_LPP_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define MESHCORE_LPP_MAX_RECORDS 16

typedef struct {
    uint8_t  channel;
    uint8_t  type;          /* LPP_* code, see meshcore_lpp.c */
    const char *type_name;  /* "temperature", "voltage", ... */
    const char *unit;       /* "C", "V", "%", "" ... */
    int      n_values;      /* 1 for scalar types, 3 for GPS/accelerometer/gyrometer */
    float    values[3];
} meshcore_lpp_record_t;

/* Best-effort decode of `len` bytes at `buf` (a GRP_DATA blob, after
 * the data_type/data_len header) as a CayenneLPP record stream.
 * Returns the number of records decoded (0..MESHCORE_LPP_MAX_RECORDS)
 * on a clean, fully-consumed parse; -1 if the buffer doesn't look
 * like valid LPP data (unknown type code, truncated record, or
 * anything left over after the last record). `len` == 0 always
 * returns -1 (nothing to show, not a valid empty telemetry record). */
int meshcore_lpp_decode(const uint8_t *buf, size_t len,
                        meshcore_lpp_record_t *out, int max_records);

/* Serializes `records` (as returned by meshcore_lpp_decode()) into a
 * compact JSON array, e.g.
 *   [{"ch":1,"type":103,"name":"temperature","unit":"C","value":23.4}, ...]
 * GPS/accelerometer/gyrometer records emit "value":[v0,v1,v2] instead
 * of a scalar. Returns the number of bytes written (excluding NUL),
 * or -1 if `cap` was too small. */
int meshcore_lpp_to_json(const meshcore_lpp_record_t *records, int n_records,
                         char *out, size_t cap);

/* Short human-readable one-line summary, e.g. "temp=23.4C hum=45%
 * batt=3.85V" -- for mc_text / the Debug tab. Returns the number of
 * bytes written (excluding NUL), or -1 if `cap` was too small. */
int meshcore_lpp_to_text(const meshcore_lpp_record_t *records, int n_records,
                         char *out, size_t cap);

#endif /* MESHCORE_LPP_H */
