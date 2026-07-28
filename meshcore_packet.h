/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore packet parser + crypto.
 */

#ifndef MESHCORE_PACKET_H
#define MESHCORE_PACKET_H

#include "meshcore.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct meshcore_packet {
    int      route_type;    /* mc_route_type_t */
    int      payload_type;  /* mc_payload_type_t */
    int      payload_ver;

    bool     has_transport_codes;
    uint16_t transport_code1;
    uint16_t transport_code2;

    uint8_t  path[MC_MAX_PATH_SIZE];
    size_t   path_len;         /* bytes */
    int      path_hash_count;  /* number of hops in path[] */
    int      path_hash_size;   /* bytes per hop hash: 1, 2, or 3 */

    uint8_t  payload[MC_MAX_PACKET_PAYLOAD];
    size_t   payload_len;
} meshcore_packet_t;

/* Decode the header/path/payload framing of a raw MeshCore LoRa
 * frame. Does not touch payload[] semantics (caller dispatches by
 * payload_type). Returns 0 on success, -1 if malformed/too short. */
int meshcore_packet_parse(const uint8_t *raw, size_t len, meshcore_packet_t *out);

/* Verify HMAC-SHA256(secret[0:secret_len], ciphertext)[0:2] against the
 * 2 MAC bytes at the front of enc_with_mac, then AES-128-ECB decrypt the
 * remaining bytes (zero-padded final block, key = secret[0:16]).
 * secret_len must be 16 or 32 (channel PSK length).
 * out_plain must have room for at least enc_len - MC_CIPHER_MAC_SIZE
 * bytes rounded up to a 16-byte multiple.
 * Returns 0 on success (MAC ok + decrypted), -1 on MAC mismatch or
 * any crypto error. */
int meshcore_verify_and_decrypt(const uint8_t *secret, size_t secret_len,
                                const uint8_t *enc_with_mac, size_t enc_len,
                                uint8_t *out_plain, size_t *out_len);

#endif /* MESHCORE_PACKET_H */
