/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore packet parser + crypto.
 *
 * Wire format of a MeshCore LoRa frame (after CSS demod, before any
 * application parsing):
 *
 *   byte[0]      header: route_type(2b) | payload_type(4b) | payload_ver(2b)
 *   [transport_codes]    2x uint16 LE, only if route_type is
 *                        TRANSPORT_FLOOD(0) or TRANSPORT_DIRECT(3)
 *   byte[]       path_len: hash_count(6b) | (hash_size-1)(2b)
 *   path[]       hash_count * hash_size bytes
 *   payload[]    remaining bytes (<= MC_MAX_PACKET_PAYLOAD)
 *
 * Crypto (V1, payload_ver 0, hash_size 1, MAC 2 bytes):
 *   AES-128-ECB per 16-byte block, zero-padded on the final partial
 *   block, key = shared_secret[0:16]. Integrity = HMAC-SHA256(secret32,
 *   ciphertext) truncated to 2 bytes, compared against the MAC bytes
 *   in the payload.
 */

#include "meshcore_packet.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

int meshcore_packet_parse(const uint8_t *raw, size_t len, meshcore_packet_t *out)
{
    if (!raw || !out || len < 2) return -1;
    memset(out, 0, sizeof(*out));

    const uint8_t *p   = raw;
    const uint8_t *end = raw + len;

    uint8_t header = *p++;
    out->route_type   = header & MC_HEADER_ROUTE_TYPE_MASK;
    out->payload_type = (header & MC_HEADER_PAYLOAD_TYPE_MASK) >> MC_HEADER_PAYLOAD_TYPE_SHIFT;
    out->payload_ver  = (header & MC_HEADER_PAYLOAD_VER_MASK)  >> MC_HEADER_PAYLOAD_VER_SHIFT;

    out->has_transport_codes = mc_route_has_transport_codes(out->route_type);
    if (out->has_transport_codes) {
        if ((size_t)(end - p) < 4) return -1;
        out->transport_code1 = rd_le16(p);     p += 2;
        out->transport_code2 = rd_le16(p);     p += 2;
    }

    if (p >= end) return -1;
    uint8_t path_len_byte = *p++;
    out->path_hash_count = path_len_byte & MC_PATHLEN_HASH_COUNT_MASK;
    out->path_hash_size  = ((path_len_byte & MC_PATHLEN_HASH_SIZE_MASK) >> MC_PATHLEN_HASH_SIZE_SHIFT) + 1;
    if (out->path_hash_size < 1 || out->path_hash_size > 3) return -1;

    size_t path_bytes = (size_t)out->path_hash_count * (size_t)out->path_hash_size;
    if (path_bytes > MC_MAX_PATH_SIZE) return -1;
    if ((size_t)(end - p) < path_bytes) return -1;
    if (path_bytes > 0) memcpy(out->path, p, path_bytes);
    out->path_len = path_bytes;
    p += path_bytes;

    size_t payload_len = (size_t)(end - p);
    if (payload_len > MC_MAX_PACKET_PAYLOAD) payload_len = MC_MAX_PACKET_PAYLOAD;
    if (payload_len > 0) memcpy(out->payload, p, payload_len);
    out->payload_len = payload_len;

    return 0;
}

int meshcore_verify_and_decrypt(const uint8_t *secret, size_t secret_len,
                                const uint8_t *enc_with_mac, size_t enc_len,
                                uint8_t *out_plain, size_t *out_len)
{
    if (!secret || !enc_with_mac || !out_plain || !out_len) return -1;
    if (secret_len != 16 && secret_len != 32) return -1;
    if (enc_len < MC_CIPHER_MAC_SIZE) return -1;

    const uint8_t *mac_bytes = enc_with_mac;
    const uint8_t *ciphertext = enc_with_mac + MC_CIPHER_MAC_SIZE;
    size_t cipher_len = enc_len - MC_CIPHER_MAC_SIZE;

    /* HMAC-SHA256(secret, ciphertext) truncated to 2 bytes. The HMAC
     * key is ALWAYS 32 bytes (MC_PUB_KEY_SIZE), zero-padded when the
     * real PSK is 16 bytes -- upstream's GroupChannel::secret is a
     * fixed uint8_t[32] buffer (Mesh.h), zero-filled by addChannel()
     * before the (possibly 16-byte) PSK is copied in, and
     * Utils::MACThenDecrypt/encryptThenMAC always call
     * resetHMAC(secret, PUB_KEY_SIZE=32) regardless of the real PSK
     * length. Only AES-128 keying (below) uses just the first 16
     * bytes. Using secret_len (16) as the HMAC key length here used
     * to make every GRP_TXT/GRP_DATA on a 16-byte-PSK channel --
     * including the default "Public" channel -- fail MAC verification
     * against a real MeshCore transmitter. */
    uint8_t hmac_key[MC_PUB_KEY_SIZE] = {0};
    memcpy(hmac_key, secret, secret_len);

    unsigned char hmac_full[EVP_MAX_MD_SIZE];
    unsigned int  hmac_len = 0;
    if (!HMAC(EVP_sha256(), hmac_key, MC_PUB_KEY_SIZE,
              ciphertext, cipher_len, hmac_full, &hmac_len))
        return -1;
    if (hmac_len < MC_CIPHER_MAC_SIZE) return -1;
    if (memcmp(hmac_full, mac_bytes, MC_CIPHER_MAC_SIZE) != 0)
        return -1;  /* MAC mismatch -- wrong key or corrupted frame */

    if (cipher_len == 0) { *out_len = 0; return 0; }

    /* AES-128-ECB, per 16-byte block, zero-padded final partial block.
     * OpenSSL's EVP ECB path applies PKCS7 padding by default on
     * decrypt, which MeshCore does not use, so we disable padding and
     * decrypt block-by-block ourselves (zero-pad the last partial
     * block on the *input* side before decrypting it -- MeshCore pads
     * plaintext with zero bytes before encryption, never the other
     * way around, so the trailing zero bytes come out in the
     * plaintext and the caller trims via out_len / higher-level
     * framing, matching upstream behavior). */
    size_t n_blocks = (cipher_len + MC_CIPHER_BLOCK_SIZE - 1) / MC_CIPHER_BLOCK_SIZE;
    size_t padded_len = n_blocks * MC_CIPHER_BLOCK_SIZE;

    uint8_t in_buf[MC_MAX_PACKET_PAYLOAD + MC_CIPHER_BLOCK_SIZE];
    if (padded_len > sizeof(in_buf)) return -1;
    memset(in_buf, 0, padded_len);
    memcpy(in_buf, ciphertext, cipher_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int rc = -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret, NULL) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outlen1 = 0, outlen2 = 0;
        if (EVP_DecryptUpdate(ctx, out_plain, &outlen1, in_buf, (int)padded_len) == 1 &&
            EVP_DecryptFinal_ex(ctx, out_plain + outlen1, &outlen2) == 1) {
            *out_len = (size_t)(outlen1 + outlen2);
            /* Trim back down to the original (unpadded) cipher length --
             * the zero-padding was only needed to complete the final
             * AES block, the true plaintext is the same length as the
             * ciphertext that was actually on the wire. */
            if (*out_len > cipher_len) *out_len = cipher_len;
            rc = 0;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
