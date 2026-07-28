/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore protocol constants.
 *
 * The wire-format constants below (header bit layout, payload types,
 * route types, sync word) are the MeshCore over-the-air protocol,
 * derived from the upstream firmware at
 * https://github.com/meshcore-dev/MeshCore (GPL-3.0-or-later /
 * MIT-family, see upstream repo). All implementation here is
 * original; only the on-the-air constants come from the firmware.
 *
 */

#ifndef MESHCORE_H
#define MESHCORE_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Header byte (byte[0]) bit layout ---- */

#define MC_HEADER_ROUTE_TYPE_MASK   0x03  /* bits[1:0] */
#define MC_HEADER_PAYLOAD_TYPE_MASK 0x3C  /* bits[5:2] */
#define MC_HEADER_PAYLOAD_TYPE_SHIFT 2
#define MC_HEADER_PAYLOAD_VER_MASK  0xC0  /* bits[7:6] */
#define MC_HEADER_PAYLOAD_VER_SHIFT 6

/* ---- route_type (2 bits) ---- */
typedef enum {
    MC_ROUTE_TRANSPORT_FLOOD  = 0,
    MC_ROUTE_FLOOD            = 1,
    MC_ROUTE_DIRECT           = 2,
    MC_ROUTE_TRANSPORT_DIRECT = 3,
} mc_route_type_t;

static inline bool mc_route_has_transport_codes(int route_type)
{
    return route_type == MC_ROUTE_TRANSPORT_FLOOD ||
           route_type == MC_ROUTE_TRANSPORT_DIRECT;
}

/* ---- payload_type (4 bits) ---- */
typedef enum {
    MC_PAYLOAD_REQ        = 0,
    MC_PAYLOAD_RESPONSE    = 1,
    MC_PAYLOAD_TXT_MSG    = 2,
    MC_PAYLOAD_ACK        = 3,
    MC_PAYLOAD_ADVERT     = 4,
    MC_PAYLOAD_GRP_TXT    = 5,
    MC_PAYLOAD_GRP_DATA   = 6,
    MC_PAYLOAD_ANON_REQ   = 7,
    MC_PAYLOAD_PATH       = 8,
    MC_PAYLOAD_TRACE      = 9,
    MC_PAYLOAD_MULTIPART  = 0x0A,
    MC_PAYLOAD_CONTROL    = 0x0B,
    MC_PAYLOAD_RAW_CUSTOM = 0x0F,
} mc_payload_type_t;

const char *mc_payload_type_name(int payload_type);

/* ---- GRP_TXT / TXT_MSG txt_type byte (from upstream
 * src/helpers/TxtDataHelpers.h) ---- */
#define MC_TXT_TYPE_PLAIN        0  /* a plain text message */
#define MC_TXT_TYPE_CLI_DATA     1  /* a CLI command */
#define MC_TXT_TYPE_SIGNED_PLAIN 2  /* plain text, signed by sender */

/* ---- ADVERT app_data flags byte (AdvertDataBuilder/Parser, from
 * upstream src/helpers/AdvertDataHelpers.cpp) ----
 * bits[3:0] = adv_type; bits[7:4] = presence flags for optional
 * lat/lon, extra1, extra2, and name fields. */
typedef enum {
    ADV_TYPE_NONE     = 0,
    ADV_TYPE_CHAT     = 1,
    ADV_TYPE_REPEATER = 2,
    ADV_TYPE_ROOM     = 3,
    ADV_TYPE_SENSOR   = 4,
} mc_adv_type_t;

#define ADV_TYPE_MASK    0x0F
#define ADV_LATLON_MASK  0x10
#define ADV_FEAT1_MASK   0x20
#define ADV_FEAT2_MASK   0x40
#define ADV_NAME_MASK    0x80

/* ---- path/hash sizing ---- */
#define MC_MAX_PACKET_PAYLOAD 184
#define MC_MAX_PATH_SIZE      64

/* path_len byte: bits[5:0]=hash_count, bits[7:6]=(hash_size-1) so
 * hash_size in {1,2,3} (4 is reserved and never emitted). */
#define MC_PATHLEN_HASH_COUNT_MASK 0x3F
#define MC_PATHLEN_HASH_SIZE_MASK  0xC0
#define MC_PATHLEN_HASH_SIZE_SHIFT 6

/* ---- crypto sizes ---- */
#define MC_PUB_KEY_SIZE   32   /* Ed25519 pubkey / shared secret bytes */
#define MC_SIGNATURE_SIZE 64
#define MC_CIPHER_MAC_SIZE 2   /* HMAC-SHA256 truncated to 2 bytes */
#define MC_CIPHER_BLOCK_SIZE 16

/* ---- LoRa sync word ----
 * MeshCore uses RadioLib's default "private network" sync word 0x12,
 * distinct from the Meshtastic OTA sync word (0x2b, wired implicitly
 * into this project's generic CSS demod). The generic lora.c decoder
 * in this project does not hard-code or verify a specific sync-word
 * value (see lora.h: lora_decoder_create() takes only sf/cr/bw), so
 * no plumbing change is needed there for MeshCore support -- this
 * constant is kept here for documentation / future use if a
 * sync-word-aware demod path is ever added. */
#define MC_SYNC_WORD 0x12

/* ---- Channel table (analogous to keyset.c, simplified) ---- */

#define MC_CHANNEL_MAX_ENTRIES 32
#define MC_CHANNEL_MAX_NAME    32
#define MC_CHANNEL_SECRET_BYTES 32

typedef struct meshcore_channel {
    char    name[MC_CHANNEL_MAX_NAME];
    uint8_t secret[MC_CHANNEL_SECRET_BYTES]; /* only secret_len bytes valid, rest zeroed */
    size_t  secret_len; /* PSK length: 16 (AES-128) or 32 bytes */
    uint8_t hash;   /* SHA256(secret[0:secret_len])[0]; see meshcore_channel_hash(). */
} meshcore_channel_t;

typedef struct meshcore_channelset {
    meshcore_channel_t entries[MC_CHANNEL_MAX_ENTRIES];
    int                n_entries;
    pthread_rwlock_t   lock;
} meshcore_channelset_t;

meshcore_channelset_t *meshcore_channelset_create(void);
void                    meshcore_channelset_destroy(meshcore_channelset_t *cs);

/* Derive the 1-byte channel hash for a PSK secret of secret_len bytes
 * (16 or 32): SHA256(secret[0:secret_len])[0]. Not load-bearing for
 * correctness: callers fall back to brute-forcing every configured
 * channel when the hash byte doesn't match (small lists in practice). */
uint8_t meshcore_channel_hash(const uint8_t *secret, size_t secret_len);

/* Decode a channel PSK given as either hex (32 or 64 hex chars) or
 * standard base64 (as used by the official MeshCore app's
 * addChannel(name, psk_base64)). Writes the decoded bytes to out
 * (must have room for MC_CHANNEL_SECRET_BYTES) and the decoded length
 * to *out_len. Returns true on success; decoded length must be 16 or
 * 32 bytes, otherwise returns false. */
bool meshcore_decode_psk(const char *str, uint8_t *out, size_t *out_len);

/* Add "Name:SECRET" where SECRET is hex (32/64 hex chars) or base64
 * (e.g. "izOH6cXN6mrJ5e26oRXNcg=="), decoding to 16 or 32 raw bytes.
 * Returns 0 on success. out_hash/out_display, if non-NULL, receive the
 * added/updated entry's resulting channel_hash and stored display name
 * (out_display must have room for MC_CHANNEL_MAX_NAME bytes) -- lets a
 * caller that just added a channel (e.g. the dashboard's C2 endpoint)
 * announce the hash<->name mapping to connected clients immediately,
 * the same way an automatic hashtag-dictionary crack does, instead of
 * silently updating server state that the UI has no way to learn about
 * until unrelated new traffic happens to arrive on that channel. */
int meshcore_channelset_add_spec(meshcore_channelset_t *cs, const char *spec,
                                  uint8_t *out_hash, char *out_display);

/* Pre-register the official MeshCore app's default "Public" channel
 * (PSK "izOH6cXN6mrJ5e26oRXNcg==", 16 bytes). Returns 0 on success.
 * out_hash/out_display: see meshcore_channelset_add_spec(). */
int meshcore_channelset_add_default_public(meshcore_channelset_t *cs,
                                            uint8_t *out_hash, char *out_display);

/* "Hashtag channel" secret derivation, matching the official app: a
 * channel identified only by name (e.g. "#test") gets its AES-128
 * secret from the first 16 bytes of SHA256("#" + name). Anyone who
 * types the same name arrives at the same secret -- no key exchange
 * needed, unlike a "private channel" (see meshcore_channelset_add_spec),
 * whose secret is random and must be shared out-of-band. */
void meshcore_channel_hashtag_secret(const char *name, uint8_t out[16]);

/* Add a hashtag channel by name alone (a leading '#' is accepted and
 * normalized to exactly one), deriving its secret via
 * meshcore_channel_hashtag_secret(). Returns 0 on success.
 * out_hash/out_display: see meshcore_channelset_add_spec(). */
int meshcore_channelset_add_hashtag(meshcore_channelset_t *cs, const char *name,
                                     uint8_t *out_hash, char *out_display);

/* Hashtag derivation is case-sensitive (SHA256("#" + name) treats
 * "Test" and "test" as different channels), so a dictionary attack
 * against an unknown hashtag channel needs more than the literal
 * spelling of each wordlist entry. Writes up to 4 deduplicated case
 * variants of `name` (as-is, all-lower, all-UPPER, Title-case) into
 * out[0..N), returns N (1..4). Shared by meshcore-recover.c (offline
 * cracker) and meshcore_hashtag_dict.c (live background attack) so
 * both try exactly the same variants. */
size_t meshcore_name_case_variants(const char *name, char out[][MC_CHANNEL_MAX_NAME]);

/* French MeshCore community deployments commonly name hashtag channels
 * after a department ("fr-30", "fr-34", ...) or region ("fr-occ",
 * "fr-paca", ...) abbreviation. Writes that generated set (department
 * numbers 01-99 plus 2a/2b, the 13 metropolitan region abbreviations,
 * and eu/europe/fr/france) into out[0..N), returns N. Shared by
 * meshcore-recover.c (offline cracker, its original home) and
 * meshcore_hashtag_dict.c (live background attack) so both try the
 * same generated candidates instead of the live path only having the
 * handful hand-picked into meshcore-extras.txt / main.c's
 * default_hashtags[]. */
size_t meshcore_builtin_hashtag_candidates(char out[][MC_CHANNEL_MAX_NAME], size_t max_out);

/* Look up candidates by hash byte; returns count written to out_idx
 * (indices into entries[]), up to max_out. */
int meshcore_channelset_lookup(const meshcore_channelset_t *cs, uint8_t hash,
                               int *out_idx, int max_out);

void meshcore_channelset_rdlock(meshcore_channelset_t *cs);
void meshcore_channelset_rdunlock(meshcore_channelset_t *cs);

#endif /* MESHCORE_H */
