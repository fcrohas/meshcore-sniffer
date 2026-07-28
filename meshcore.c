/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore channel table.
 */

#include "meshcore.h"

#include <ctype.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

const char *mc_payload_type_name(int payload_type)
{
    switch (payload_type) {
    case MC_PAYLOAD_REQ:        return "REQ";
    case MC_PAYLOAD_RESPONSE:   return "RESPONSE";
    case MC_PAYLOAD_TXT_MSG:    return "TXT_MSG";
    case MC_PAYLOAD_ACK:        return "ACK";
    case MC_PAYLOAD_ADVERT:     return "ADVERT";
    case MC_PAYLOAD_GRP_TXT:    return "GRP_TXT";
    case MC_PAYLOAD_GRP_DATA:   return "GRP_DATA";
    case MC_PAYLOAD_ANON_REQ:   return "ANON_REQ";
    case MC_PAYLOAD_PATH:       return "PATH";
    case MC_PAYLOAD_TRACE:      return "TRACE";
    case MC_PAYLOAD_MULTIPART:  return "MULTIPART";
    case MC_PAYLOAD_CONTROL:    return "CONTROL";
    case MC_PAYLOAD_RAW_CUSTOM: return "RAW_CUSTOM";
    default:                    return "UNKNOWN";
    }
}

uint8_t meshcore_channel_hash(const uint8_t *secret, size_t secret_len)
{
    /* SHA256(secret[0:secret_len])[0]. Not load-bearing: meshcore_decoders.c
     * brute-forces the small configured channel list on hash mismatch. */
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    uint8_t h = 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, secret, secret_len) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1 && digest_len > 0) {
        h = digest[0];
    }
    EVP_MD_CTX_free(ctx);
    return h;
}

meshcore_channelset_t *meshcore_channelset_create(void)
{
    meshcore_channelset_t *cs = calloc(1, sizeof(*cs));
    if (!cs) return NULL;
    pthread_rwlock_init(&cs->lock, NULL);
    return cs;
}

void meshcore_channelset_destroy(meshcore_channelset_t *cs)
{
    if (!cs) return;
    pthread_rwlock_destroy(&cs->lock);
    free(cs);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t max_out)
{
    size_t hl = strlen(hex);
    if (hl % 2) return -1;
    size_t n = hl / 2;
    if (n > max_out) return -1;
    for (size_t i = 0; i < n; ++i) {
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

static bool is_strict_hex(const char *s, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        if (hex_nibble(s[i]) < 0) return false;
    return true;
}

/* Standard base64 decode via OpenSSL's EVP_DecodeBlock, which always
 * emits a multiple of 3 bytes and ignores '=' padding chars internally
 * -- so we count trailing '=' in the input and subtract that many
 * bytes from the result to get the true decoded length. */
static int base64_decode(const char *b64, uint8_t *out, size_t max_out)
{
    size_t len = strlen(b64);
    if (len == 0 || len % 4 != 0) return -1;

    size_t pad = 0;
    if (len >= 1 && b64[len - 1] == '=') pad++;
    if (len >= 2 && b64[len - 2] == '=') pad++;

    /* Reject anything outside the standard base64 alphabet (+/=,
     * alnum) so garbage/hex-looking strings don't silently "succeed". */
    for (size_t i = 0; i < len; ++i) {
        char c = b64[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '+' || c == '/' ||
                  (c == '=' && i >= len - 2);
        if (!ok) return -1;
    }

    size_t decoded_max = (len / 4) * 3;

    uint8_t tmp[128];
    if (decoded_max > sizeof(tmp)) return -1;
    int dlen = EVP_DecodeBlock(tmp, (const unsigned char *)b64, (int)len);
    if (dlen < 0) return -1;
    size_t n = (size_t)dlen - pad;
    if (n > max_out) return -1;
    memcpy(out, tmp, n);
    return (int)n;
}

bool meshcore_decode_psk(const char *str, uint8_t *out, size_t *out_len)
{
    if (!str || !out || !out_len) return false;
    size_t slen = strlen(str);

    /* Try strict hex first: only 0-9a-fA-F, even length, 32 or 64 chars. */
    if ((slen == 32 || slen == 64) && is_strict_hex(str, slen)) {
        int n = hex_decode(str, out, MC_CHANNEL_SECRET_BYTES);
        if (n == 16 || n == 32) {
            *out_len = (size_t)n;
            return true;
        }
    }

    /* Fall back to standard base64 (accepts '+', '/', '=', and is also
     * what upstream MeshCore uses natively for addChannel(name, psk)). */
    int n = base64_decode(str, out, MC_CHANNEL_SECRET_BYTES);
    if (n == 16 || n == 32) {
        *out_len = (size_t)n;
        return true;
    }

    return false;
}
/* Shared tail of both add paths below: lock, upsert by name, unlock.
 * Re-adding an already-known name (exact match on the normalized
 * display name add_spec/add_hashtag already built) overwrites that
 * entry's secret/hash in place instead of growing the array -- this
 * keeps repeated/automatic re-submission (e.g. the dashboard restoring
 * its localStorage-remembered channels on every page load) from
 * silently exhausting MC_CHANNEL_MAX_ENTRIES over time. */
static int add_channel_locked(meshcore_channelset_t *cs, const char *name,
                              const uint8_t *secret, size_t secret_len,
                              uint8_t *out_hash, char *out_display)
{
    pthread_rwlock_wrlock(&cs->lock);
    meshcore_channel_t *e = NULL;
    for (int i = 0; i < cs->n_entries; ++i) {
        if (!strcmp(cs->entries[i].name, name)) { e = &cs->entries[i]; break; }
    }
    if (!e) {
        if (cs->n_entries >= MC_CHANNEL_MAX_ENTRIES) {
            pthread_rwlock_unlock(&cs->lock);
            return -1;
        }
        e = &cs->entries[cs->n_entries++];
    }
    memset(e, 0, sizeof(*e));
    strncpy(e->name, name, sizeof(e->name) - 1);
    memcpy(e->secret, secret, secret_len);
    e->secret_len = secret_len;
    e->hash = meshcore_channel_hash(secret, secret_len);
    if (out_hash) *out_hash = e->hash;
    if (out_display) snprintf(out_display, MC_CHANNEL_MAX_NAME, "%s", e->name);
    pthread_rwlock_unlock(&cs->lock);
    return 0;
}

int meshcore_channelset_add_spec(meshcore_channelset_t *cs, const char *spec,
                                  uint8_t *out_hash, char *out_display)
{
    if (!cs || !spec) return -1;
    const char *colon = strchr(spec, ':');
    if (!colon) return -1;

    char name[MC_CHANNEL_MAX_NAME] = {0};
    size_t nlen = (size_t)(colon - spec);
    if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
    memcpy(name, spec, nlen);
    name[nlen] = 0;

    uint8_t secret[MC_CHANNEL_SECRET_BYTES] = {0};
    size_t slen = 0;
    if (!meshcore_decode_psk(colon + 1, secret, &slen)) {
        fprintf(stderr, "meshcore: channel '%s' secret must decode to 16 or 32 bytes "
                "(hex: 32/64 hex chars, or base64)\n", name);
        return -1;
    }

    return add_channel_locked(cs, name, secret, slen, out_hash, out_display);
}

void meshcore_channel_hashtag_secret(const char *name, uint8_t out[16])
{
    /* "#" + name, SHA256, first 16 bytes -- see meshcore_channelset_add_hashtag(). */
    char buf[1 + MC_CHANNEL_MAX_NAME];
    buf[0] = '#';
    size_t nlen = strlen(name);
    if (nlen > sizeof(buf) - 1) nlen = sizeof(buf) - 1;
    memcpy(buf + 1, name, nlen);

    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    memset(out, 0, 16);
    if (!ctx) return;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, buf, nlen + 1) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1 && digest_len >= 16) {
        memcpy(out, digest, 16);
    }
    EVP_MD_CTX_free(ctx);
}

int meshcore_channelset_add_hashtag(meshcore_channelset_t *cs, const char *name,
                                     uint8_t *out_hash, char *out_display)
{
    if (!cs || !name || !*name) return -1;
    /* Normalize away a leading '#' the user may have typed -- the hash
     * input always has exactly one, added below. */
    if (name[0] == '#') ++name;
    if (!*name) return -1;

    /* "Public" is not a generic community hashtag channel -- it's the
     * official app's one reserved default, joined via an explicit
     * hard-coded secret baked into the firmware (see
     * meshcore_channelset_add_default_public() / upstream's
     * PUBLIC_GROUP_PSK in MyMesh.cpp), not derived from the name at
     * all. Deriving SHA256("#Public") here instead would silently add
     * a channel that looks identical in a UI but can never decrypt
     * real Public traffic -- exactly the trap a user re-adding it by
     * name (e.g. via the web dashboard's "Add MeshCore channel" form
     * after --meshcore-no-default-channel) would fall into. Recognize
     * it case-insensitively and route to the known secret instead. */
    if (!strcasecmp(name, "public")) {
        return meshcore_channelset_add_default_public(cs, out_hash, out_display);
    }

    char display[MC_CHANNEL_MAX_NAME];
    snprintf(display, sizeof(display), "#%s", name);

    uint8_t secret[16];
    meshcore_channel_hashtag_secret(name, secret);
    return add_channel_locked(cs, display, secret, sizeof(secret), out_hash, out_display);
}

size_t meshcore_name_case_variants(const char *name, char out[][MC_CHANNEL_MAX_NAME])
{
    size_t n = 0;
    snprintf(out[n++], MC_CHANNEL_MAX_NAME, "%s", name);
    for (int pass = 0; pass < 3; ++pass) {
        char v[MC_CHANNEL_MAX_NAME];
        snprintf(v, sizeof(v), "%s", name);
        size_t vlen = strlen(v);
        if (pass == 0) {
            for (size_t c = 0; c < vlen; ++c) v[c] = (char)tolower((unsigned char)v[c]);
        } else if (pass == 1) {
            for (size_t c = 0; c < vlen; ++c) v[c] = (char)toupper((unsigned char)v[c]);
        } else if (vlen > 0) {
            v[0] = (char)toupper((unsigned char)v[0]);
            for (size_t c = 1; c < vlen; ++c) v[c] = (char)tolower((unsigned char)v[c]);
        }
        bool dup = false;
        for (size_t k = 0; k < n; ++k) if (!strcmp(out[k], v)) { dup = true; break; }
        if (!dup && n < 4) snprintf(out[n++], MC_CHANNEL_MAX_NAME, "%s", v);
    }
    return n;
}

size_t meshcore_builtin_hashtag_candidates(char out[][MC_CHANNEL_MAX_NAME], size_t max_out)
{
    size_t n = 0;

    /* French department numbers 01-99, as literally described -- plus
     * 2a/2b since department "20" (Corse) is split that way in modern
     * INSEE codes and may be what a "20" placeholder maps to. */
    for (int d = 1; d <= 99 && n < max_out; ++d)
        snprintf(out[n++], MC_CHANNEL_MAX_NAME, "fr-%02d", d);
    if (n < max_out) snprintf(out[n++], MC_CHANNEL_MAX_NAME, "fr-2a");
    if (n < max_out) snprintf(out[n++], MC_CHANNEL_MAX_NAME, "fr-2b");

    /* The 13 metropolitan region abbreviations in common community use. */
    static const char *regions[] = {
        "ara", "bfc", "bre", "cvl", "cor", "ges", "hdf",
        "idf", "nor", "naq", "occ", "pdl", "paca",
    };
    for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]) && n < max_out; ++i)
        snprintf(out[n++], MC_CHANNEL_MAX_NAME, "fr-%s", regions[i]);

    static const char *misc[] = { "eu", "europe", "fr", "france" };
    for (size_t i = 0; i < sizeof(misc) / sizeof(misc[0]) && n < max_out; ++i)
        snprintf(out[n++], MC_CHANNEL_MAX_NAME, "%s", misc[i]);

    return n;
}

int meshcore_channelset_add_default_public(meshcore_channelset_t *cs,
                                            uint8_t *out_hash, char *out_display)
{
    /* Official MeshCore app hard-codes this PSK for its default
     * "Public" channel (base64 "izOH6cXN6mrJ5e26oRXNcg==" -> 16 bytes). */
    return meshcore_channelset_add_spec(cs, "Public:izOH6cXN6mrJ5e26oRXNcg==", out_hash, out_display);
}

int meshcore_channelset_lookup(const meshcore_channelset_t *cs, uint8_t hash,
                               int *out_idx, int max_out)
{
    if (!cs || !out_idx || max_out <= 0) return 0;
    int n = 0;
    /* Prefer exact hash matches first. */
    for (int i = 0; i < cs->n_entries && n < max_out; ++i) {
        if (cs->entries[i].hash == hash) out_idx[n++] = i;
    }
    /* Fallback: brute-force every remaining channel (small lists in
     * practice; see TODO on meshcore_channel_hash()). */
    for (int i = 0; i < cs->n_entries && n < max_out; ++i) {
        if (cs->entries[i].hash == hash) continue;
        out_idx[n++] = i;
    }
    return n;
}

void meshcore_channelset_rdlock(meshcore_channelset_t *cs)
{
    if (cs) pthread_rwlock_rdlock(&cs->lock);
}

void meshcore_channelset_rdunlock(meshcore_channelset_t *cs)
{
    if (cs) pthread_rwlock_unlock(&cs->lock);
}
