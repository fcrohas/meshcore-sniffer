/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore region-scope name resolution. See
 * meshcore_region_dict.h for the crypto background and the fast/full/
 * background-enqueue split this file implements.
 *
 * meshcore_region_resolve_fast() used to be the ONLY tier, called
 * unconditionally inline from the live decode path -- on a cache miss
 * it fell through to the full ~150-entry x up to 8 case/'#' variants
 * wordlist scan right there in the decoder, synchronously, for every
 * still-unresolved transport-coded packet. That's real per-frame cost
 * (SHA256 + HMAC-SHA256 per candidate, each sha256_key16() call also
 * heap-allocating an EVP_MD_CTX) paid on the hot path for exactly the
 * packets that DON'T have a quick answer -- which regressed live
 * decode throughput on a busy mesh (messages silently not decoded,
 * not because the channel key was missing, but because the decode
 * pipeline fell behind). The full scan is now only ever run
 * synchronously from an offline/batch context (meshcore_region_
 * recover.c) or asynchronously from the background worker thread
 * below, matching the channel hashtag dictionary attack
 * (meshcore_hashtag_dict.c)'s existing enqueue-and-forget shape.
 */

#include "meshcore_region_dict.h"

#include "meshcore.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <string.h>

/* Common public region names an operator following the upstream docs'
 * examples (#Europe, #UK, #France, ...) is likely to have used.
 * Single tokens only -- CLI region names are space-delimited, so a
 * multi-word candidate could never match a real one anyway. Extend
 * this list as real-world names are observed; there is currently no
 * --wordlist option for this (unlike the channel hashtag attack) to
 * keep the wordlist a known, bounded size. */
static const char *const REGION_CURATED_CANDIDATES[] = {
    "Europe", "UK", "France", "Germany", "Spain", "Italy", "Portugal",
    "Netherlands", "Belgium", "Switzerland", "Austria", "Ireland",
    "Scotland", "Wales", "Poland", "Sweden", "Norway", "Denmark",
    "Finland", "London", "Paris", "Lyon", "Manchester",
    "US", "USA", "Canada", "Mexico", "Australia", "NZ",
    "Asia", "Africa", "World", "Global", "Local", "Test", "Home",
};
#define REGION_CURATED_COUNT \
    (sizeof(REGION_CURATED_CANDIDATES) / sizeof(REGION_CURATED_CANDIDATES[0]))

/* Full candidate list: the curated names above, plus the same
 * fr-<dept>/fr-<region>/eu/europe/fr/france set the channel hashtag
 * dictionary attack already generates (meshcore_builtin_hashtag_
 * candidates(), meshcore.c) -- French MeshCore deployments commonly
 * name their region scope the same short way they name hashtag
 * channels (e.g. "fr-occ" for Occitanie, "fr-naq" for
 * Nouvelle-Aquitaine, "fr-33" for a department, "eu"/"fr" for the
 * wider wildcard tiers). Built once, lazily. */
#define REGION_MAX_CANDIDATES 256
static char           g_candidates[REGION_MAX_CANDIDATES][MC_CHANNEL_MAX_NAME];
static size_t         g_candidate_count = 0;
static pthread_once_t g_candidates_once = PTHREAD_ONCE_INIT;

static void init_candidates(void)
{
    size_t n = 0;
    for (size_t i = 0; i < REGION_CURATED_COUNT && n < REGION_MAX_CANDIDATES; ++i)
        snprintf(g_candidates[n++], MC_CHANNEL_MAX_NAME, "%s", REGION_CURATED_CANDIDATES[i]);
    n += meshcore_builtin_hashtag_candidates(g_candidates + n, REGION_MAX_CANDIDATES - n);
    g_candidate_count = n;
}

#define MC_REGION_MAX_CONFIRMED 64

typedef struct {
    char    name[MC_CHANNEL_MAX_NAME];
    uint8_t key[16];
} confirmed_region_t;

static confirmed_region_t g_confirmed[MC_REGION_MAX_CONFIRMED];
static int                g_confirmed_count = 0;
static pthread_mutex_t    g_confirmed_mu = PTHREAD_MUTEX_INITIALIZER;

static void sha256_key16(const char *s, uint8_t out16[16])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    memset(out16, 0, 16);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, s, strlen(s)) == 1 &&
        EVP_DigestFinal_ex(ctx, digest, &dlen) == 1 && dlen >= 16) {
        memcpy(out16, digest, 16);
    }
    EVP_MD_CTX_free(ctx);
}

/* Mirrors TransportKey::calcTransportCode(): HMAC-SHA256(key, type ||
 * payload)[0:2] as a little-endian uint16, with the firmware's
 * reserved-value bump (0 -> 1, 0xFFFF -> 0xFFFE). */
static uint16_t calc_transport_code(const uint8_t key16[16], uint8_t payload_type,
                                    const uint8_t *payload, size_t payload_len)
{
    uint8_t msg[1 + MC_MAX_PACKET_PAYLOAD];
    msg[0] = payload_type;
    size_t mlen = payload_len;
    if (mlen > sizeof(msg) - 1) mlen = sizeof(msg) - 1;
    if (mlen > 0 && payload) memcpy(msg + 1, payload, mlen);

    unsigned char hmac_full[EVP_MAX_MD_SIZE];
    unsigned int  hmac_len = 0;
    if (!HMAC(EVP_sha256(), key16, 16, msg, mlen + 1, hmac_full, &hmac_len))
        return 0;

    uint16_t code = (uint16_t)hmac_full[0] | ((uint16_t)hmac_full[1] << 8);
    if (code == 0) code = 1;
    else if (code == 0xFFFF) code = 0xFFFE;
    return code;
}

static void remember_confirmed(const char *name, const uint8_t key16[16])
{
    pthread_mutex_lock(&g_confirmed_mu);
    for (int i = 0; i < g_confirmed_count; ++i) {
        if (!strcmp(g_confirmed[i].name, name)) { pthread_mutex_unlock(&g_confirmed_mu); return; }
    }
    if (g_confirmed_count < MC_REGION_MAX_CONFIRMED) {
        snprintf(g_confirmed[g_confirmed_count].name, sizeof(g_confirmed[g_confirmed_count].name), "%s", name);
        memcpy(g_confirmed[g_confirmed_count].key, key16, 16);
        g_confirmed_count++;
    }
    pthread_mutex_unlock(&g_confirmed_mu);
}

bool meshcore_region_resolve_fast(uint8_t payload_type, const uint8_t *payload,
                                  size_t payload_len, uint16_t code,
                                  char *name_out, size_t name_cap)
{
    if (code == 0 || (!payload && payload_len > 0)) return false;

    pthread_mutex_lock(&g_confirmed_mu);
    int n_confirmed = g_confirmed_count;
    confirmed_region_t local[MC_REGION_MAX_CONFIRMED];
    memcpy(local, g_confirmed, sizeof(confirmed_region_t) * (size_t)n_confirmed);
    pthread_mutex_unlock(&g_confirmed_mu);

    for (int i = 0; i < n_confirmed; ++i) {
        if (calc_transport_code(local[i].key, payload_type, payload, payload_len) == code) {
            snprintf(name_out, name_cap, "%s", local[i].name);
            return true;
        }
    }
    return false;
}

bool meshcore_region_resolve_full(uint8_t payload_type, const uint8_t *payload,
                                  size_t payload_len, uint16_t code,
                                  char *name_out, size_t name_cap)
{
    if (meshcore_region_resolve_fast(payload_type, payload, payload_len, code, name_out, name_cap))
        return true;
    if (code == 0 || (!payload && payload_len > 0)) return false;

    /* Each candidate tried as typed, with a leading '#' (the docs' own
     * naming convention for public regions), and case variants of
     * both. */
    pthread_once(&g_candidates_once, init_candidates);
    for (size_t i = 0; i < g_candidate_count; ++i) {
        char case_variants[4][MC_CHANNEL_MAX_NAME];
        size_t nv = meshcore_name_case_variants(g_candidates[i], case_variants);
        for (size_t v = 0; v < nv; ++v) {
            for (int with_hash = 0; with_hash < 2; ++with_hash) {
                char cand[MC_CHANNEL_MAX_NAME + 1];
                if (with_hash) snprintf(cand, sizeof(cand), "#%s", case_variants[v]);
                else           snprintf(cand, sizeof(cand), "%s",  case_variants[v]);

                uint8_t key[16];
                sha256_key16(cand, key);
                if (calc_transport_code(key, payload_type, payload, payload_len) == code) {
                    snprintf(name_out, name_cap, "%s", cand);
                    remember_confirmed(cand, key);
                    return true;
                }
            }
        }
    }
    return false;
}

/* ---- Background worker: runs meshcore_region_resolve_full() off the
 * live decode path, matching meshcore_hashtag_dict.c's shape. ---- */

#define MC_REGION_QUEUE_SIZE 64

typedef struct {
    uint8_t  payload_type;
    uint8_t  payload[MC_MAX_PACKET_PAYLOAD];
    size_t   payload_len;
    uint16_t code;
} mc_region_frame_t;

static mc_region_frame_t g_rq[MC_REGION_QUEUE_SIZE];
static int               g_rq_head = 0, g_rq_tail = 0;
static pthread_mutex_t   g_rq_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t    g_rq_cv = PTHREAD_COND_INITIALIZER;
static pthread_t         g_rq_thread;
static pthread_once_t    g_rq_thread_once = PTHREAD_ONCE_INIT;

static void *region_dict_worker(void *arg)
{
    (void)arg;
    for (;;) {
        mc_region_frame_t f;
        pthread_mutex_lock(&g_rq_mu);
        while (g_rq_head == g_rq_tail) pthread_cond_wait(&g_rq_cv, &g_rq_mu);
        f = g_rq[g_rq_tail];
        g_rq_tail = (g_rq_tail + 1) % MC_REGION_QUEUE_SIZE;
        pthread_mutex_unlock(&g_rq_mu);

        char name[MC_CHANNEL_MAX_NAME];
        meshcore_region_resolve_full(f.payload_type, f.payload, f.payload_len, f.code,
                                     name, sizeof(name));
        /* Result (if any) is already cached by _full() via
         * remember_confirmed(); nothing else to do with it here --
         * see meshcore_region_dict_enqueue()'s doc comment. */
    }
    return NULL;
}

static void start_region_dict_worker(void)
{
    pthread_create(&g_rq_thread, NULL, region_dict_worker, NULL);
}

void meshcore_region_dict_enqueue(uint8_t payload_type, const uint8_t *payload,
                                  size_t payload_len, uint16_t code)
{
    if (!payload || payload_len == 0) return;
    if (payload_len > MC_MAX_PACKET_PAYLOAD) payload_len = MC_MAX_PACKET_PAYLOAD;

    pthread_once(&g_rq_thread_once, start_region_dict_worker);

    pthread_mutex_lock(&g_rq_mu);
    int next = (g_rq_head + 1) % MC_REGION_QUEUE_SIZE;
    if (next == g_rq_tail) {
        /* Queue full; drop oldest by advancing tail -- bounded latency
         * at the cost of dropping some samples in a very busy mesh. */
        g_rq_tail = (g_rq_tail + 1) % MC_REGION_QUEUE_SIZE;
    }
    mc_region_frame_t *e = &g_rq[g_rq_head];
    e->payload_type = payload_type;
    memcpy(e->payload, payload, payload_len);
    e->payload_len = payload_len;
    e->code = code;
    g_rq_head = next;
    pthread_cond_signal(&g_rq_cv);
    pthread_mutex_unlock(&g_rq_mu);
}
