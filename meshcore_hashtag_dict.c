/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore hashtag-channel dictionary attack.
 *
 * Background thread tries each wordlist entry (plus case variants) as
 * a candidate hashtag-channel name against undecrypted GRP_TXT/GRP_DATA
 * frames. To reuse the existing decode validation (HMAC-SHA256 MAC +
 * AES-128-ECB decrypt) without inventing a parallel verifier, each
 * attempt builds a temporary single-entry channelset via
 * meshcore_channelset_add_hashtag() and calls meshcore_decode_grp_txt()/
 * meshcore_decode_grp_data() with it -- exactly mirrors
 * recover/meshcore-recover.c's offline attack, and psk_dict.c's
 * Meshtastic-side equivalent.
 *
 * The discovered channel is then promoted to the live runtime
 * channelset (so the next frame on that channel decrypts normally),
 * and an MC_CHANNEL_DISCOVERED JSON event is emitted to feed/stdout/web
 * for operator visibility. The frame that triggered discovery itself
 * stays undecrypted in the public output -- the candidate path runs in
 * the background after the hot path has already moved on.
 */

#include "meshcore_hashtag_dict.h"

#include "meshcore.h"
#include "meshcore_decoders.h"
#include "meshcore_packet.h"
#include "meshcore_redecrypt.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forwards from main.c / web.c / webhook.c so we can publish the
 * discovery event and promote the winning channel into live use. */
extern meshcore_channelset_t *app_get_meshcore_channels(void);
extern void web_publish_line(const char *json, size_t len);
extern void webhook_publish(const char *event_name, const char *json, size_t len,
                            const char *summary);

#define MC_DICT_QUEUE_SIZE      128
#define MC_DICT_FRAME_MAX_BYTES 256
#define MC_DICT_MAX_CANDIDATES  500000

typedef struct {
    uint8_t bytes[MC_DICT_FRAME_MAX_BYTES];
    size_t  len;
    float   rssi_db, snr_db;
    int     sf, cr, bw_hz;
} mc_dict_frame_t;

static mc_dict_frame_t g_queue[MC_DICT_QUEUE_SIZE];
static int             g_q_head = 0, g_q_tail = 0; /* head=write, tail=read */
static pthread_mutex_t g_q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_q_cv = PTHREAD_COND_INITIALIZER;

static char   (*g_candidates)[MC_CHANNEL_MAX_NAME] = NULL;
static size_t   g_candidate_count = 0;

static pthread_t     g_thread;
static volatile int  g_run = 0;
static int           g_started = 0;

/* Track which channel_hash bytes have already been discovered to
 * suppress duplicate alerts -- a long capture would otherwise re-fire
 * on every frame for channels already cracked. */
static uint8_t g_cracked_hashes[256] = {0};

/* Appends entries from `path` into the already-allocated g_candidates
 * array (caller -- meshcore_hashtag_dict_init() -- allocates it once).
 * Must NOT (re)allocate here: it's called once for the configured
 * wordlist and again for the bundled extras file, and a second
 * calloc() would orphan/leak the first call's entries while
 * g_candidate_count kept counting against the stale buffer. */
static size_t append_wordlist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "meshcore-hashtag-dict: cannot open %s\n", path);
        return 0;
    }

    size_t added = 0;
    char line[256];
    while (g_candidate_count < MC_DICT_MAX_CANDIDATES && fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = 0;
        char *start = line;
        while (*start == ' ' || *start == '\t') ++start;
        if (!*start || *start == '#') continue;
        snprintf(g_candidates[g_candidate_count++], MC_CHANNEL_MAX_NAME, "%s", start);
        ++added;
    }
    fclose(f);
    fprintf(stderr, "meshcore-hashtag-dict: loaded %zu candidate name(s) from %s\n", added, path);
    return added;
}

/* Appends meshcore_builtin_hashtag_candidates()'s generated
 * fr-<dept>/fr-<region>/eu/europe/fr/france set into g_candidates,
 * always, regardless of --meshcore-hashtag-wordlist -- previously only
 * a handful of these were reachable at all, hand-picked into
 * meshcore-extras.txt or main.c's default_hashtags[], so most French
 * department/region hashtag channels were never tried against
 * observed-but-undecrypted frames. */
static size_t append_builtin(void)
{
    char tmp[256][MC_CHANNEL_MAX_NAME]; /* comfortably covers the ~118 generated entries */
    size_t got = meshcore_builtin_hashtag_candidates(tmp, sizeof(tmp) / sizeof(tmp[0]));
    size_t added = 0;
    for (size_t i = 0; i < got && g_candidate_count < MC_DICT_MAX_CANDIDATES; ++i) {
        snprintf(g_candidates[g_candidate_count++], MC_CHANNEL_MAX_NAME, "%s", tmp[i]);
        ++added;
    }
    fprintf(stderr, "meshcore-hashtag-dict: loaded %zu built-in candidate name(s) "
                     "(fr-<dept>/fr-<region>/eu/europe/fr/france)\n", added);
    return added;
}

static void emit_discovery(uint8_t channel_hash, const char *name)
{
    char line[256];
    int n = snprintf(line, sizeof(line),
        "{\"event\":\"MC_CHANNEL_DISCOVERED\",\"channel_hash\":%u,\"channel_name\":\"%s\"}\n",
        (unsigned)channel_hash, name);
    if (n <= 0) return;
    fwrite(line, 1, (size_t)n, stdout); fflush(stdout);
    web_publish_line(line, (size_t)n);
    char sum[160];
    snprintf(sum, sizeof(sum),
             "MeshCore hashtag channel discovered: \"%s\" (channel_hash 0x%02x)",
             name, channel_hash);
    webhook_publish("MC_CHANNEL_DISCOVERED", line, (size_t)n, sum);
    fprintf(stderr, "[meshcore-hashtag-dict] discovered channel \"%s\" (channel_hash 0x%02x)\n",
            name, channel_hash);
}

/* Try each wordlist candidate (and its case variants) against one
 * frame. On first match that decrypts successfully, promote the name
 * into the live runtime channelset and emit the discovery event. */
static void try_candidates(const mc_dict_frame_t *f)
{
    meshcore_packet_t pkt;
    if (meshcore_packet_parse(f->bytes, f->len, &pkt) < 0) return;
    if (pkt.payload_type != MC_PAYLOAD_GRP_TXT && pkt.payload_type != MC_PAYLOAD_GRP_DATA) return;
    if (pkt.payload_len < 1) return;
    uint8_t channel_hash = pkt.payload[0];
    if (g_cracked_hashes[channel_hash]) return;

    meshcore_channelset_t *trial = meshcore_channelset_create();
    if (!trial) return;

    for (size_t i = 0; i < g_candidate_count && g_run; ++i) {
        char variants[4][MC_CHANNEL_MAX_NAME];
        size_t n_variants = meshcore_name_case_variants(g_candidates[i], variants);

        for (size_t vi = 0; vi < n_variants; ++vi) {
            trial->n_entries = 0;
            if (meshcore_channelset_add_hashtag(trial, variants[vi], NULL, NULL) != 0) continue;
            if (trial->entries[0].hash != channel_hash) continue; /* cheap prefilter */

            mesh_event_t ev;
            memset(&ev, 0, sizeof(ev));
            bool decoded = (pkt.payload_type == MC_PAYLOAD_GRP_TXT)
                         ? meshcore_decode_grp_txt(&pkt, trial, &ev)
                         : meshcore_decode_grp_data(&pkt, trial, &ev);
            if (!decoded || !ev.decrypted) continue;

            /* Promote to the live channelset under the same
             * derivation the real device would use, then stop -- one
             * discovery per channel_hash is enough. */
            meshcore_channelset_t *live = app_get_meshcore_channels();
            if (live) meshcore_channelset_add_hashtag(live, variants[vi], NULL, NULL);
            g_cracked_hashes[channel_hash] = 1;
            emit_discovery(channel_hash, ev.channel_name[0] ? ev.channel_name : variants[vi]);
            meshcore_channelset_destroy(trial);
            return;
        }
    }
    meshcore_channelset_destroy(trial);
}

static void *mc_dict_thread(void *arg)
{
    (void)arg;
    while (g_run) {
        mc_dict_frame_t f;
        pthread_mutex_lock(&g_q_mu);
        while (g_run && g_q_head == g_q_tail) {
            pthread_cond_wait(&g_q_cv, &g_q_mu);
        }
        if (!g_run) { pthread_mutex_unlock(&g_q_mu); break; }
        f = g_queue[g_q_tail];
        g_q_tail = (g_q_tail + 1) % MC_DICT_QUEUE_SIZE;
        pthread_mutex_unlock(&g_q_mu);

        try_candidates(&f);
    }
    return NULL;
}

bool meshcore_hashtag_dict_init(const char *path)
{
    if (g_started) return true;
    if (!path) return false;

    g_candidates = calloc(MC_DICT_MAX_CANDIDATES, sizeof(*g_candidates));
    if (!g_candidates) return false;

    size_t n = append_wordlist(path);
    n += append_builtin();
#ifdef MC_DEFAULT_HASHTAG_EXTRAS
    /* Hand-picked extras (bot/meteo/.../not otherwise generated) always
     * tried in addition to whatever wordlist is configured and to the
     * generated fr-<dept>/fr-<region> set above. */
    n += append_wordlist(MC_DEFAULT_HASHTAG_EXTRAS);
#endif
    if (n == 0) {
        free(g_candidates);
        g_candidates = NULL;
        return false;
    }

    g_run = 1;
    if (pthread_create(&g_thread, NULL, mc_dict_thread, NULL) != 0) {
        g_run = 0;
        return false;
    }
    g_started = 1;
    return true;
}

void meshcore_hashtag_dict_shutdown(void)
{
    if (!g_started) return;
    pthread_mutex_lock(&g_q_mu);
    g_run = 0;
    pthread_cond_broadcast(&g_q_cv);
    pthread_mutex_unlock(&g_q_mu);
    pthread_join(g_thread, NULL);
    free(g_candidates);
    g_candidates = NULL;
    g_candidate_count = 0;
    g_started = 0;
}

void meshcore_hashtag_dict_enqueue(const uint8_t *frame_bytes, size_t frame_len,
                                   float rssi_db, float snr_db,
                                   int sf, int cr, int bw_hz)
{
    if (!g_started || !frame_bytes || frame_len == 0) return;
    if (frame_len > MC_DICT_FRAME_MAX_BYTES) frame_len = MC_DICT_FRAME_MAX_BYTES;

    pthread_mutex_lock(&g_q_mu);
    int next = (g_q_head + 1) % MC_DICT_QUEUE_SIZE;
    if (next == g_q_tail) {
        /* Queue full; drop oldest by advancing tail -- bounded latency
         * at the cost of dropping some samples in a very busy mesh. */
        g_q_tail = (g_q_tail + 1) % MC_DICT_QUEUE_SIZE;
    }
    mc_dict_frame_t *e = &g_queue[g_q_head];
    memcpy(e->bytes, frame_bytes, frame_len);
    e->len = frame_len;
    e->rssi_db = rssi_db; e->snr_db = snr_db;
    e->sf = sf; e->cr = cr; e->bw_hz = bw_hz;
    g_q_head = next;
    pthread_cond_signal(&g_q_cv);
    pthread_mutex_unlock(&g_q_mu);
}
