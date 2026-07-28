/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: command-and-control dispatch.
 *
 * Body parsing + side-effect application for each /api/<endpoint>
 * action, transport-independent. The HTTP web layer in web.c parses
 * an HTTP POST and calls these; a future DEALER socket path will
 * call them with a frame body. Both produce the same JSON response.
 *
 * Helpers that depend on raw HTTP semantics (URL-decode, share-URL
 * parse, content-length walk) stay in web.c -- those are coupled to
 * the HTTP request shape. We re-use decode_channel_share() through an
 * extern declaration so the share-URL handler can stay generic.
 */

#include "c2.h"
#include "cot.h"
#include "keyset.h"
#include "meshcore.h"
#include "meshcore_redecrypt.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forwards from web.c -- kept there because they're closer to the HTTP
 * URL form they parse. */
extern int decode_channel_share(keyset_t *ks, const char *url_or_b64);

/* Forwards from main.c -- the channel-set is global state owned there. */
extern keyset_t *app_get_keyset(void);
extern int       app_add_runtime_extra_freq(uint64_t f_hz, int bw_hz, int sf, int cr);
extern meshcore_channelset_t *app_get_meshcore_channels(void);

/* Forwards from main.c/web.c/webhook.c -- so a manually-added channel
 * can announce its hash<->name mapping to connected dashboard clients
 * the same way an automatic hashtag-dictionary crack does (see
 * meshcore_hashtag_dict.c's emit_discovery()); otherwise the add
 * succeeds server-side but the UI has no way to learn about it until
 * unrelated new traffic happens to arrive on that exact channel. */
extern void web_publish_line(const char *json, size_t len);
extern void webhook_publish(const char *event_name, const char *json, size_t len,
                            const char *summary);

static void respond(c2_response_t *out, int status, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out->body, sizeof(out->body), fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(out->body)) n = (int)sizeof(out->body) - 1;
    out->body_len = (size_t)n;
    out->status   = status;
}

void c2_keys_add(const char *body, c2_response_t *out)
{
    keyset_t *ks = app_get_keyset();
    if (!body || !ks) {
        respond(out, 400, "{\"error\":\"no body or no keyset\"}");
        return;
    }
    int added = keyset_parse_csv(ks, body);
    respond(out, 200, "{\"added\":%d}", added);
}

void c2_share_url(const char *body, c2_response_t *out)
{
    keyset_t *ks = app_get_keyset();
    if (!body || !ks) {
        respond(out, 400, "{\"error\":\"no body or no keyset\"}");
        return;
    }
    int added = decode_channel_share(ks, body);
    if (added < 0) {
        respond(out, 400, "{\"error\":\"could not parse share URL\"}");
        return;
    }
    respond(out, 200, "{\"added\":%d}", added);
}

void c2_extra_freq(const char *body, c2_response_t *out)
{
    if (!body) {
        respond(out, 400, "{\"error\":\"no body\"}");
        return;
    }
    /* Format: "HZ:bw=BW:sf=SF:cr=CR" -- match the CLI parser. */
    uint64_t f = strtoull(body, NULL, 10);
    int bw = 250000, sf = 11, cr = 5;
    const char *p = body;
    while ((p = strchr(p, ':')) != NULL) {
        ++p;
        if      (!strncmp(p, "bw=", 3)) bw = atoi(p + 3);
        else if (!strncmp(p, "sf=", 3)) sf = atoi(p + 3);
        else if (!strncmp(p, "cr=", 3)) cr = atoi(p + 3);
    }
    int id = (f && bw) ? app_add_runtime_extra_freq(f, bw, sf, cr) : -1;
    if (id < 0) {
        respond(out, 400, "{\"error\":\"add failed\"}");
        return;
    }
    respond(out, 200, "{\"channel_id\":%d}", id);
}

void c2_cot_multicast(const char *body, c2_response_t *out)
{
    if (!body) {
        respond(out, 400, "{\"error\":\"no body\"}");
        return;
    }
    /* Body: "HOST:PORT" or empty to disable. */
    const char *colon = strchr(body, ':');
    if (!colon || !*body) {
        cot_set_endpoint(NULL, 0);
        respond(out, 200, "{\"enabled\":false}");
        return;
    }
    char host[64];
    size_t hl = (size_t)(colon - body);
    if (hl >= sizeof(host)) hl = sizeof(host) - 1;
    memcpy(host, body, hl);
    host[hl] = 0;
    int port = atoi(colon + 1);
    int rc = cot_set_endpoint(host, port);
    if (rc < 0) {
        respond(out, 400, "{\"error\":\"could not bind multicast\"}");
        return;
    }
    respond(out, 200, "{\"enabled\":true,\"host\":\"%s\",\"port\":%d}", host, port);
}

/* Announce a manually-added channel's hash<->name mapping to connected
 * dashboard clients (and webhook sinks), mirroring
 * meshcore_hashtag_dict.c's emit_discovery() for automatic finds --
 * same event shape, distinct event name so a webhook consumer can
 * still tell "operator configured this" apart from "brute-forced". */
static void emit_channel_added(uint8_t channel_hash, const char *name)
{
    char line[256];
    int n = snprintf(line, sizeof(line),
        "{\"event\":\"MC_CHANNEL_ADDED\",\"channel_hash\":%u,\"channel_name\":\"%s\"}\n",
        (unsigned)channel_hash, name);
    if (n <= 0) return;
    web_publish_line(line, (size_t)n);
    char sum[160];
    snprintf(sum, sizeof(sum), "MeshCore channel added via dashboard: \"%s\" (channel_hash 0x%02x)",
             name, channel_hash);
    webhook_publish("MC_CHANNEL_ADDED", line, (size_t)n, sum);
}

/* Body: comma/semicolon/newline-separated channel specs, one of:
 *   - "Name" (or "#Name")  -- hashtag channel, secret derived from the
 *                              name alone (meshcore_channelset_add_hashtag),
 *                              matching the official app's no-key "Add
 *                              Channel" flow.
 *   - "Name:SECRET"         -- private channel, explicit hex/base64 secret
 *                              (meshcore_channelset_add_spec), same shape
 *                              as the CLI --meshcore-channel flag. */
void c2_meshcore_channel_add(const char *body, c2_response_t *out)
{
    meshcore_channelset_t *cs = app_get_meshcore_channels();
    if (!body || !cs) {
        respond(out, 400, "{\"error\":\"no body or no meshcore channel set\"}");
        return;
    }
    char dup[1024];
    size_t bl = strlen(body);
    if (bl >= sizeof(dup)) bl = sizeof(dup) - 1;
    memcpy(dup, body, bl);
    dup[bl] = 0;

    int added = 0;
    char *save = NULL;
    for (char *tok = strtok_r(dup, ",;\n", &save); tok; tok = strtok_r(NULL, ",;\n", &save)) {
        while (*tok == ' ' || *tok == '\t') ++tok;
        if (!*tok) continue;
        const char *colon = strchr(tok, ':');
        if (colon) {
            uint8_t hash = 0;
            char display[MC_CHANNEL_MAX_NAME] = {0};
            if (meshcore_channelset_add_spec(cs, tok, &hash, display) == 0) {
                ++added;
                emit_channel_added(hash, display);
                /* Retroactively fix any already-stored, still-
                 * encrypted history on this hash -- see
                 * meshcore_redecrypt.c. A no-op scan when there's
                 * nothing to fix. */
                meshcore_redecrypt_channel(hash, cs);
            }
            continue;
        }
        /* Hashtag channel, no explicit secret: the real MeshCore app
         * hashes the name bytes verbatim (meshcore_channel_hashtag_secret()),
         * so a channel named "Meteo" on the mesh won't decrypt for an
         * operator who typed "meteo" here -- the add still "succeeds"
         * (a channelset entry is created either way) but every message
         * on that channel stays undecryptable forever, with no feedback
         * that the guess was wrong. Add the literal spelling plus its
         * lower/upper/title-case variants -- the same set the background
         * dictionary attack (meshcore_hashtag_dict.c) tries -- as
         * *candidate* channelset entries, so a differently-cased real
         * name still decrypts once real traffic arrives on it.
         *
         * Only announce the exact spelling the operator typed
         * (variants[0] -- meshcore_name_case_variants() always puts the
         * literal input first) via MC_CHANNEL_ADDED. Announcing every
         * variant used to create one dashboard row per guess, each with
         * its own (essentially arbitrary) derived channel_hash -- for
         * three wrong-case guesses that's three permanent 0-message
         * decoy rows in the Channels tab alongside the one real,
         * already-populated channel. The silently-added variants still
         * work for decryption; they just don't get their own row until
         * (if ever) real traffic actually lands on that exact hash, at
         * which point the normal per-frame handler names it. */
        char variants[4][MC_CHANNEL_MAX_NAME];
        size_t n_variants = meshcore_name_case_variants(tok, variants);
        bool tok_added = false;
        for (size_t vi = 0; vi < n_variants; ++vi) {
            uint8_t hash = 0;
            char display[MC_CHANNEL_MAX_NAME] = {0};
            if (meshcore_channelset_add_hashtag(cs, variants[vi], &hash, display) == 0) {
                tok_added = true;
                if (vi == 0) emit_channel_added(hash, display);
                meshcore_redecrypt_channel(hash, cs);
            }
        }
        if (tok_added) ++added;
    }
    respond(out, 200, "{\"added\":%d}", added);
}
void c2_dispatch(const char *cmd, const char *body, c2_response_t *out)
{
    if (!cmd) {
        respond(out, 400, "{\"error\":\"no cmd\"}");
        return;
    }
    if      (!strcmp(cmd, "keys_add"))      c2_keys_add(body, out);
    else if (!strcmp(cmd, "share_url"))     c2_share_url(body, out);
    else if (!strcmp(cmd, "extra_freq"))    c2_extra_freq(body, out);
    else if (!strcmp(cmd, "cot_multicast")) c2_cot_multicast(body, out);
    else if (!strcmp(cmd, "meshcore_channel_add")) c2_meshcore_channel_add(body, out);
    else respond(out, 404, "{\"error\":\"unknown cmd\"}");
}
