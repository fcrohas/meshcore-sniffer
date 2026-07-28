/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: offline hashtag-channel recovery for MeshCore
 * GRP_TXT/GRP_DATA frames.
 *
 * A MeshCore "hashtag channel" (meshcore_channel_hashtag_secret() in
 * ../meshcore.c) derives its AES-128 secret from a human-typed name:
 * SHA256("#" + name)[0:16]. Unlike a private channel (a real random
 * 128-bit key -- not worth attacking), a hashtag channel's effective
 * keyspace is "plausible channel names", which is exactly the kind of
 * problem a wordlist/mask attack is good at. This tool tries every
 * candidate name against one captured frame, using the project's own
 * meshcore_channelset_add_hashtag() + meshcore_decode_grp_txt() to
 * derive the secret and verify the HMAC-SHA256 MAC + AES-128-ECB
 * decrypt exactly the way a real node would -- no crypto reimplemented
 * here.
 *
 * Same dual-use posture as ../recover/meshtastic-recover.c: neutral
 * tool, scope/authorization is the operator's responsibility.
 */

#include "../meshcore.h"
#include "../meshcore_packet.h"
#include "../meshcore_decoders.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CANDIDATES 500000

/* Generation logic (fr-<dept>/fr-<region>/eu/europe/fr/france) lives in
 * meshcore_builtin_hashtag_candidates() (meshcore.c/.h) so the live
 * sniffer's background dictionary attack (meshcore_hashtag_dict.c)
 * tries the exact same set, not just this offline tool. */

static size_t load_wordlist(const char *path, char out[][MC_CHANNEL_MAX_NAME], size_t max_out)
{
    FILE *f = !strcmp(path, "-") ? stdin : fopen(path, "r");
    if (!f) {
        fprintf(stderr, "meshcore-recover: cannot open wordlist '%s'\n", path);
        return 0;
    }
    size_t n = 0;
    char line[256];
    while (n < max_out && fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || isspace((unsigned char)line[len-1])))
            line[--len] = 0;
        char *start = line;
        while (*start && isspace((unsigned char)*start)) ++start;
        if (!*start || *start == '#') continue;
        snprintf(out[n++], MC_CHANNEL_MAX_NAME, "%s", start);
    }
    if (f != stdin) fclose(f);
    return n;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_frame(const char *hex, uint8_t *out, size_t max_out)
{
    size_t len = strlen(hex);
    if (len % 2) return -1;
    size_t n = len / 2;
    if (n > max_out) return -1;
    for (size_t i = 0; i < n; ++i) {
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s --frame=HEX [--wordlist=FILE] [--no-builtin] [--no-default-wordlist] [--list] [-v]\n"
        "  --frame=HEX      raw MeshCore LoRa frame, hex-encoded (required unless --list)\n"
        "  --wordlist=FILE  extra candidate channel names, one per line ('#' = comment)\n"
#ifdef MC_DEFAULT_HASHTAG_WORDLIST
        "  --no-default-wordlist  skip the bundled ~23k-word French list (" MC_DEFAULT_HASHTAG_WORDLIST ")\n"
#endif
#ifdef MC_DEFAULT_HASHTAG_EXTRAS
        "                   and the hand-picked extras (" MC_DEFAULT_HASHTAG_EXTRAS ")\n"
#endif
        "                   tried automatically otherwise, in addition to --wordlist\n"
        "  --no-builtin     skip the built-in fr-<dept>/fr-<region>/eu/europe list\n"
        "  --list           print the full candidate list (builtin + default wordlist + --wordlist) and exit\n"
        "  -v               print every candidate tried, not just hits\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *frame_hex = NULL;
    const char *wordlist_path = NULL;
    bool use_builtin = true;
    bool use_default_wordlist = true;
    bool verbose = false;
    bool list_only = false;

    for (int i = 1; i < argc; ++i) {
        if (!strncmp(argv[i], "--frame=", 8)) frame_hex = argv[i] + 8;
        else if (!strncmp(argv[i], "--wordlist=", 11)) wordlist_path = argv[i] + 11;
        else if (!strcmp(argv[i], "--no-builtin")) use_builtin = false;
        else if (!strcmp(argv[i], "--no-default-wordlist")) use_default_wordlist = false;
        else if (!strcmp(argv[i], "--list")) list_only = true;
        else if (!strcmp(argv[i], "-v")) verbose = true;
        else { usage(argv[0]); return 2; }
    }

    static char candidates[MAX_CANDIDATES][MC_CHANNEL_MAX_NAME];
    size_t n_candidates = 0;

    if (use_builtin)
        n_candidates += meshcore_builtin_hashtag_candidates(candidates + n_candidates, MAX_CANDIDATES - n_candidates);
#ifdef MC_DEFAULT_HASHTAG_WORDLIST
    if (use_default_wordlist)
        n_candidates += load_wordlist(MC_DEFAULT_HASHTAG_WORDLIST, candidates + n_candidates, MAX_CANDIDATES - n_candidates);
#endif
#ifdef MC_DEFAULT_HASHTAG_EXTRAS
    if (use_default_wordlist)
        n_candidates += load_wordlist(MC_DEFAULT_HASHTAG_EXTRAS, candidates + n_candidates, MAX_CANDIDATES - n_candidates);
#endif
#if !defined(MC_DEFAULT_HASHTAG_WORDLIST) && !defined(MC_DEFAULT_HASHTAG_EXTRAS)
    (void)use_default_wordlist;
#endif
    if (wordlist_path)
        n_candidates += load_wordlist(wordlist_path, candidates + n_candidates, MAX_CANDIDATES - n_candidates);

    if (list_only) {
        for (size_t i = 0; i < n_candidates; ++i) printf("%s\n", candidates[i]);
        return 0;
    }

    if (!frame_hex) { usage(argv[0]); return 2; }

    uint8_t raw[512];
    int raw_len = parse_hex_frame(frame_hex, raw, sizeof(raw));
    if (raw_len < 0) {
        fprintf(stderr, "meshcore-recover: --frame is not valid hex\n");
        return 2;
    }

    meshcore_packet_t pkt;
    if (meshcore_packet_parse(raw, (size_t)raw_len, &pkt) < 0) {
        fprintf(stderr, "meshcore-recover: frame failed to parse (malformed header/path)\n");
        return 1;
    }
    if (pkt.payload_type != MC_PAYLOAD_GRP_TXT && pkt.payload_type != MC_PAYLOAD_GRP_DATA) {
        fprintf(stderr, "meshcore-recover: payload_type %d (%s) is not GRP_TXT/GRP_DATA -- "
                "hashtag channels only apply to those\n",
                pkt.payload_type, mc_payload_type_name(pkt.payload_type));
        return 1;
    }
    if (pkt.payload_len < 1) {
        fprintf(stderr, "meshcore-recover: empty payload\n");
        return 1;
    }
    uint8_t channel_hash = pkt.payload[0];
    fprintf(stderr, "meshcore-recover: frame parsed OK, payload_type=%s channel_hash=0x%02x, "
            "%zu candidate name(s) to try\n",
            mc_payload_type_name(pkt.payload_type), channel_hash, n_candidates);

    meshcore_channelset_t *cs = meshcore_channelset_create();
    if (!cs) { fprintf(stderr, "meshcore-recover: out of memory\n"); return 1; }

    size_t n_hash_matched = 0;
    size_t n_hits = 0;

    for (size_t i = 0; i < n_candidates; ++i) {
        /* Hashtag derivation is case-sensitive; try the name as given
         * plus lower/UPPER/Title-case variants since a wordlist
         * entry's case may not match what was actually typed into
         * the app. Shared with meshcore_hashtag_dict.c so both
         * crackers try exactly the same variants. */
        char variants[4][MC_CHANNEL_MAX_NAME];
        size_t n_variants = meshcore_name_case_variants(candidates[i], variants);

        for (size_t vi = 0; vi < n_variants; ++vi) {
            const char *name = variants[vi];
            cs->n_entries = 0;
            if (meshcore_channelset_add_hashtag(cs, name, NULL, NULL) != 0) continue;

            bool hash_matched = (cs->entries[0].hash == channel_hash);
            if (hash_matched) ++n_hash_matched;

            if (verbose)
                fprintf(stderr, "  trying '%s' (secret hash 0x%02x)%s\n",
                        name, cs->entries[0].hash, hash_matched ? "  <- hash prefilter match" : "");

            if (!hash_matched) continue; /* cheap filter: real device's HMAC would also reject */

            mesh_event_t ev;
            memset(&ev, 0, sizeof(ev));
            bool decoded = (pkt.payload_type == MC_PAYLOAD_GRP_TXT)
                         ? meshcore_decode_grp_txt(&pkt, cs, &ev)
                         : meshcore_decode_grp_data(&pkt, cs, &ev);

            if (decoded && ev.decrypted) {
                ++n_hits;
                char secret_hex[2 * MC_CHANNEL_SECRET_BYTES + 1];
                for (size_t b = 0; b < cs->entries[0].secret_len; ++b)
                    snprintf(secret_hex + 2*b, 3, "%02x", cs->entries[0].secret[b]);

                printf("FOUND: channel name=\"%s\" secret(hex)=%s\n", name, secret_hex);
                printf("  --meshcore-channel spec: %s:hex:%s\n", name, secret_hex);
                if (pkt.payload_type == MC_PAYLOAD_GRP_TXT) {
                    printf("  timestamp=%u txt_type=%u text=\"%s\"\n",
                           ev.mc_timestamp, ev.mc_txt_type, ev.mc_text);
                } else {
                    printf("  data_type=%u data_len=%u text=\"%s\"\n",
                           ev.mc_data_type, ev.mc_data_len, ev.mc_text);
                }
            }
        }
    }

    fprintf(stderr, "meshcore-recover: %zu/%zu candidates passed the hash prefilter, %zu hit(s)\n",
            n_hash_matched, n_candidates, n_hits);

    meshcore_channelset_destroy(cs);
    return n_hits > 0 ? 0 : 1;
}
