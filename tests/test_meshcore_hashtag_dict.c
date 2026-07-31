/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: regression test for meshcore_hashtag_dict.c, the
 * background hashtag-channel dictionary attack.
 *
 * Synthesizes a GRP_TXT frame encrypted under hashtag channel "test",
 * enqueues it as if it arrived undecrypted off the radio, and checks
 * that the background thread finds it via a wordlist entry of
 * different case ("TEST" -> case-variant match on "test"), promotes it
 * into the live channelset, and that a subsequent decode of the same
 * frame against that channelset now succeeds.
 *
 * This binary provides its own app_get_meshcore_channels() /
 * web_publish_line() / webhook_publish() -- the extern hooks
 * meshcore_hashtag_dict.c expects the main sniffer binary to supply --
 * since it links the real module (not meshcore_hashtag_dict_stub.c).
 */

#include "meshcore.h"
#include "meshcore_decoders.h"
#include "meshcore_hashtag_dict.h"
#include "meshcore_packet.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); ++failures; } \
    else { fprintf(stderr, "ok:   %s\n", msg); } \
} while (0)

static meshcore_channelset_t *g_test_channels;

meshcore_channelset_t *app_get_meshcore_channels(void) { return g_test_channels; }
void web_publish_line(const char *json, size_t len) { (void)json; (void)len; }
void webhook_publish(const char *event_name, const char *json, size_t len, const char *summary)
{
    (void)event_name; (void)json; (void)len; (void)summary;
}

/* Build a GRP_TXT frame encrypted under hashtag channel `name`, same
 * construction the real firmware/meshcore-recover's self-test use. */
static size_t build_grp_txt_frame(const char *name, const char *msg, uint8_t *frame)
{
    uint8_t secret[16];
    meshcore_channel_hashtag_secret(name, secret);
    uint8_t chash = meshcore_channel_hash(secret, 16);

    uint8_t plain[64] = {0};
    uint32_t ts = (uint32_t)time(NULL);
    memcpy(plain, &ts, 4);
    plain[4] = 0; /* txt_type PLAIN */
    memcpy(plain + 5, msg, strlen(msg));
    size_t plain_len = 5 + strlen(msg);
    size_t padded_len = ((plain_len + 15) / 16) * 16;

    uint8_t cipher[80];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int outlen1 = 0, outlen2 = 0;
    EVP_EncryptUpdate(ctx, cipher, &outlen1, plain, (int)padded_len);
    EVP_EncryptFinal_ex(ctx, cipher + outlen1, &outlen2);
    size_t cipher_len = (size_t)(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);

    uint8_t hmac_key[32] = {0};
    memcpy(hmac_key, secret, 16);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), hmac_key, 32, cipher, cipher_len, mac, &mac_len);

    size_t p = 0;
    frame[p++] = (uint8_t)(MC_ROUTE_FLOOD | (MC_PAYLOAD_GRP_TXT << MC_HEADER_PAYLOAD_TYPE_SHIFT));
    frame[p++] = 0x00; /* path_len_byte: hash_count=0, hash_size=1 */
    frame[p++] = chash;
    frame[p++] = mac[0];
    frame[p++] = mac[1];
    memcpy(frame + p, cipher, cipher_len);
    p += cipher_len;
    return p;
}

static void test_discovery(void)
{
    g_test_channels = meshcore_channelset_create();
    CHECK(g_test_channels != NULL, "live channelset created");

    uint8_t frame[128];
    size_t frame_len = build_grp_txt_frame("test", "hello#test", frame);

    /* Sanity: the live channelset has no entry for this channel yet,
     * so a direct decode attempt must report undecrypted. */
    meshcore_packet_t pkt;
    CHECK(meshcore_packet_parse(frame, frame_len, &pkt) == 0, "synthetic frame parses");
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    meshcore_decode_grp_txt(&pkt, g_test_channels, &ev);
    CHECK(!ev.decrypted, "before discovery: frame is undecrypted against the empty live channelset");

    char wordlist_path[] = "/tmp/mc_hashtag_dict_test_XXXXXX";
    int fd = mkstemp(wordlist_path);
    CHECK(fd >= 0, "wordlist temp file created");
    FILE *wf = fdopen(fd, "w");
    /* Deliberately wrong case ("TEST") -- exercises
     * meshcore_name_case_variants()'s lowercase pass, not a literal
     * wordlist match. */
    fprintf(wf, "bogus1\nTEST\nbogus2\n");
    fclose(wf);

    CHECK(meshcore_hashtag_dict_init(wordlist_path), "dict thread starts");
    meshcore_hashtag_dict_enqueue(frame, frame_len, 0.0f, 0.0f, 7, 5, 125000);

    bool discovered = false;
    for (int i = 0; i < 300 && !discovered; ++i) {
        usleep(10000); /* 10ms */
        memset(&ev, 0, sizeof(ev));
        meshcore_decode_grp_txt(&pkt, g_test_channels, &ev);
        if (ev.decrypted) discovered = true;
    }
    CHECK(discovered, "background thread cracked \"TEST\" -> \"test\" and promoted it into the live channelset");
    CHECK(discovered && !strcmp(ev.mc_text, "hello#test"),
          "promoted channel decrypts the original message text");

    meshcore_hashtag_dict_shutdown();
    unlink(wordlist_path);
    meshcore_channelset_destroy(g_test_channels);
}

/* Regression: French department/region hashtag channels (e.g. "fr-48"
 * for a Mont-Lozere community deployment) used to only be reachable if
 * hand-picked into a wordlist -- meshcore_builtin_hashtag_candidates()
 * (meshcore.c) now generates the full fr-<dept>/fr-<region> set and
 * meshcore_hashtag_dict_init() always loads it, so this must crack
 * even with an unrelated/empty wordlist file. */
static void test_department_channel_builtin(void)
{
    g_test_channels = meshcore_channelset_create();
    CHECK(g_test_channels != NULL, "dept channel: live channelset created");

    uint8_t frame[128];
    size_t frame_len = build_grp_txt_frame("fr-48", "hello mont lozere", frame);

    meshcore_packet_t pkt;
    CHECK(meshcore_packet_parse(frame, frame_len, &pkt) == 0, "dept channel: synthetic frame parses");
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    meshcore_decode_grp_txt(&pkt, g_test_channels, &ev);
    CHECK(!ev.decrypted, "dept channel: undecrypted against the empty live channelset before discovery");

    /* Wordlist file has no relevant entries -- only the always-loaded
     * built-in generator can crack this. */
    char wordlist_path[] = "/tmp/mc_hashtag_dict_test_dept_XXXXXX";
    int fd = mkstemp(wordlist_path);
    CHECK(fd >= 0, "dept channel: wordlist temp file created");
    FILE *wf = fdopen(fd, "w");
    fprintf(wf, "bogus1\nbogus2\n");
    fclose(wf);

    CHECK(meshcore_hashtag_dict_init(wordlist_path), "dept channel: dict thread starts");
    meshcore_hashtag_dict_enqueue(frame, frame_len, 0.0f, 0.0f, 7, 5, 125000);

    bool discovered = false;
    for (int i = 0; i < 300 && !discovered; ++i) {
        usleep(10000);
        memset(&ev, 0, sizeof(ev));
        meshcore_decode_grp_txt(&pkt, g_test_channels, &ev);
        if (ev.decrypted) discovered = true;
    }
    CHECK(discovered, "dept channel: built-in candidate \"fr-48\" cracked with no matching wordlist entry");
    CHECK(discovered && !strcmp(ev.mc_text, "hello mont lozere"),
          "dept channel: promoted channel decrypts the original message text");

    meshcore_hashtag_dict_shutdown();
    unlink(wordlist_path);
    meshcore_channelset_destroy(g_test_channels);
}

/* Regression: channel_hash is only 1 byte (256 values), so two
 * genuinely different hashtag channels sharing the same hash byte is
 * common on a busy mesh (observed for real: "#lazarus" and "#meteo"
 * both hash to the same byte in production). try_candidates() used to
 * gate on a per-hash-byte "already cracked, skip" flag that, once set
 * by discovering the FIRST channel on a given hash byte, silently
 * blocked ever discovering a SECOND colliding channel on that same
 * byte -- its traffic stayed undecodable forever even though the
 * dashboard already showed a channel name for that hash. This
 * deterministically finds a real collision (pigeonhole: trying more
 * candidate names than there are hash-byte values guarantees one) and
 * checks both channels get discovered, not just the first. */
static void test_hash_collision_both_discovered(void)
{
    char name_a[32] = {0}, name_b[32] = {0};
    uint8_t hash_a = 0, seen[256] = {0};
    char seen_name[256][32];
    bool found = false;

    for (int i = 0; i < 300 && !found; ++i) {
        char cand[32];
        snprintf(cand, sizeof(cand), "collide%d", i);
        uint8_t secret[16];
        meshcore_channel_hashtag_secret(cand, secret);
        uint8_t h = meshcore_channel_hash(secret, 16);
        if (seen[h]) {
            snprintf(name_a, sizeof(name_a), "%s", seen_name[h]);
            snprintf(name_b, sizeof(name_b), "%s", cand);
            hash_a = h;
            found = true;
        } else {
            seen[h] = 1;
            snprintf(seen_name[h], sizeof(seen_name[h]), "%s", cand);
        }
    }
    CHECK(found, "collision: found two distinct names sharing one channel_hash byte");
    if (!found) return;

    g_test_channels = meshcore_channelset_create();
    CHECK(g_test_channels != NULL, "collision: live channelset created");

    uint8_t frame_a[128], frame_b[128];
    size_t len_a = build_grp_txt_frame(name_a, "msg on channel A", frame_a);
    size_t len_b = build_grp_txt_frame(name_b, "msg on channel B", frame_b);

    meshcore_packet_t pkt_a, pkt_b;
    CHECK(meshcore_packet_parse(frame_a, len_a, &pkt_a) == 0, "collision: frame A parses");
    CHECK(meshcore_packet_parse(frame_b, len_b, &pkt_b) == 0, "collision: frame B parses");
    CHECK(pkt_a.payload[0] == hash_a && pkt_b.payload[0] == hash_a,
          "collision: both frames really do carry the same wire channel_hash byte");

    char wordlist_path[] = "/tmp/mc_hashtag_dict_test_coll_XXXXXX";
    int fd = mkstemp(wordlist_path);
    CHECK(fd >= 0, "collision: wordlist temp file created");
    FILE *wf = fdopen(fd, "w");
    fprintf(wf, "%s\n%s\n", name_a, name_b);
    fclose(wf);

    CHECK(meshcore_hashtag_dict_init(wordlist_path), "collision: dict thread starts");

    meshcore_hashtag_dict_enqueue(frame_a, len_a, 0.0f, 0.0f, 7, 5, 125000);
    mesh_event_t ev_a;
    bool discovered_a = false;
    for (int i = 0; i < 300 && !discovered_a; ++i) {
        usleep(10000);
        memset(&ev_a, 0, sizeof(ev_a));
        meshcore_decode_grp_txt(&pkt_a, g_test_channels, &ev_a);
        if (ev_a.decrypted) discovered_a = true;
    }
    CHECK(discovered_a, "collision: first channel on the shared hash byte is discovered");

    /* The regression: before the fix, this second, still-undecrypted
     * frame on the SAME hash byte would never even be re-attempted by
     * the dictionary thread, so it would stay undecryptable forever. */
    meshcore_hashtag_dict_enqueue(frame_b, len_b, 0.0f, 0.0f, 7, 5, 125000);
    mesh_event_t ev_b;
    bool discovered_b = false;
    for (int i = 0; i < 300 && !discovered_b; ++i) {
        usleep(10000);
        memset(&ev_b, 0, sizeof(ev_b));
        meshcore_decode_grp_txt(&pkt_b, g_test_channels, &ev_b);
        if (ev_b.decrypted) discovered_b = true;
    }
    CHECK(discovered_b, "collision: SECOND channel on the same shared hash byte is ALSO discovered");
    CHECK(discovered_b && !strcmp(ev_b.mc_text, "msg on channel B"),
          "collision: second channel's message decodes correctly");

    meshcore_hashtag_dict_shutdown();
    unlink(wordlist_path);
    meshcore_channelset_destroy(g_test_channels);
}

int main(void)
{
    test_discovery();
    test_department_channel_builtin();
    test_hash_collision_both_discovered();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall checks passed\n");
    return 0;
}
