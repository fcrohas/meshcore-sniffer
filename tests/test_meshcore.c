/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore smoke test.
 *
 * Covers:
 *   1. ADVERT: synthesize a raw MeshCore frame (header + path_len=0 +
 *      pubkey + timestamp + signature + app_data="Test Node"), parse
 *      it, and check the decoded node name.
 *   2. GRP_TXT: AES-128-ECB + HMAC-SHA256(2B) encrypt a test message
 *      with a known 32-byte secret, then verify
 *      meshcore_verify_and_decrypt() recovers it.
 */

#include "meshcore.h"
#include "meshcore_packet.h"
#include "meshcore_decoders.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); ++failures; } \
    else { fprintf(stderr, "ok:   %s\n", msg); } \
} while (0)

static void test_advert(void)
{
    uint8_t frame[300];
    size_t  n = 0;

    /* header: route_type=FLOOD(1), payload_type=ADVERT(4), payload_ver=0 */
    frame[n++] = (uint8_t)((MC_PAYLOAD_ADVERT << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);

    /* path_len byte: hash_count=0, hash_size-1=0 */
    frame[n++] = 0;

    /* payload: pubkey(32, arbitrary bytes) */
    for (int i = 0; i < MC_PUB_KEY_SIZE; ++i) frame[n++] = (uint8_t)(0xA0 + i);

    /* timestamp (4B LE) */
    uint32_t ts = 1700000000u;
    frame[n++] = (uint8_t)(ts);
    frame[n++] = (uint8_t)(ts >> 8);
    frame[n++] = (uint8_t)(ts >> 16);
    frame[n++] = (uint8_t)(ts >> 24);

    /* signature(64, arbitrary -- not verified in v1) */
    for (int i = 0; i < MC_SIGNATURE_SIZE; ++i) frame[n++] = (uint8_t)(0x55 + i);

    /* app_data: flags(1) = ADV_TYPE_CHAT | ADV_NAME_MASK, then name text
     * (no lat/lon, no extras -- not null-terminated on the wire). */
    frame[n++] = (uint8_t)(ADV_TYPE_CHAT | ADV_NAME_MASK);
    const char *name = "Test Node";
    memcpy(frame + n, name, strlen(name));
    n += strlen(name);

    meshcore_packet_t pkt;
    int rc = meshcore_packet_parse(frame, n, &pkt);
    CHECK(rc == 0, "ADVERT: meshcore_packet_parse succeeds");
    CHECK(pkt.payload_type == MC_PAYLOAD_ADVERT, "ADVERT: payload_type decoded");
    CHECK(pkt.route_type == MC_ROUTE_FLOOD, "ADVERT: route_type decoded");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    bool ok = meshcore_decode_advert(&pkt, &ev);
    CHECK(ok, "ADVERT: meshcore_decode_advert succeeds");
    CHECK(ev.mc_adv_type == ADV_TYPE_CHAT, "ADVERT: adv_type decoded as CHAT");
    CHECK(ev.mc_has_name, "ADVERT: has_name flag set");
    CHECK(strcmp(ev.mc_node_name, "Test Node") == 0, "ADVERT: node name == 'Test Node'");
    CHECK(!ev.mc_has_latlon, "ADVERT: has_latlon not set when flag absent");
    CHECK(ev.mc_timestamp == ts, "ADVERT: timestamp round-trips");
}

static void test_advert_latlon(void)
{
    uint8_t frame[300];
    size_t  n = 0;

    frame[n++] = (uint8_t)((MC_PAYLOAD_ADVERT << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame[n++] = 0; /* path_len byte */

    for (int i = 0; i < MC_PUB_KEY_SIZE; ++i) frame[n++] = (uint8_t)(0xB0 + i);

    uint32_t ts = 1700000100u;
    frame[n++] = (uint8_t)(ts);
    frame[n++] = (uint8_t)(ts >> 8);
    frame[n++] = (uint8_t)(ts >> 16);
    frame[n++] = (uint8_t)(ts >> 24);

    for (int i = 0; i < MC_SIGNATURE_SIZE; ++i) frame[n++] = (uint8_t)(0x66 + i);

    /* app_data: flags = ADV_TYPE_REPEATER | ADV_LATLON_MASK | ADV_NAME_MASK,
     * then lat/lon (int32 LE, degrees*1e6, Paris), then name. */
    frame[n++] = (uint8_t)(ADV_TYPE_REPEATER | ADV_LATLON_MASK | ADV_NAME_MASK);
    int32_t lat_e6 = (int32_t)(48.8566 * 1e6);
    int32_t lon_e6 = (int32_t)(2.3522 * 1e6);
    memcpy(frame + n, &lat_e6, 4); n += 4;
    memcpy(frame + n, &lon_e6, 4); n += 4;
    const char *name = "Paris Repeater";
    memcpy(frame + n, name, strlen(name));
    n += strlen(name);

    meshcore_packet_t pkt;
    int rc = meshcore_packet_parse(frame, n, &pkt);
    CHECK(rc == 0, "ADVERT latlon: meshcore_packet_parse succeeds");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    bool ok = meshcore_decode_advert(&pkt, &ev);
    CHECK(ok, "ADVERT latlon: meshcore_decode_advert succeeds");
    CHECK(ev.mc_adv_type == ADV_TYPE_REPEATER, "ADVERT latlon: adv_type decoded as REPEATER");
    CHECK(ev.mc_has_latlon, "ADVERT latlon: has_latlon flag set");
    CHECK(ev.mc_lat > 48.85 && ev.mc_lat < 48.86, "ADVERT latlon: lat close to 48.8566");
    CHECK(ev.mc_lon > 2.35 && ev.mc_lon < 2.36, "ADVERT latlon: lon close to 2.3522");
    CHECK(ev.mc_has_name, "ADVERT latlon: has_name flag set");
    CHECK(strcmp(ev.mc_node_name, "Paris Repeater") == 0, "ADVERT latlon: node name == 'Paris Repeater'");
}

static void test_grp_txt_crypto(void)
{
    /* Known 32-byte secret. */
    uint8_t secret[MC_CHANNEL_SECRET_BYTES];
    for (int i = 0; i < MC_CHANNEL_SECRET_BYTES; ++i) secret[i] = (uint8_t)(0x10 + i);

    /* Plaintext: timestamp(4) + "hi:hello world" text, zero-padded to a
     * 16-byte multiple for AES-ECB. */
    uint8_t plain[32] = {0};
    uint32_t ts = 42;
    plain[0] = (uint8_t)ts; plain[1] = 0; plain[2] = 0; plain[3] = 0;
    const char *msg = "hi:hello world";
    memcpy(plain + 4, msg, strlen(msg));
    size_t plain_len = 4 + strlen(msg);
    size_t padded_len = ((plain_len + 15) / 16) * 16;

    /* Encrypt with AES-128-ECB, key = secret[0:16], no padding. */
    uint8_t ciphertext[32] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1 = 0, outlen2 = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plain, (int)padded_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    size_t cipher_len = (size_t)(outlen1 + outlen2);

    /* HMAC-SHA256(secret-full-32B, ciphertext) truncated to 2 bytes. */
    unsigned char hmac_full[EVP_MAX_MD_SIZE];
    unsigned int  hmac_len = 0;
    HMAC(EVP_sha256(), secret, MC_PUB_KEY_SIZE, ciphertext, cipher_len, hmac_full, &hmac_len);

    uint8_t enc_with_mac[64];
    memcpy(enc_with_mac, hmac_full, MC_CIPHER_MAC_SIZE);
    memcpy(enc_with_mac + MC_CIPHER_MAC_SIZE, ciphertext, cipher_len);
    size_t enc_len = MC_CIPHER_MAC_SIZE + cipher_len;

    uint8_t out_plain[64];
    size_t  out_len = 0;
    int rc = meshcore_verify_and_decrypt(secret, sizeof(secret), enc_with_mac, enc_len, out_plain, &out_len);
    CHECK(rc == 0, "GRP_TXT: meshcore_verify_and_decrypt succeeds (MAC ok)");
    CHECK(out_len == cipher_len, "GRP_TXT: decrypted length matches ciphertext length");
    CHECK(memcmp(out_plain, plain, plain_len) == 0, "GRP_TXT: decrypted plaintext matches original");
    CHECK(memcmp(out_plain + 4, msg, strlen(msg)) == 0, "GRP_TXT: decoded text == 'hi:hello world'");

    /* Corrupt one MAC byte -- must fail closed. */
    uint8_t bad[64];
    memcpy(bad, enc_with_mac, enc_len);
    bad[0] ^= 0xFF;
    size_t bad_len = 0;
    rc = meshcore_verify_and_decrypt(secret, sizeof(secret), bad, enc_len, out_plain, &bad_len);
    CHECK(rc != 0, "GRP_TXT: corrupted MAC is rejected");
}

static void test_advert_signature(void)
{
    /* Generate a real Ed25519 keypair. */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    CHECK(pctx != NULL, "ADVERT sig: EVP_PKEY_CTX_new_id(ED25519) succeeds");
    EVP_PKEY *key = NULL;
    CHECK(EVP_PKEY_keygen_init(pctx) == 1, "ADVERT sig: keygen_init succeeds");
    CHECK(EVP_PKEY_keygen(pctx, &key) == 1, "ADVERT sig: keygen succeeds");
    EVP_PKEY_CTX_free(pctx);

    uint8_t pubkey[MC_PUB_KEY_SIZE];
    size_t pubkey_len = sizeof(pubkey);
    CHECK(EVP_PKEY_get_raw_public_key(key, pubkey, &pubkey_len) == 1 &&
          pubkey_len == MC_PUB_KEY_SIZE,
          "ADVERT sig: extracted 32-byte raw public key");

    uint32_t ts = 1700000042u;
    const char *name = "Signed Node";
    uint8_t app_data[1 + 32];
    app_data[0] = 0x00; /* flags */
    memcpy(app_data + 1, name, strlen(name));
    size_t app_data_len = 1 + strlen(name);

    uint8_t msg[MC_PUB_KEY_SIZE + 4 + sizeof(app_data)];
    memcpy(msg, pubkey, MC_PUB_KEY_SIZE);
    msg[MC_PUB_KEY_SIZE + 0] = (uint8_t)(ts);
    msg[MC_PUB_KEY_SIZE + 1] = (uint8_t)(ts >> 8);
    msg[MC_PUB_KEY_SIZE + 2] = (uint8_t)(ts >> 16);
    msg[MC_PUB_KEY_SIZE + 3] = (uint8_t)(ts >> 24);
    memcpy(msg + MC_PUB_KEY_SIZE + 4, app_data, app_data_len);
    size_t msg_len = MC_PUB_KEY_SIZE + 4 + app_data_len;

    uint8_t signature[MC_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    CHECK(EVP_DigestSignInit(mctx, NULL, NULL, NULL, key) == 1,
          "ADVERT sig: DigestSignInit succeeds");
    CHECK(EVP_DigestSign(mctx, signature, &sig_len, msg, msg_len) == 1 &&
          sig_len == MC_SIGNATURE_SIZE,
          "ADVERT sig: DigestSign produces a 64-byte signature");
    EVP_MD_CTX_free(mctx);

    bool ok = meshcore_advert_verify_signature(pubkey, ts, app_data, app_data_len, signature);
    CHECK(ok, "ADVERT sig: valid signature verifies");

    uint8_t bad_sig[MC_SIGNATURE_SIZE];
    memcpy(bad_sig, signature, sizeof(bad_sig));
    bad_sig[0] ^= 0xFF;
    ok = meshcore_advert_verify_signature(pubkey, ts, app_data, app_data_len, bad_sig);
    CHECK(!ok, "ADVERT sig: corrupted signature is rejected");

    EVP_PKEY_free(key);
}

static void test_grp_data_dispatch(void)
{
    uint8_t secret[MC_CHANNEL_SECRET_BYTES];
    for (int i = 0; i < MC_CHANNEL_SECRET_BYTES; ++i) secret[i] = (uint8_t)(0x20 + i);

    /* Real wire format (BaseChatMesh::sendGroupData): data_type(2 LE) +
     * data_len(1 byte) + blob -- no leading timestamp. */
    uint8_t blob[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };
    uint16_t data_type = 0x1234;
    uint8_t data_len = (uint8_t)sizeof(blob);

    uint8_t plain[32] = {0};
    plain[0] = (uint8_t)(data_type);      plain[1] = (uint8_t)(data_type >> 8);
    plain[2] = data_len;
    memcpy(plain + 3, blob, sizeof(blob));
    size_t plain_len = 3 + sizeof(blob);
    size_t padded_len = ((plain_len + 15) / 16) * 16;

    uint8_t ciphertext[32] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1 = 0, outlen2 = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plain, (int)padded_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    size_t cipher_len = (size_t)(outlen1 + outlen2);

    unsigned char hmac_full[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), secret, MC_PUB_KEY_SIZE, ciphertext, cipher_len, hmac_full, &hmac_len);

    /* Build a full MeshCore packet: header + path_len(0) +
     * channel_hash(1) + MAC(2) + ciphertext. */
    uint8_t frame[300];
    size_t n = 0;
    frame[n++] = (uint8_t)((MC_PAYLOAD_GRP_DATA << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame[n++] = 0; /* path_len: hash_count=0 */
    uint8_t channel_hash = meshcore_channel_hash(secret, MC_CHANNEL_SECRET_BYTES);
    frame[n++] = channel_hash;
    memcpy(frame + n, hmac_full, MC_CIPHER_MAC_SIZE); n += MC_CIPHER_MAC_SIZE;
    memcpy(frame + n, ciphertext, cipher_len); n += cipher_len;

    meshcore_packet_t pkt;
    int rc = meshcore_packet_parse(frame, n, &pkt);
    CHECK(rc == 0, "GRP_DATA: meshcore_packet_parse succeeds");

    meshcore_channelset_t *cs = meshcore_channelset_create();
    CHECK(cs != NULL, "GRP_DATA: channelset_create succeeds");
    char spec[16 + 1 + MC_CHANNEL_SECRET_BYTES * 2 + 1];
    snprintf(spec, sizeof(spec), "TestChan:");
    size_t off = strlen(spec);
    for (int i = 0; i < MC_CHANNEL_SECRET_BYTES; ++i)
        off += (size_t)snprintf(spec + off, sizeof(spec) - off, "%02x", secret[i]);
    CHECK(meshcore_channelset_add_spec(cs, spec, NULL, NULL) == 0, "GRP_DATA: channelset_add_spec succeeds");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    bool ok = meshcore_decode_grp_data(&pkt, cs, &ev);
    CHECK(ok, "GRP_DATA: meshcore_decode_grp_data succeeds");
    CHECK(ev.decrypted, "GRP_DATA: payload decrypted");
    CHECK(ev.mc_data_type == data_type, "GRP_DATA: data_type round-trips");
    CHECK(ev.mc_data_len == data_len, "GRP_DATA: data_len round-trips");
    CHECK(strcmp(ev.mc_text, "deadbeef0102") == 0, "GRP_DATA: hex dump of blob matches");

    meshcore_channelset_destroy(cs);
}

static void test_psk_decode(void)
{
    uint8_t out[MC_CHANNEL_SECRET_BYTES];
    size_t  out_len = 0;

    /* Official MeshCore "Public" channel PSK, base64 -> 16 bytes. */
    bool ok = meshcore_decode_psk("izOH6cXN6mrJ5e26oRXNcg==", out, &out_len);
    CHECK(ok, "PSK decode: valid base64 'Public' PSK decodes");
    CHECK(out_len == 16, "PSK decode: 'Public' PSK decodes to 16 bytes");

    /* 32-byte base64 (no padding needed, len % 4 == 0). */
    static const char *b64_32 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    ok = meshcore_decode_psk(b64_32, out, &out_len);
    CHECK(ok, "PSK decode: valid base64 32-byte PSK decodes");
    CHECK(out_len == 32, "PSK decode: 32-byte base64 PSK decodes to 32 bytes");
    uint8_t expect32[32];
    for (int i = 0; i < 32; ++i) expect32[i] = (uint8_t)i;
    CHECK(memcmp(out, expect32, 32) == 0, "PSK decode: base64 32-byte content round-trips");

    /* Invalid base64 (bad char). */
    ok = meshcore_decode_psk("not_valid_base64_or_hex!!", out, &out_len);
    CHECK(!ok, "PSK decode: invalid base64/hex string is rejected");

    /* Valid base64 alphabet but wrong decoded length (e.g. 8 bytes). */
    ok = meshcore_decode_psk("AAECAwQFBgc=", out, &out_len);
    CHECK(!ok, "PSK decode: base64 decoding to 8 bytes (not 16/32) is rejected");

    /* Existing hex path still works: 64 hex chars -> 32 bytes. */
    static const char *hex32 =
        "1011121314151617" "18191a1b1c1d1e1f" "2021222324252627" "28292a2b2c2d2e2f";
    ok = meshcore_decode_psk(hex32, out, &out_len);
    CHECK(ok, "PSK decode: 64-char hex PSK decodes");
    CHECK(out_len == 32, "PSK decode: hex PSK decodes to 32 bytes");

    /* 32-char hex -> 16 bytes. */
    ok = meshcore_decode_psk("1011121314151617" "18191a1b1c1d1e1f", out, &out_len);
    CHECK(ok, "PSK decode: 32-char hex PSK decodes");
    CHECK(out_len == 16, "PSK decode: hex PSK decodes to 16 bytes");
}

static void test_public_channel_default(void)
{
    meshcore_channelset_t *cs = meshcore_channelset_create();
    CHECK(cs != NULL, "Public default: channelset_create succeeds");
    CHECK(meshcore_channelset_add_default_public(cs, NULL, NULL) == 0,
          "Public default: add_default_public succeeds");

    /* Recover the raw 16-byte secret the same way the CLI-less default
     * path does, to build a matching encrypted GRP_TXT frame. */
    uint8_t secret[MC_CHANNEL_SECRET_BYTES] = {0};
    size_t  secret_len = 0;
    CHECK(meshcore_decode_psk("izOH6cXN6mrJ5e26oRXNcg==", secret, &secret_len),
          "Public default: PSK re-decodes for test setup");
    CHECK(secret_len == 16, "Public default: PSK is 16 bytes");

    uint8_t plain[32] = {0};
    uint32_t ts = 7;
    plain[0] = (uint8_t)ts;
    plain[4] = 0;  /* TXT_TYPE_PLAIN -- meshcore_decode_grp_txt() now rejects
                    * (txt_type>>2)!=0, so the text must start at plain[5],
                    * not plain[4] (this test previously omitted the
                    * txt_type byte entirely and fed the letter 'h' of
                    * "hi:public hello" into that validation instead). */
    const char *msg = "hi:public hello";
    memcpy(plain + 5, msg, strlen(msg));
    size_t plain_len = 5 + strlen(msg);
    size_t padded_len = ((plain_len + 15) / 16) * 16;

    uint8_t ciphertext[32] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1 = 0, outlen2 = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plain, (int)padded_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    size_t cipher_len = (size_t)(outlen1 + outlen2);

    /* Firmware always HMACs with a 32-byte key (GroupChannel::secret
     * is a fixed uint8_t[32], zero-padded by addChannel() when the
     * real PSK -- like this 16-byte "Public" one -- is shorter; see
     * Utils::MACThenDecrypt / meshcore_verify_and_decrypt()). Using
     * just the 16 real secret bytes here used to match this test
     * against the (buggy) production code, but would silently fail
     * against a real MeshCore transmitter. */
    uint8_t hmac_key[32] = {0};
    memcpy(hmac_key, secret, secret_len);
    unsigned char hmac_full[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key), ciphertext, cipher_len, hmac_full, &hmac_len);

    uint8_t frame[300];
    size_t n = 0;
    frame[n++] = (uint8_t)((MC_PAYLOAD_GRP_TXT << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame[n++] = 0; /* path_len: hash_count=0 */
    uint8_t channel_hash = meshcore_channel_hash(secret, secret_len);
    frame[n++] = channel_hash;
    memcpy(frame + n, hmac_full, MC_CIPHER_MAC_SIZE); n += MC_CIPHER_MAC_SIZE;
    memcpy(frame + n, ciphertext, cipher_len); n += cipher_len;

    meshcore_packet_t pkt;
    int rc = meshcore_packet_parse(frame, n, &pkt);
    CHECK(rc == 0, "Public default: meshcore_packet_parse succeeds");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    bool ok = meshcore_decode_grp_txt(&pkt, cs, &ev);
    CHECK(ok, "Public default: meshcore_decode_grp_txt succeeds");
    CHECK(ev.decrypted, "Public default: message decrypted using the preloaded 'Public' channel "
                        "with no user-supplied --meshcore-channel");
    CHECK(strcmp(ev.channel_name, "Public") == 0, "Public default: channel_name == 'Public'");
    CHECK(strstr(ev.mc_text, "public hello") != NULL, "Public default: decoded text matches");

    meshcore_channelset_destroy(cs);
}

static void test_hashtag_public_special_case(void)
{
    /* Regression: a user typing the bare name "Public" into the web
     * dashboard's "Add MeshCore channel" form (or any other
     * add_hashtag() caller, e.g. re-adding it after
     * --meshcore-no-default-channel) used to silently derive
     * SHA256("#Public")[0:16] -- a channel indistinguishable in the UI
     * from the real default, but unable to decrypt any real Public
     * traffic. See meshcore_channelset_add_hashtag(). */
    uint8_t want_secret[MC_CHANNEL_SECRET_BYTES] = {0};
    size_t  want_len = 0;
    CHECK(meshcore_decode_psk("izOH6cXN6mrJ5e26oRXNcg==", want_secret, &want_len),
          "hashtag 'Public': reference PSK decodes for test setup");

    static const char *variants[] = { "Public", "public", "PUBLIC", "#Public" };
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        meshcore_channelset_t *cs = meshcore_channelset_create();
        CHECK(cs != NULL, "hashtag 'Public': channelset_create succeeds");
        CHECK(meshcore_channelset_add_hashtag(cs, variants[i], NULL, NULL) == 0, "hashtag 'Public': add_hashtag succeeds");
        CHECK(cs->n_entries == 1, "hashtag 'Public': exactly one entry added");
        CHECK(cs->entries[0].secret_len == want_len &&
              memcmp(cs->entries[0].secret, want_secret, want_len) == 0,
              "hashtag 'Public': resolves to the real known secret, not a derived hashtag secret");
        CHECK(strcmp(cs->entries[0].name, "Public") == 0, "hashtag 'Public': channel name is 'Public'");
        meshcore_channelset_destroy(cs);
    }
}

static void test_add_channel_dedup_by_name(void)
{
    /* The web dashboard's localStorage-backed channel restore re-POSTs
     * every remembered channel on every page load (see web.c). Without
     * dedup-by-name, that would silently grow the channelset by one
     * entry per reload until MC_CHANNEL_MAX_ENTRIES (32) is exhausted.
     * add_channel_locked() must instead upsert in place by name. */
    meshcore_channelset_t *cs = meshcore_channelset_create();
    CHECK(cs != NULL, "dedup: channelset_create succeeds");

    CHECK(meshcore_channelset_add_hashtag(cs, "test", NULL, NULL) == 0, "dedup: first add_hashtag succeeds");
    CHECK(cs->n_entries == 1, "dedup: exactly one entry after first add");
    uint8_t hash_after_first = cs->entries[0].hash;

    for (int i = 0; i < 5; ++i) {
        CHECK(meshcore_channelset_add_hashtag(cs, "test", NULL, NULL) == 0, "dedup: repeated add_hashtag succeeds");
    }
    CHECK(cs->n_entries == 1, "dedup: repeated adds of the same name do not grow the entry count");
    CHECK(cs->entries[0].hash == hash_after_first, "dedup: re-added entry resolves to the same hash");

    /* A different name must still get its own entry. */
    CHECK(meshcore_channelset_add_hashtag(cs, "other", NULL, NULL) == 0, "dedup: distinct name still adds a new entry");
    CHECK(cs->n_entries == 2, "dedup: distinct name brings total to two entries");

    /* add_hashtag() stores the entry under the display name "#test"
     * (it prefixes '#'), while add_spec() uses whatever name it's
     * given literally -- so re-keying the *same* channel via add_spec
     * means passing "#test:SECRET", not "test:SECRET" (that would be
     * a distinct channel named "test"). This must still upsert
     * cs->entries[0] in place, not append a third entry, and the
     * hash must change to reflect the new explicit secret. */
    CHECK(meshcore_channelset_add_spec(cs, "#test:izOH6cXN6mrJ5e26oRXNcg==", NULL, NULL) == 0,
          "dedup: add_spec re-keying an existing hashtag name succeeds");
    CHECK(cs->n_entries == 2, "dedup: add_spec on an existing name upserts, does not append");
    CHECK(cs->entries[0].hash != hash_after_first,
          "dedup: re-keyed entry's hash reflects the newly supplied secret");

    meshcore_channelset_destroy(cs);
}

/* Regression: the C2 dashboard endpoint (c2.c) needs to know the
 * resulting hash/display name of a channel it just added so it can
 * broadcast MC_CHANNEL_ADDED to connected clients -- without this, a
 * manually-added channel silently updates server state with no way
 * for the UI to learn about it until unrelated new traffic arrives. */
static void test_add_channel_out_params(void)
{
    meshcore_channelset_t *cs = meshcore_channelset_create();
    CHECK(cs != NULL, "out-params: channelset_create succeeds");

    uint8_t hash = 0;
    char display[MC_CHANNEL_MAX_NAME] = {0};
    CHECK(meshcore_channelset_add_hashtag(cs, "fr-48", &hash, display) == 0,
          "out-params: add_hashtag succeeds");
    CHECK(!strcmp(display, "#fr-48"), "out-params: add_hashtag reports the normalized display name");
    CHECK(hash == cs->entries[0].hash, "out-params: add_hashtag reports the entry's actual hash");

    /* "Public" routes through add_default_public internally -- the
     * out-params must still reflect the REAL stored entry, not a
     * derived-from-name guess (see meshcore_channelset_add_hashtag()'s
     * special case). */
    uint8_t pub_hash = 0;
    char pub_display[MC_CHANNEL_MAX_NAME] = {0};
    CHECK(meshcore_channelset_add_hashtag(cs, "public", &pub_hash, pub_display) == 0,
          "out-params: add_hashtag('public') succeeds");
    CHECK(!strcmp(pub_display, "Public"), "out-params: 'public' reports display name 'Public', not '#public'");
    int idx[MC_CHANNEL_MAX_ENTRIES];
    int n = meshcore_channelset_lookup(cs, pub_hash, idx, MC_CHANNEL_MAX_ENTRIES);
    bool found_public = false;
    for (int i = 0; i < n; ++i) if (!strcmp(cs->entries[idx[i]].name, "Public")) found_public = true;
    CHECK(found_public, "out-params: reported hash actually resolves to the stored 'Public' entry");

    uint8_t spec_hash = 0;
    char spec_display[MC_CHANNEL_MAX_NAME] = {0};
    CHECK(meshcore_channelset_add_spec(cs, "MyPrivate:izOH6cXN6mrJ5e26oRXNcg==", &spec_hash, spec_display) == 0,
          "out-params: add_spec succeeds");
    CHECK(!strcmp(spec_display, "MyPrivate"), "out-params: add_spec reports the literal name before the colon");

    /* NULL out-params must remain fully optional (every other caller
     * in this codebase passes NULL, NULL). */
    CHECK(meshcore_channelset_add_hashtag(cs, "another", NULL, NULL) == 0,
          "out-params: NULL out_hash/out_display are accepted");

    meshcore_channelset_destroy(cs);
}

static mesh_event_t g_last_ev;
static bool         g_last_ev_valid;

static void capture_cb(const mesh_event_t *ev, void *user)
{
    (void)user;
    g_last_ev = *ev;
    g_last_ev_valid = true;
}

static void test_txt_msg_envelope(void)
{
    /* TXT_MSG (payload_type 2) used to have no case in the decode
     * switch and fell through to decode_unknown(), losing
     * dest_hash/src_hash for every 1:1 text message. Its envelope is
     * dest_hash(1)+src_hash(1)+MAC(2), same shape as REQ/RESPONSE/PATH
     * -- undecryptable by a passive sniffer without the ECDH shared
     * secret, but dest/src hash should still be extracted. */
    uint8_t frame[64];
    size_t  n = 0;
    frame[n++] = (uint8_t)((MC_PAYLOAD_TXT_MSG << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame[n++] = 0; /* path_len: hash_count=0 */
    frame[n++] = 0x7A; /* dest_hash */
    frame[n++] = 0x3C; /* src_hash */
    frame[n++] = 0xAB; /* MAC[0] (opaque -- no ECDH key to verify against) */
    frame[n++] = 0xCD; /* MAC[1] */

    g_last_ev_valid = false;
    int rc = meshcore_packet_decode_with_radio(frame, n, -80.0f, 5.0f, 7, 5, 125000,
                                               NULL, capture_cb, NULL);
    CHECK(rc == 0, "TXT_MSG: meshcore_packet_decode_with_radio succeeds");
    CHECK(g_last_ev_valid, "TXT_MSG: callback invoked");
    CHECK(strcmp(g_last_ev.mc_type_name, "TXT_MSG") == 0,
          "TXT_MSG: mc_type_name == 'TXT_MSG' (used to fall through to decode_unknown)");
    CHECK(g_last_ev.mc_dest_hash == 0x7A, "TXT_MSG: dest_hash extracted from envelope");
    CHECK(g_last_ev.mc_src_hash == 0x3C, "TXT_MSG: src_hash extracted from envelope");
    CHECK(!g_last_ev.decrypted, "TXT_MSG: not decrypted (no ECDH key available to a passive sniffer)");
}

static void test_trace(void)
{
    /* TRACE (payload_type 9) wire format (Mesh::onRecvPacket, v1.11+):
     *   header path[] (hash_size=1, since TRACE never calls
     *   setPathHashSizeAndCount) = accumulated per-hop SNR bytes, one
     *   signed byte per hop already traversed.
     *   payload = tag(4) + auth_code(4) + flags(1, lower 2 bits =
     *   route hash-entry-size selector, entry_size = 1<<(flags&3)) +
     *   the destination route's hash list, one entry per intended hop.
     * This function used to misread the payload as two n_hops-sized
     * parallel arrays (SNRs then hashes), using the header path's hop
     * count as n_hops for both -- structurally wrong on every count. */
    uint8_t frame[64];
    size_t  n = 0;
    frame[n++] = (uint8_t)((MC_PAYLOAD_TRACE << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_DIRECT);

    /* header path_len byte: hash_count=2 (two hops traversed so far). */
    int n_snr = 2;
    frame[n++] = (uint8_t)(n_snr & MC_PATHLEN_HASH_COUNT_MASK);
    frame[n++] = 48;                 /* SNR hop 0: (int8_t)(12.0*4) */
    frame[n++] = (uint8_t)(int8_t)-14; /* SNR hop 1: (int8_t)(-3.5*4) */

    uint32_t tag = 0xAABBCCDDu, auth = 0x11223344u;
    memcpy(frame + n, &tag, 4);  n += 4;
    memcpy(frame + n, &auth, 4); n += 4;
    frame[n++] = 0x00; /* flags: route path_sz=0 -> 1-byte hash entries */
    uint8_t route_hashes[3] = { 0x11, 0x22, 0x33 };
    memcpy(frame + n, route_hashes, sizeof(route_hashes)); n += sizeof(route_hashes);

    meshcore_packet_t pkt;
    int rc = meshcore_packet_parse(frame, n, &pkt);
    CHECK(rc == 0, "TRACE: meshcore_packet_parse succeeds");
    CHECK(pkt.path_hash_count == n_snr,
          "TRACE: header path_hash_count == 2 (SNR bytes collected so far)");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    bool ok = meshcore_decode_trace(&pkt, &ev);
    CHECK(ok, "TRACE: meshcore_decode_trace succeeds");
    CHECK(ev.mc_path_snrs[0] == 48, "TRACE: SNR hop 0 read from header path[], not payload");
    CHECK((int8_t)ev.mc_path_snrs[1] == -14, "TRACE: SNR hop 1 read from header path[], not payload");
    CHECK(ev.mc_path_hashes[0] == 0x11 && ev.mc_path_hashes[1] == 0x22 && ev.mc_path_hashes[2] == 0x33,
          "TRACE: route hash list decoded from payload (not interleaved with SNRs)");
    CHECK(ev.mc_path_hop_count == 3,
          "TRACE: hop_count reflects the full route length (3), not just SNRs collected so far (2)");
}

int main(void)
{
    test_advert();
    test_advert_latlon();
    test_advert_signature();
    test_grp_txt_crypto();
    test_grp_data_dispatch();
    test_psk_decode();
    test_public_channel_default();
    test_hashtag_public_special_case();
    test_add_channel_dedup_by_name();
    test_add_channel_out_params();
    test_txt_msg_envelope();
    test_trace();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall checks passed\n");
    return 0;
}
