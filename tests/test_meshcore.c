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
#include "meshcore_lpp.h"
#include "meshcore_region_dict.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

/* Regression test for the "repeater with bad GPS position" bug: a
 * single flipped bit in ADVERT's lat/lon field (radio corruption, or
 * the CRC bruteforce recovery guessing wrong on a CRC-fail frame)
 * previously produced wild, unmistakably bogus coordinates that got
 * persisted/published as the node's live position -- e.g. a repeater
 * jumping thousands of km, or landing on null island (0,0).
 * meshcore_decode_advert() now drops just the lat/lon on an
 * implausible fix rather than propagating it. */
static void test_advert_latlon_implausible(void)
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

    /* Out-of-range latitude (impossible: > 90 degrees), as seen from a
     * real corrupted capture. */
    frame[n++] = (uint8_t)(ADV_TYPE_REPEATER | ADV_LATLON_MASK | ADV_NAME_MASK);
    int32_t lat_e6 = (int32_t)(-1176.023371 * 1e6);
    int32_t lon_e6 = (int32_t)(-879.116277 * 1e6);
    memcpy(frame + n, &lat_e6, 4); n += 4;
    memcpy(frame + n, &lon_e6, 4); n += 4;
    const char *name = "Bad Fix Repeater";
    memcpy(frame + n, name, strlen(name));
    n += strlen(name);

    meshcore_packet_t pkt;
    int rc = meshcore_packet_parse(frame, n, &pkt);
    CHECK(rc == 0, "ADVERT implausible latlon: meshcore_packet_parse succeeds");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    bool ok = meshcore_decode_advert(&pkt, &ev);
    CHECK(ok, "ADVERT implausible latlon: meshcore_decode_advert succeeds");
    CHECK(!ev.mc_has_latlon, "ADVERT implausible latlon: has_latlon NOT set for out-of-range coordinates");
    CHECK(ev.mc_adv_type == ADV_TYPE_REPEATER, "ADVERT implausible latlon: adv_type still decoded as REPEATER");
    CHECK(strcmp(ev.mc_node_name, "Bad Fix Repeater") == 0,
          "ADVERT implausible latlon: name still decoded despite dropped position");

    /* Second case: exact (0,0) -- the classic "no GPS fix" sentinel,
     * seen in practice from a node that never got a real fix. */
    n = 0;
    frame[n++] = (uint8_t)((MC_PAYLOAD_ADVERT << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame[n++] = 0;
    for (int i = 0; i < MC_PUB_KEY_SIZE; ++i) frame[n++] = (uint8_t)(0xC0 + i);
    frame[n++] = (uint8_t)(ts);
    frame[n++] = (uint8_t)(ts >> 8);
    frame[n++] = (uint8_t)(ts >> 16);
    frame[n++] = (uint8_t)(ts >> 24);
    for (int i = 0; i < MC_SIGNATURE_SIZE; ++i) frame[n++] = (uint8_t)(0x77 + i);
    frame[n++] = (uint8_t)(ADV_TYPE_REPEATER | ADV_LATLON_MASK);
    int32_t zero = 0;
    memcpy(frame + n, &zero, 4); n += 4;
    memcpy(frame + n, &zero, 4); n += 4;

    meshcore_packet_t pkt2;
    CHECK(meshcore_packet_parse(frame, n, &pkt2) == 0, "ADVERT null-island: meshcore_packet_parse succeeds");
    mesh_event_t ev2;
    memset(&ev2, 0, sizeof(ev2));
    CHECK(meshcore_decode_advert(&pkt2, &ev2), "ADVERT null-island: meshcore_decode_advert succeeds");
    CHECK(!ev2.mc_has_latlon, "ADVERT null-island: has_latlon NOT set for (0,0)");
}

/* mesh_event_crc2bit_trusted() (meshcore_decoders.c) is the gate
 * main.c's on_mesh_event() uses before publishing a crc_corrected_bits
 * >= 2 frame as genuinely corrected: a bare 2-bit CRC16 match collides
 * with wrong content often enough (see lora_crc_bruteforce_correct_2bit's
 * doc) that it must not be trusted without independent authentication.
 * Exercises every branch directly against a constructed mesh_event_t,
 * no frame parsing required since this is a pure predicate. */
static void test_crc2bit_trust_gate(void)
{
    mesh_event_t ev;

    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.mc_payload_type = MC_PAYLOAD_GRP_TXT;
    ev.decrypted = true;
    CHECK(mesh_event_crc2bit_trusted(&ev),
          "GRP_TXT with decrypted=true (channel HMAC verified) is trusted");

    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.mc_payload_type = MC_PAYLOAD_GRP_TXT;
    ev.decrypted = false;
    CHECK(!mesh_event_crc2bit_trusted(&ev),
          "GRP_TXT with decrypted=false (no channel HMAC match) is NOT trusted");

    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.mc_payload_type = MC_PAYLOAD_GRP_DATA;
    ev.decrypted = true;
    CHECK(mesh_event_crc2bit_trusted(&ev),
          "GRP_DATA with decrypted=true is trusted");

    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.mc_payload_type = MC_PAYLOAD_ADVERT;
    ev.mc_sig_valid = true;
    CHECK(mesh_event_crc2bit_trusted(&ev),
          "ADVERT with mc_sig_valid=true (Ed25519 verified) is trusted");

    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.mc_payload_type = MC_PAYLOAD_ADVERT;
    ev.mc_sig_valid = false;
    CHECK(!mesh_event_crc2bit_trusted(&ev),
          "ADVERT with mc_sig_valid=false is NOT trusted");

    /* Payload types with no independent MAC/signature check anywhere
     * in this codebase (ACK has no crypto field at all; TXT_MSG/REQ/
     * RESPONSE/PATH/ANON_REQ carry a MAC this passive sniffer can't
     * verify without the peer's ECDH secret; TRACE's auth_code is
     * parsed but not checked) must never be trusted regardless of
     * decrypted/mc_sig_valid. */
    int untrusted_types[] = { MC_PAYLOAD_ACK, MC_PAYLOAD_TXT_MSG, MC_PAYLOAD_REQ,
                               MC_PAYLOAD_RESPONSE, MC_PAYLOAD_PATH, MC_PAYLOAD_ANON_REQ,
                               MC_PAYLOAD_TRACE, MC_PAYLOAD_MULTIPART, MC_PAYLOAD_CONTROL,
                               MC_PAYLOAD_RAW_CUSTOM };
    for (size_t i = 0; i < sizeof(untrusted_types) / sizeof(untrusted_types[0]); ++i) {
        memset(&ev, 0, sizeof(ev));
        ev.is_meshcore = true;
        ev.mc_payload_type = untrusted_types[i];
        ev.decrypted = true;
        ev.mc_sig_valid = true;
        CHECK(!mesh_event_crc2bit_trusted(&ev),
              "payload type with no MAC/signature check is never trusted even if decrypted/mc_sig_valid are true");
    }

    /* The Meshtastic protocol path has no equivalent authentication in
     * this codebase -- is_meshcore=false must never be trusted no
     * matter what the other fields say. */
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = false;
    ev.mc_payload_type = MC_PAYLOAD_GRP_TXT;
    ev.decrypted = true;
    CHECK(!mesh_event_crc2bit_trusted(&ev),
          "Meshtastic path (is_meshcore=false) is never trusted");
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

/* Regression/coverage for meshcore_lpp_decode() (meshcore_lpp.c) in
 * isolation -- validates against known-good encoded values (matching
 * MeshCore firmware's LPPDataHelpers.h scaling exactly) plus the
 * rejection paths that keep GRP_DATA telemetry decode from
 * false-positiving on non-telemetry app data. */
static void test_lpp_decode(void)
{
    /* channel=1 VOLTAGE(116): 3.85V -> 385 = 0x0181.
     * channel=1 TEMPERATURE(103): 23.4C -> 234 = 0x00EA.
     * channel=2 HUMIDITY(104): 45% -> 90 = 0x5A (90/2). */
    uint8_t buf[] = {
        1, 116, 0x01, 0x81,
        1, 103, 0x00, 0xEA,
        2, 104, 0x5A,
    };
    meshcore_lpp_record_t recs[MESHCORE_LPP_MAX_RECORDS];
    int n = meshcore_lpp_decode(buf, sizeof(buf), recs, MESHCORE_LPP_MAX_RECORDS);
    CHECK(n == 3, "LPP: 3-record buffer decodes to 3 records");
    CHECK(recs[0].type == 116 && recs[0].values[0] > 3.84f && recs[0].values[0] < 3.86f,
          "LPP: voltage record ~3.85V");
    CHECK(recs[1].type == 103 && recs[1].values[0] > 23.3f && recs[1].values[0] < 23.5f,
          "LPP: temperature record ~23.4C");
    CHECK(recs[2].type == 104 && recs[2].values[0] > 44.9f && recs[2].values[0] < 45.1f,
          "LPP: humidity record ~45%%");

    char json[512];
    int jl = meshcore_lpp_to_json(recs, n, json, sizeof(json));
    CHECK(jl > 0, "LPP: to_json produces non-empty output");
    CHECK(strstr(json, "\"name\":\"voltage\"") != NULL, "LPP: JSON contains voltage record");
    CHECK(strstr(json, "\"name\":\"temperature\"") != NULL, "LPP: JSON contains temperature record");

    char txt[256];
    int tl = meshcore_lpp_to_text(recs, n, txt, sizeof(txt));
    CHECK(tl > 0, "LPP: to_text produces non-empty output");

    /* Negative temperature: -5.2C -> -52 = 0xFFCC (16-bit two's complement). */
    uint8_t buf_neg[] = { 1, 103, 0xFF, 0xCC };
    int n_neg = meshcore_lpp_decode(buf_neg, sizeof(buf_neg), recs, MESHCORE_LPP_MAX_RECORDS);
    CHECK(n_neg == 1, "LPP: negative-temperature buffer decodes to 1 record");
    CHECK(recs[0].values[0] > -5.3f && recs[0].values[0] < -5.1f,
          "LPP: negative temperature decodes to ~-5.2C (two's complement)");

    /* GPS: 3x 3-byte signed sub-fields (lat/lon /10000, alt /100). */
    int32_t lati = (int32_t)(45.1234 * 10000);
    int32_t loni = (int32_t)(5.6789 * 10000);
    int32_t alti = (int32_t)(250.5 * 100);
    uint8_t gpsbuf[11] = {
        1, 136,
        (uint8_t)(lati >> 16), (uint8_t)(lati >> 8), (uint8_t)lati,
        (uint8_t)(loni >> 16), (uint8_t)(loni >> 8), (uint8_t)loni,
        (uint8_t)(alti >> 16), (uint8_t)(alti >> 8), (uint8_t)alti,
    };
    int n_gps = meshcore_lpp_decode(gpsbuf, sizeof(gpsbuf), recs, MESHCORE_LPP_MAX_RECORDS);
    CHECK(n_gps == 1 && recs[0].n_values == 3, "LPP: GPS record decodes with 3 sub-values");
    CHECK(recs[0].values[0] > 45.12f && recs[0].values[0] < 45.13f, "LPP: GPS lat ~45.1234");
    CHECK(recs[0].values[1] > 5.67f && recs[0].values[1] < 5.69f, "LPP: GPS lon ~5.6789");
    CHECK(recs[0].values[2] > 250.4f && recs[0].values[2] < 250.6f, "LPP: GPS alt ~250.5m");

    /* Arbitrary non-LPP bytes must be rejected, not misparsed -- this
     * is what keeps GRP_DATA telemetry decode from false-positiving on
     * ordinary app data that happens to share the wire shape. */
    uint8_t garbage[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    CHECK(meshcore_lpp_decode(garbage, sizeof(garbage), recs, MESHCORE_LPP_MAX_RECORDS) == -1,
          "LPP: unknown type codes are rejected, not misparsed");

    /* Truncated final record (declares a 2-byte value, only 1 byte present). */
    uint8_t trunc[] = { 1, 103, 0x00 };
    CHECK(meshcore_lpp_decode(trunc, sizeof(trunc), recs, MESHCORE_LPP_MAX_RECORDS) == -1,
          "LPP: truncated record is rejected");

    /* Empty buffer. */
    CHECK(meshcore_lpp_decode(buf, 0, recs, MESHCORE_LPP_MAX_RECORDS) == -1,
          "LPP: zero-length buffer is rejected");
}

/* End-to-end: a GRP_DATA frame whose decrypted blob is a valid
 * CayenneLPP record stream must populate mc_telemetry_json (not just
 * fall back to the hex dump test_grp_data_dispatch already covers for
 * non-LPP blobs). Uses the same encrypt-a-frame scaffolding as
 * test_grp_data_dispatch. */
static void test_grp_data_lpp_telemetry(void)
{
    uint8_t secret[MC_CHANNEL_SECRET_BYTES];
    for (int i = 0; i < MC_CHANNEL_SECRET_BYTES; ++i) secret[i] = (uint8_t)(0x30 + i);

    /* channel=1 VOLTAGE(116): 3.85V; channel=1 TEMPERATURE(103): 23.4C. */
    uint8_t blob[8] = { 1, 116, 0x01, 0x81, 1, 103, 0x00, 0xEA };
    uint16_t data_type = 0x0100; /* "MeshCore Open" per docs/number_allocations.md */
    uint8_t data_len = (uint8_t)sizeof(blob);

    uint8_t plain[32] = {0};
    plain[0] = (uint8_t)(data_type); plain[1] = (uint8_t)(data_type >> 8);
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

    uint8_t frame[300];
    size_t n = 0;
    frame[n++] = (uint8_t)((MC_PAYLOAD_GRP_DATA << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame[n++] = 0;
    uint8_t channel_hash = meshcore_channel_hash(secret, MC_CHANNEL_SECRET_BYTES);
    frame[n++] = channel_hash;
    memcpy(frame + n, hmac_full, MC_CIPHER_MAC_SIZE); n += MC_CIPHER_MAC_SIZE;
    memcpy(frame + n, ciphertext, cipher_len); n += cipher_len;

    meshcore_packet_t pkt;
    CHECK(meshcore_packet_parse(frame, n, &pkt) == 0, "GRP_DATA LPP: meshcore_packet_parse succeeds");

    meshcore_channelset_t *cs = meshcore_channelset_create();
    char spec[16 + 1 + MC_CHANNEL_SECRET_BYTES * 2 + 1];
    snprintf(spec, sizeof(spec), "TelemChan:");
    size_t off = strlen(spec);
    for (int i = 0; i < MC_CHANNEL_SECRET_BYTES; ++i)
        off += (size_t)snprintf(spec + off, sizeof(spec) - off, "%02x", secret[i]);
    CHECK(meshcore_channelset_add_spec(cs, spec, NULL, NULL) == 0, "GRP_DATA LPP: channelset_add_spec succeeds");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    bool ok = meshcore_decode_grp_data(&pkt, cs, &ev);
    CHECK(ok, "GRP_DATA LPP: meshcore_decode_grp_data succeeds");
    CHECK(ev.decrypted, "GRP_DATA LPP: payload decrypted");
    CHECK(strlen(ev.mc_telemetry_json) > 0, "GRP_DATA LPP: mc_telemetry_json populated");
    CHECK(strstr(ev.mc_telemetry_json, "\"name\":\"voltage\"") != NULL,
          "GRP_DATA LPP: telemetry JSON contains the voltage record");
    CHECK(strstr(ev.mc_telemetry_json, "\"name\":\"temperature\"") != NULL,
          "GRP_DATA LPP: telemetry JSON contains the temperature record");
    CHECK(strstr(ev.mc_text, "voltage") != NULL, "GRP_DATA LPP: mc_text summary readable, not a hex dump");

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

/* MULTIPART (payload_type 0x0A) is a cleartext wrapper, no encryption
 * of its own: payload[0] high nibble = packets remaining, low nibble
 * = the wrapped payload's real mc_payload_type_t. Only an ACK inside
 * is cleartext enough to unwrap one level further. */
static void test_multipart(void)
{
    /* Wraps an ACK: remaining=2, inner_type=MC_PAYLOAD_ACK(3). */
    uint8_t frame1[64];
    size_t  n1 = 0;
    frame1[n1++] = (uint8_t)((MC_PAYLOAD_MULTIPART << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame1[n1++] = 0; /* path_len: hash_count=0 */
    frame1[n1++] = (uint8_t)((2 << 4) | MC_PAYLOAD_ACK);
    uint32_t ack_crc = 0xDEADBEEFu;
    memcpy(&frame1[n1], &ack_crc, 4); n1 += 4;

    g_last_ev_valid = false;
    int rc1 = meshcore_packet_decode_with_radio(frame1, n1, -80.0f, 5.0f, 7, 5, 125000,
                                                NULL, capture_cb, NULL);
    CHECK(rc1 == 0, "MULTIPART: meshcore_packet_decode_with_radio succeeds (ACK-wrapped)");
    CHECK(g_last_ev_valid, "MULTIPART: callback invoked (ACK-wrapped)");
    CHECK(g_last_ev.mc_multipart_remaining == 2, "MULTIPART: remaining count == 2");
    CHECK(g_last_ev.mc_multipart_inner_type == MC_PAYLOAD_ACK, "MULTIPART: inner_type == ACK");
    CHECK(g_last_ev.decrypted, "MULTIPART: decrypted == true when wrapping a cleartext ACK");
    CHECK(g_last_ev.mc_timestamp == ack_crc, "MULTIPART: unwrapped ack_crc matches");

    /* Wraps a TXT_MSG: remaining=0, inner_type=MC_PAYLOAD_TXT_MSG(2) --
     * genuinely opaque without TXT_MSG's own ECDH secret, same as if
     * it had arrived un-wrapped. */
    uint8_t frame2[64];
    size_t  n2 = 0;
    frame2[n2++] = (uint8_t)((MC_PAYLOAD_MULTIPART << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame2[n2++] = 0;
    frame2[n2++] = (uint8_t)((0 << 4) | MC_PAYLOAD_TXT_MSG);
    frame2[n2++] = 0x11; frame2[n2++] = 0x22; frame2[n2++] = 0x33; frame2[n2++] = 0x44;

    g_last_ev_valid = false;
    int rc2 = meshcore_packet_decode_with_radio(frame2, n2, -80.0f, 5.0f, 7, 5, 125000,
                                                NULL, capture_cb, NULL);
    CHECK(rc2 == 0, "MULTIPART: meshcore_packet_decode_with_radio succeeds (TXT_MSG-wrapped)");
    CHECK(g_last_ev.mc_multipart_inner_type == MC_PAYLOAD_TXT_MSG, "MULTIPART: inner_type == TXT_MSG");
    CHECK(!g_last_ev.decrypted, "MULTIPART: decrypted == false for a non-ACK inner type");
}

/* CONTROL (payload_type 0x0B) has no protocol-level structure beyond
 * one reserved bit -- this tests the specific NODE_DISCOVER_REQ/_RESP
 * application convention (simple_repeater/simple_sensor firmware). */
static void test_control_discover(void)
{
    /* NODE_DISCOVER_REQ: filter=0x04, tag=0xCAFEF00D, since=0x11223344. */
    uint8_t frame1[64];
    size_t  n1 = 0;
    frame1[n1++] = (uint8_t)((MC_PAYLOAD_CONTROL << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame1[n1++] = 0;
    frame1[n1++] = 0x80; /* CTL_TYPE_NODE_DISCOVER_REQ, prefix_only=0 */
    frame1[n1++] = 0x04; /* filter */
    uint32_t tag1 = 0xCAFEF00Du;
    memcpy(&frame1[n1], &tag1, 4); n1 += 4;
    uint32_t since1 = 0x11223344u;
    memcpy(&frame1[n1], &since1, 4); n1 += 4;

    g_last_ev_valid = false;
    int rc1 = meshcore_packet_decode_with_radio(frame1, n1, -80.0f, 5.0f, 7, 5, 125000,
                                                NULL, capture_cb, NULL);
    CHECK(rc1 == 0, "CONTROL: meshcore_packet_decode_with_radio succeeds (DISCOVER_REQ)");
    CHECK(strcmp(g_last_ev.mc_ctl_subtype, "NODE_DISCOVER_REQ") == 0,
          "CONTROL: mc_ctl_subtype == 'NODE_DISCOVER_REQ'");
    CHECK(g_last_ev.mc_ctl_filter == 0x04, "CONTROL: filter decoded");
    CHECK(g_last_ev.mc_ctl_tag == tag1, "CONTROL: tag decoded");
    CHECK(g_last_ev.mc_ctl_since == since1, "CONTROL: optional since field decoded");
    CHECK(g_last_ev.decrypted, "CONTROL: DISCOVER_REQ is fully cleartext");

    /* NODE_DISCOVER_RESP: node_type=ADV_TYPE_REPEATER, snr=12.0dB (x4=48),
     * tag echoed, 32-byte pubkey -- this is the one that should also
     * derive a real node identity (mc_derive_from_id() in
     * feed_meshcore_json.c / mc_node_id() in db_sqlite.c). */
    uint8_t frame2[64];
    size_t  n2 = 0;
    frame2[n2++] = (uint8_t)((MC_PAYLOAD_CONTROL << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame2[n2++] = 0;
    frame2[n2++] = (uint8_t)(0x90 | ADV_TYPE_REPEATER); /* CTL_TYPE_NODE_DISCOVER_RESP */
    frame2[n2++] = 48; /* SNR x4 = 12.0dB */
    uint32_t tag2 = tag1;
    memcpy(&frame2[n2], &tag2, 4); n2 += 4;
    uint8_t pubkey[MC_PUB_KEY_SIZE];
    for (int i = 0; i < MC_PUB_KEY_SIZE; ++i) pubkey[i] = (uint8_t)(0x50 + i);
    memcpy(&frame2[n2], pubkey, MC_PUB_KEY_SIZE); n2 += MC_PUB_KEY_SIZE;

    g_last_ev_valid = false;
    int rc2 = meshcore_packet_decode_with_radio(frame2, n2, -80.0f, 5.0f, 7, 5, 125000,
                                                NULL, capture_cb, NULL);
    CHECK(rc2 == 0, "CONTROL: meshcore_packet_decode_with_radio succeeds (DISCOVER_RESP)");
    CHECK(strcmp(g_last_ev.mc_ctl_subtype, "NODE_DISCOVER_RESP") == 0,
          "CONTROL: mc_ctl_subtype == 'NODE_DISCOVER_RESP'");
    CHECK(g_last_ev.mc_adv_type == ADV_TYPE_REPEATER, "CONTROL: node_type == ADV_TYPE_REPEATER");
    CHECK(g_last_ev.mc_ctl_snr > 11.9f && g_last_ev.mc_ctl_snr < 12.1f, "CONTROL: SNR ~12.0dB");
    CHECK(g_last_ev.mc_ctl_tag == tag2, "CONTROL: tag echoed back matches");
    CHECK(memcmp(g_last_ev.mc_pubkey, pubkey, MC_PUB_KEY_SIZE) == 0, "CONTROL: responder pubkey decoded");
    CHECK(g_last_ev.decrypted, "CONTROL: DISCOVER_RESP is fully cleartext");

    /* Unrecognized CONTROL sub-type (high nibble 0x50, matches
     * neither convention) -- must not fabricate a subtype or identity. */
    uint8_t frame3[16];
    size_t  n3 = 0;
    frame3[n3++] = (uint8_t)((MC_PAYLOAD_CONTROL << MC_HEADER_PAYLOAD_TYPE_SHIFT) | MC_ROUTE_FLOOD);
    frame3[n3++] = 0;
    frame3[n3++] = 0x57;

    g_last_ev_valid = false;
    int rc3 = meshcore_packet_decode_with_radio(frame3, n3, -80.0f, 5.0f, 7, 5, 125000,
                                                NULL, capture_cb, NULL);
    CHECK(rc3 == 0, "CONTROL: meshcore_packet_decode_with_radio succeeds (unrecognized sub-type)");
    CHECK(g_last_ev.mc_ctl_subtype[0] == 0, "CONTROL: mc_ctl_subtype empty for an unrecognized sub-type");
    CHECK(!g_last_ev.decrypted, "CONTROL: not decrypted for an unrecognized sub-type");
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

/* Reference implementation of upstream's TransportKey::calcTransportCode(),
 * independent of meshcore_region_dict.c's own copy, so this test actually
 * proves the dictionary attack matches what a real firmware node would
 * compute -- not just that our two copies of the same formula agree. */
static uint16_t ref_region_transport_code(const char *region_name, uint8_t payload_type,
                                          const uint8_t *payload, size_t payload_len)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, region_name, strlen(region_name));
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    uint8_t key[16];
    memcpy(key, digest, 16);

    uint8_t msg[256];
    msg[0] = payload_type;
    memcpy(msg + 1, payload, payload_len);
    unsigned char hmac_full[EVP_MAX_MD_SIZE];
    unsigned int  hmac_len = 0;
    HMAC(EVP_sha256(), key, 16, msg, payload_len + 1, hmac_full, &hmac_len);

    uint16_t code = (uint16_t)hmac_full[0] | ((uint16_t)hmac_full[1] << 8);
    if (code == 0) code = 1;
    else if (code == 0xFFFF) code = 0xFFFE;
    return code;
}

static void test_region_resolve(void)
{
    uint8_t payload_type = MC_PAYLOAD_GRP_TXT;
    uint8_t payload[10]  = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

    /* "#Europe" -- exactly as typed in the upstream docs' own examples. */
    uint16_t code = ref_region_transport_code("#Europe", payload_type, payload, sizeof(payload));
    char name[64] = {0};
    bool ok = meshcore_region_resolve_full(payload_type, payload, sizeof(payload), code, name, sizeof(name));
    CHECK(ok, "region: '#Europe' transport code resolves");
    CHECK(ok && !strcmp(name, "#Europe"), "region: resolved name == '#Europe'");

    /* Lowercase, no leading '#' -- exercises the case-variant + bare-name path. */
    uint8_t payload2[6] = {1, 2, 3, 4, 5, 6};
    uint16_t code2 = ref_region_transport_code("uk", payload_type, payload2, sizeof(payload2));
    char name2[64] = {0};
    bool ok2 = meshcore_region_resolve_full(payload_type, payload2, sizeof(payload2), code2, name2, sizeof(name2));
    CHECK(ok2, "region: lowercase 'uk' (no '#') transport code resolves");
    CHECK(ok2 && !strcmp(name2, "uk"), "region: resolved name == 'uk'");

    /* Same region name again with different payload bytes (different code,
     * since the HMAC is payload-dependent) -- exercises the confirmed-name
     * fast path added after the first '#Europe' match above. */
    uint8_t payload3[4] = {9, 9, 9, 9};
    uint16_t code3 = ref_region_transport_code("#Europe", payload_type, payload3, sizeof(payload3));
    char name3[64] = {0};
    bool ok3 = meshcore_region_resolve_full(payload_type, payload3, sizeof(payload3), code3, name3, sizeof(name3));
    CHECK(ok3 && !strcmp(name3, "#Europe"), "region: '#Europe' resolves again via confirmed-name cache");

    /* A private/unlisted region name must NOT produce a false-positive match. */
    uint16_t code4 = ref_region_transport_code("SomeSecretPrivateRegionXYZ", payload_type, payload, sizeof(payload));
    char name4[64] = {0};
    bool ok4 = meshcore_region_resolve_full(payload_type, payload, sizeof(payload), code4, name4, sizeof(name4));
    CHECK(!ok4, "region: unlisted private region name does not false-positive");

    /* French department/region shorthand -- same generated set the
     * channel hashtag dictionary attack already uses (fr-<dept>,
     * fr-<region abbrev>, eu/europe/fr/france), now also tried for
     * region-scope names since French deployments commonly name their
     * scope the same short way (e.g. "fr-occ" for Occitanie). */
    uint8_t payload5[8] = {5, 4, 3, 2, 1, 0, 9, 8};
    uint16_t code5 = ref_region_transport_code("fr-occ", payload_type, payload5, sizeof(payload5));
    char name5[64] = {0};
    bool ok5 = meshcore_region_resolve_full(payload_type, payload5, sizeof(payload5), code5, name5, sizeof(name5));
    CHECK(ok5 && !strcmp(name5, "fr-occ"), "region: 'fr-occ' (Occitanie) resolves via the generated fr-<region> set");

    uint8_t payload6[5] = {7, 7, 7, 7, 7};
    uint16_t code6 = ref_region_transport_code("fr-naq", payload_type, payload6, sizeof(payload6));
    char name6[64] = {0};
    bool ok6 = meshcore_region_resolve_full(payload_type, payload6, sizeof(payload6), code6, name6, sizeof(name6));
    CHECK(ok6 && !strcmp(name6, "fr-naq"), "region: 'fr-naq' (Nouvelle-Aquitaine) resolves via the generated fr-<region> set");

    uint8_t payload7[3] = {1, 2, 3};
    uint16_t code7 = ref_region_transport_code("fr-33", payload_type, payload7, sizeof(payload7));
    char name7[64] = {0};
    bool ok7 = meshcore_region_resolve_full(payload_type, payload7, sizeof(payload7), code7, name7, sizeof(name7));
    CHECK(ok7 && !strcmp(name7, "fr-33"), "region: 'fr-33' (department) resolves via the generated fr-<dept> set");
}

/* Regression: the live decode path (meshcore_decoders.c) must never
 * run the full wordlist scan synchronously -- it was found to
 * regress decode throughput on a busy mesh in practice. Verifies the
 * split actually works end-to-end: resolve_fast() alone must miss an
 * unconfirmed name, meshcore_region_dict_enqueue() must hand it to
 * the background worker, and resolve_fast() must then start hitting
 * once the worker catches up -- proving the background path, not
 * just resolve_full()'s matching logic in isolation, actually works. */
static void test_region_dict_background_enqueue(void)
{
    uint8_t payload_type = MC_PAYLOAD_GRP_TXT;
    uint8_t payload[7] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70};
    /* "Test" is one of the curated built-in candidates (see
     * REGION_CURATED_CANDIDATES, meshcore_region_dict.c) so
     * resolve_full() -- run by the background worker -- can actually
     * find it; a made-up name outside the wordlist would never
     * resolve regardless of the fast/full split being tested here.
     * Not reused by any earlier test in this file, so it starts
     * unconfirmed. */
    uint16_t code = ref_region_transport_code("Test", payload_type, payload, sizeof(payload));

    char name[64] = {0};
    bool fast_before = meshcore_region_resolve_fast(payload_type, payload, sizeof(payload), code, name, sizeof(name));
    CHECK(!fast_before, "region bg: fast path misses an unconfirmed name before enqueue");

    meshcore_region_dict_enqueue(payload_type, payload, sizeof(payload), code);

    bool fast_after = false;
    for (int i = 0; i < 300 && !fast_after; ++i) {
        usleep(10000); /* 10ms */
        memset(name, 0, sizeof(name));
        fast_after = meshcore_region_resolve_fast(payload_type, payload, sizeof(payload), code, name, sizeof(name));
    }
    CHECK(fast_after, "region bg: background worker resolves the enqueued frame");
    CHECK(fast_after && !strcmp(name, "Test"),
          "region bg: resolved name == 'Test'");
}

int main(void)
{
    test_advert();
    test_advert_latlon();
    test_advert_latlon_implausible();
    test_crc2bit_trust_gate();
    test_advert_signature();
    test_grp_txt_crypto();
    test_grp_data_dispatch();
    test_lpp_decode();
    test_grp_data_lpp_telemetry();
    test_psk_decode();
    test_public_channel_default();
    test_hashtag_public_special_case();
    test_add_channel_dedup_by_name();
    test_add_channel_out_params();
    test_txt_msg_envelope();
    test_multipart();
    test_control_discover();
    test_trace();
    test_region_resolve();
    test_region_dict_background_enqueue();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall checks passed\n");
    return 0;
}
