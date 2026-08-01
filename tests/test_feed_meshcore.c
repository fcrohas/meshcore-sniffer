/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: regression test for feed_serialize_event_meshcore()
 * (feed_meshcore_json.c).
 *
 * Covers two real-world bugs found on live hardware:
 *
 *   1. A GRP_TXT message decrypted successfully (ev->decrypted == true,
 *      ev->mc_text[0] non-empty) but never surfaced any visible text to
 *      the operator. Root cause: the built-in web dashboard's JS drops
 *      every event lacking a top-level "from" field
 *      (`if (!p.from) return;` in web.c) before it ever looks at
 *      "text" -- and no MeshCore event ever emitted "from". This test
 *      asserts the JSON produced by feed_serialize_event_meshcore()
 *      for a decrypted GRP_TXT event contains both "text" and "from".
 *
 *   2. An ADVERT with a name (and optionally lat/lon) never appeared
 *      on the map or in a node list, because nothing ever called
 *      node_db_remember() for MeshCore events. This test asserts (a)
 *      the JSON contains "from"/"long_name"/"lat"/"lon", and (b) that
 *      node_db_lookup() on the derived id returns the ADVERT's name
 *      after serialization.
 */

#include "feed_meshcore_json.h"
#include "feed_meshcore_observer.h"
#include "jw.h"
#include "meshcore.h"
#include "node_db.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); ++failures; } \
    else { fprintf(stderr, "ok:   %s\n", msg); } \
} while (0)

static void test_grp_txt_text_and_from_visible(void)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore     = true;
    ev.decrypted       = true;
    ev.mc_payload_type = MC_PAYLOAD_GRP_TXT;
    ev.slot_id         = -1;
    strncpy(ev.mc_type_name, "GRP_TXT", sizeof(ev.mc_type_name) - 1);
    strncpy(ev.channel_name, "Public", sizeof(ev.channel_name) - 1);
    ev.mc_channel_hash = 0x42;
    strncpy(ev.mc_text, "Paquito: hello mesh", sizeof(ev.mc_text) - 1);

    char buf[2048];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    feed_serialize_event_meshcore(&j, &ev, NULL, 0.0);
    buf[j.len < sizeof(buf) ? j.len : sizeof(buf) - 1] = 0;

    CHECK(strstr(buf, "\"text\":\"Paquito: hello mesh\"") != NULL,
          "GRP_TXT: JSON contains the decoded 'text' field");
    CHECK(strstr(buf, "\"from\":\"!") != NULL,
          "GRP_TXT: JSON contains a generic 'from' field (dashboard requires it "
          "to display anything for this event, including 'text')");
    CHECK(strstr(buf, "\"decrypted\":true") != NULL,
          "GRP_TXT: JSON reports decrypted:true");
}

static void test_grp_txt_undecrypted_no_text(void)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore     = true;
    ev.decrypted       = false;
    ev.mc_payload_type = MC_PAYLOAD_GRP_TXT;
    ev.slot_id         = -1;
    strncpy(ev.mc_type_name, "GRP_TXT", sizeof(ev.mc_type_name) - 1);
    ev.mc_channel_hash = 0x99;
    /* Even if mc_text somehow held stale bytes, an undecrypted event
     * must never surface them. */
    strncpy(ev.mc_text, "should not appear", sizeof(ev.mc_text) - 1);

    char buf[2048];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    feed_serialize_event_meshcore(&j, &ev, NULL, 0.0);
    buf[j.len < sizeof(buf) ? j.len : sizeof(buf) - 1] = 0;

    CHECK(strstr(buf, "\"text\"") == NULL,
          "GRP_TXT: undecrypted event never emits a 'text' field");
}

static void test_advert_node_and_position_visible(void)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore     = true;
    ev.decrypted       = true;
    ev.mc_payload_type = MC_PAYLOAD_ADVERT;
    ev.slot_id         = -1;
    strncpy(ev.mc_type_name, "ADVERT", sizeof(ev.mc_type_name) - 1);
    for (int i = 0; i < MC_PUB_KEY_SIZE; ++i) ev.mc_pubkey[i] = (uint8_t)(0x10 + i);
    ev.mc_has_name  = true;
    strncpy(ev.mc_node_name, "Paquito", sizeof(ev.mc_node_name) - 1);
    ev.mc_has_latlon = true;
    ev.mc_lat = 48.8566;
    ev.mc_lon = 2.3522;

    char buf[2048];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    feed_serialize_event_meshcore(&j, &ev, NULL, 0.0);
    buf[j.len < sizeof(buf) ? j.len : sizeof(buf) - 1] = 0;

    CHECK(strstr(buf, "\"from\":\"!") != NULL,
          "ADVERT: JSON contains a generic 'from' field");
    CHECK(strstr(buf, "\"long_name\":\"Paquito\"") != NULL,
          "ADVERT: JSON contains generic 'long_name' (dashboard node-list label)");
    CHECK(strstr(buf, "\"node_name\":\"Paquito\"") != NULL,
          "ADVERT: JSON still contains the existing 'node_name' field (no regression)");
    CHECK(strstr(buf, "\"lat\":48.8566000") != NULL, "ADVERT: JSON contains 'lat'");
    CHECK(strstr(buf, "\"lon\":2.3522000")  != NULL, "ADVERT: JSON contains 'lon'");

    /* Derive the expected pseudo id the same way
     * feed_serialize_event_meshcore() does (first 4 pubkey bytes),
     * and confirm node_db now knows this node's name -- i.e. the
     * dashboard's node list / map would resolve it. */
    uint32_t expect_id = ((uint32_t)ev.mc_pubkey[0] << 24) |
                         ((uint32_t)ev.mc_pubkey[1] << 16) |
                         ((uint32_t)ev.mc_pubkey[2] << 8)  |
                          (uint32_t)ev.mc_pubkey[3];
    node_record_t rec;
    bool found = node_db_lookup(expect_id, &rec);
    CHECK(found, "ADVERT: node_db now has an entry for the derived pseudo-id "
                 "(was previously never populated for MeshCore -- node list / "
                 "map lookups by id silently found nothing)");
    if (found) {
        CHECK(strcmp(rec.long_name, "Paquito") == 0,
              "ADVERT: node_db entry's long_name matches the ADVERT name");
    }
}

static void test_ack_has_no_from(void)
{
    /* ACK / unknown frames carry no identity info; must not fabricate
     * a "from" for them (regression guard on mc_derive_from_id()). */
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore     = true;
    ev.decrypted       = true;
    ev.mc_payload_type = MC_PAYLOAD_ACK;
    ev.slot_id         = -1;
    strncpy(ev.mc_type_name, "ACK", sizeof(ev.mc_type_name) - 1);

    char buf[2048];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    feed_serialize_event_meshcore(&j, &ev, NULL, 0.0);
    buf[j.len < sizeof(buf) ? j.len : sizeof(buf) - 1] = 0;

    CHECK(strstr(buf, "\"from\"") == NULL,
          "ACK: no fabricated 'from' field for events with no identity info");
}

/* CONTROL's NODE_DISCOVER_RESP application convention (simple_repeater/
 * simple_sensor firmware) reveals a responding node's full pubkey +
 * SNR in the clear -- as informative as an ADVERT, just via a
 * different mechanism. Mirrors test_advert_node_and_position_visible()
 * above: confirms it also derives a real "from" id and populates
 * node_db, so a repeater answering a discovery probe lights up the
 * node list/map even if it never happens to send a fresh ADVERT. */
static void test_control_discover_resp_node_visible(void)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore     = true;
    ev.decrypted       = true;
    ev.mc_payload_type = MC_PAYLOAD_CONTROL;
    ev.slot_id         = -1;
    strncpy(ev.mc_type_name, "CONTROL", sizeof(ev.mc_type_name) - 1);
    strncpy(ev.mc_ctl_subtype, "NODE_DISCOVER_RESP", sizeof(ev.mc_ctl_subtype) - 1);
    ev.mc_adv_type = ADV_TYPE_REPEATER;
    ev.mc_ctl_snr  = 12.0f;
    ev.mc_ctl_tag  = 0xCAFEF00Du;
    for (int i = 0; i < MC_PUB_KEY_SIZE; ++i) ev.mc_pubkey[i] = (uint8_t)(0x50 + i);

    char buf[2048];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    feed_serialize_event_meshcore(&j, &ev, NULL, 0.0);
    buf[j.len < sizeof(buf) ? j.len : sizeof(buf) - 1] = 0;

    CHECK(strstr(buf, "\"from\":\"!") != NULL,
          "CONTROL DISCOVER_RESP: JSON contains a generic 'from' field");
    CHECK(strstr(buf, "\"ctl_subtype\":\"NODE_DISCOVER_RESP\"") != NULL,
          "CONTROL DISCOVER_RESP: JSON contains 'ctl_subtype'");
    CHECK(strstr(buf, "\"adv_type_name\":\"REPEATER\"") != NULL,
          "CONTROL DISCOVER_RESP: JSON contains 'adv_type_name'");

    uint32_t expect_id = ((uint32_t)ev.mc_pubkey[0] << 24) |
                         ((uint32_t)ev.mc_pubkey[1] << 16) |
                         ((uint32_t)ev.mc_pubkey[2] << 8)  |
                          (uint32_t)ev.mc_pubkey[3];
    node_record_t rec;
    bool found = node_db_lookup(expect_id, &rec);
    CHECK(found, "CONTROL DISCOVER_RESP: node_db now has an entry for the derived "
                 "pseudo-id, same as an ADVERT would produce");
}

static void test_observer_schema_flood(void)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore     = true;
    ev.decrypted       = true;
    ev.mc_payload_type = 5;
    ev.mc_route_type   = 1;  /* flood */
    ev.payload_len     = 2;
    ev.snr_db          = 4.0f;
    ev.rssi_db         = -93.0f;
    strncpy(ev.raw_hex, "0a1b2c3d", sizeof(ev.raw_hex) - 1);

    char buf[1024];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    feed_serialize_event_observer(&j, &ev, "ag loft rpt", "A1B2");
    buf[j.len < sizeof(buf) ? j.len : sizeof(buf) - 1] = 0;

    CHECK(strstr(buf, "\"origin\":\"ag loft rpt\"") != NULL, "observer: 'origin' field present");
    CHECK(strstr(buf, "\"origin_id\":\"A1B2\"") != NULL, "observer: 'origin_id' field present");
    CHECK(strstr(buf, "\"type\":\"PACKET\"") != NULL, "observer: 'type' is PACKET");
    CHECK(strstr(buf, "\"direction\":\"rx\"") != NULL, "observer: 'direction' is rx");
    CHECK(strstr(buf, "\"len\":\"4\"") != NULL, "observer: 'len' is raw byte count as a string");
    CHECK(strstr(buf, "\"packet_type\":\"5\"") != NULL, "observer: 'packet_type' matches mc_payload_type");
    CHECK(strstr(buf, "\"route\":\"F\"") != NULL, "observer: flood route_type maps to route 'F'");
    CHECK(strstr(buf, "\"payload_len\":\"2\"") != NULL, "observer: 'payload_len' present");
    CHECK(strstr(buf, "\"raw\":\"0a1b2c3d\"") != NULL, "observer: 'raw' is the hex packet");
    CHECK(strstr(buf, "\"SNR\":\"4.0\"") != NULL, "observer: 'SNR' present");
    CHECK(strstr(buf, "\"RSSI\":\"-93\"") != NULL, "observer: 'RSSI' present");
    CHECK(strstr(buf, "\"path\"") == NULL, "observer: flood packets carry no 'path' field");
}

static void test_observer_schema_direct_path(void)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore          = true;
    ev.decrypted            = true;
    ev.mc_payload_type      = 2;
    ev.mc_route_type        = 2;  /* direct */
    ev.payload_len          = 1;
    strncpy(ev.raw_hex, "aabb", sizeof(ev.raw_hex) - 1);
    ev.mc_hdr_path_hash_count = 2;
    ev.mc_hdr_path_hash_size  = 1;
    ev.mc_hdr_path_len        = 2;
    ev.mc_hdr_path[0]         = 0xC2;
    ev.mc_hdr_path[1]         = 0xE2;

    char buf[1024];
    jw_t j;
    jw_init(&j, buf, sizeof(buf));
    feed_serialize_event_observer(&j, &ev, "ag loft rpt", "A1B2");
    buf[j.len < sizeof(buf) ? j.len : sizeof(buf) - 1] = 0;

    CHECK(strstr(buf, "\"route\":\"D\"") != NULL, "observer: direct route_type maps to route 'D'");
    CHECK(strstr(buf, "\"path\":\"C2 -> E2\"") != NULL, "observer: 'path' renders hop hashes as 'XX -> YY'");
}

int main(void)
{
    test_grp_txt_text_and_from_visible();
    test_grp_txt_undecrypted_no_text();
    test_advert_node_and_position_visible();
    test_ack_has_no_from();
    test_control_discover_resp_node_visible();
    test_observer_schema_flood();
    test_observer_schema_direct_path();

    if (failures) {
        fprintf(stderr, "\n%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall checks passed\n");
    return 0;
}
