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

int main(void)
{
    test_grp_txt_text_and_from_visible();
    test_grp_txt_undecrypted_no_text();
    test_advert_node_and_position_visible();
    test_ack_has_no_from();

    if (failures) {
        fprintf(stderr, "\n%d check(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall checks passed\n");
    return 0;
}
