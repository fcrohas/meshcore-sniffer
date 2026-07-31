/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: regression test for db_sqlite.c (the SQLite
 * persistence sink). Exercises init/publish/shutdown directly against
 * synthetic mesh_event_t values, bypassing the full SDR/decode
 * pipeline (which run_selftest() doesn't wire sinks into anyway --
 * archive_init()/db_sqlite_init() are only called from run_live()).
 *
 * Also covers the cross-restart recovery path: node_db_persist_hook()
 * upserting into the `nodes` table, db_sqlite_load_nodes() reloading
 * it, and db_sqlite_replay_recent() replaying recent events.json rows
 * into web_publish_line() (stubbed below -- this binary doesn't link
 * web.c).
 */

#include "db_sqlite.h"
#include "node_db.h"

#include <sqlite3.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); ++failures; } \
    else { fprintf(stderr, "ok:   %s\n", msg); } \
} while (0)

/* db_sqlite.c calls this ad-hoc-extern-declared function (matching the
 * convention used elsewhere -- web_publish_line() isn't in web.h)
 * whenever db_sqlite_replay_recent() replays a historical row. This
 * binary doesn't link web.c, so it provides its own instrumented stub
 * to verify replay actually pushes the expected content. */
static int  g_web_publish_calls = 0;
static char g_web_publish_last[512];
void web_publish_line(const char *json, size_t len)
{
    ++g_web_publish_calls;
    size_t n = len < sizeof(g_web_publish_last) - 1 ? len : sizeof(g_web_publish_last) - 1;
    memcpy(g_web_publish_last, json, n);
    g_web_publish_last[n] = 0;
}

static const char *TEST_DB_PATH = "/tmp/test_db_sqlite_regression.sqlite3";

static void reset_db_file(void)
{
    unlink(TEST_DB_PATH);
    char wal[128], shm[128];
    snprintf(wal, sizeof(wal), "%s-wal", TEST_DB_PATH);
    snprintf(shm, sizeof(shm), "%s-shm", TEST_DB_PATH);
    unlink(wal);
    unlink(shm);
}

static int64_t count_rows(sqlite3 *db)
{
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM events", -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    int64_t n = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) n = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static void test_meshcore_row(void)
{
    reset_db_file();
    CHECK(db_sqlite_init(TEST_DB_PATH), "db_sqlite_init succeeds on a fresh path");

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.decrypted = true;
    ev.has_crc = true;
    ev.payload_crc_ok = true;
    ev.crc_corrected = true;
    ev.crc_corrected_bits = 1;
    ev.rssi_db = -80.0f;
    ev.snr_db = 6.5f;
    ev.sf = 11; ev.cr = 5; ev.bw_hz = 250000;
    ev.mc_payload_type = 5; /* MC_PAYLOAD_GRP_TXT */
    strncpy(ev.mc_type_name, "GRP_TXT", sizeof(ev.mc_type_name) - 1);
    strncpy(ev.mc_text, "hello from a test", sizeof(ev.mc_text) - 1);
    strncpy(ev.channel_name, "Public", sizeof(ev.channel_name) - 1);
    ev.mc_channel_hash = 0x0e;
    strncpy(ev.raw_hex, "deadbeef", sizeof(ev.raw_hex) - 1);

    const char *json = "{\"protocol\":\"meshcore\",\"mc_type\":\"GRP_TXT\"}";
    db_sqlite_publish(&ev, json, strlen(json));

    /* Second row: Meshtastic TEXT_MESSAGE_APP, CRC-fail (untrusted). */
    mesh_event_t ev2;
    memset(&ev2, 0, sizeof(ev2));
    ev2.is_meshcore = false;
    ev2.decrypted = true;
    ev2.has_crc = true;
    ev2.payload_crc_ok = false;
    ev2.header.from = 0xdeadbeef;
    ev2.portnum = 1; /* MESH_PORT_TEXT_MESSAGE */
    static const uint8_t text_payload[] = "Hello";
    ev2.payload = text_payload;
    ev2.payload_len = sizeof(text_payload) - 1;
    db_sqlite_publish(&ev2, "{\"protocol\":\"meshtastic\"}", 26);

    db_sqlite_shutdown();

    sqlite3 *db;
    CHECK(sqlite3_open(TEST_DB_PATH, &db) == SQLITE_OK, "reopen the DB file for verification");
    CHECK(count_rows(db) == 2, "exactly 2 rows were inserted");

    sqlite3_stmt *stmt;
    CHECK(sqlite3_prepare_v2(db,
        "SELECT protocol, type, decrypted, crc_ok, crc_corrected, crc_corrected_bits, node_id, "
        "channel_name, channel_hash, text, raw_hex, json FROM events WHERE protocol='meshcore'",
        -1, &stmt, NULL) == SQLITE_OK, "prepare select for the meshcore row");
    CHECK(sqlite3_step(stmt) == SQLITE_ROW, "meshcore row is present");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 0), "meshcore") == 0, "protocol == 'meshcore'");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 1), "GRP_TXT") == 0, "type == 'GRP_TXT'");
    CHECK(sqlite3_column_int(stmt, 2) == 1, "decrypted == 1");
    CHECK(sqlite3_column_int(stmt, 3) == 1, "crc_ok == 1");
    CHECK(sqlite3_column_int(stmt, 4) == 1, "crc_corrected == 1 (bruteforce-recovered frame)");
    CHECK(sqlite3_column_int(stmt, 5) == 1, "crc_corrected_bits == 1 (single-bit recovery)");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 6), "!8000000e") == 0,
          "node_id == '!8000000e' (GRP_TXT keys off channel_hash 0x0e, tagged with bit 31)");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 7), "Public") == 0, "channel_name == 'Public'");
    CHECK(sqlite3_column_int(stmt, 8) == 0x0e, "channel_hash == 0x0e");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 9), "hello from a test") == 0, "text matches mc_text");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt, 10), "deadbeef") == 0, "raw_hex matches");
    CHECK(strstr((const char *)sqlite3_column_text(stmt, 11), "GRP_TXT") != NULL, "json column holds the full serialized event");
    sqlite3_finalize(stmt);

    sqlite3_stmt *stmt2;
    CHECK(sqlite3_prepare_v2(db,
        "SELECT protocol, type, node_id, crc_ok, text FROM events WHERE protocol='meshtastic'",
        -1, &stmt2, NULL) == SQLITE_OK, "prepare select for the meshtastic row");
    CHECK(sqlite3_step(stmt2) == SQLITE_ROW, "meshtastic row is present");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt2, 1), "TEXT_MESSAGE_APP") == 0, "type == port name 'TEXT_MESSAGE_APP'");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt2, 2), "!deadbeef") == 0, "node_id == '!deadbeef' (from header.from)");
    CHECK(sqlite3_column_int(stmt2, 3) == 0, "crc_ok == 0 (CRC-fail, untrusted row still persisted)");
    CHECK(strcmp((const char *)sqlite3_column_text(stmt2, 4), "Hello") == 0, "text == 'Hello' (Meshtastic payload is raw UTF-8)");
    sqlite3_finalize(stmt2);

    sqlite3_close(db);
    reset_db_file();
}

static void test_publish_before_init_is_noop(void)
{
    /* No db_sqlite_init() call in this process yet for this path --
     * publish must not crash and must not create a file. */
    reset_db_file();
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    db_sqlite_publish(&ev, "{}", 2);
    CHECK(access(TEST_DB_PATH, F_OK) != 0, "publish before init creates no file");
}

static void test_node_reload_and_event_replay(void)
{
    reset_db_file();
    CHECK(db_sqlite_init(TEST_DB_PATH), "db_sqlite_init succeeds for reload test");

    /* node_db_remember() fires node_db_persist_hook() internally --
     * db_sqlite.c's real implementation upserts into the `nodes`
     * table (this target links db_sqlite.c directly, not the stub). */
    node_db_remember(0x1234, "Alice Node", "ALCE", 9, 1);
    node_db_remember(0x5678, "Bob Node", "BOB1", 4, 0);

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    const char *json = "{\"protocol\":\"meshcore\",\"mc_type\":\"GRP_TXT\",\"text\":\"replay me\"}";
    db_sqlite_publish(&ev, json, strlen(json));

    /* Regression check for the "last_seen reset to page-load time"
     * bug: node_db_persist_hook() stamps last_seen with wall-clock
     * "now" on every node_db_remember() call, which is correct for a
     * real sighting but was also firing every time
     * db_sqlite_load_nodes() reloaded the table at startup -- clobbering
     * every node's real last_seen with the restart time. Capture
     * 0x1234's last_seen now (set by the node_db_remember() call
     * above), then assert the reload below leaves it untouched. */
    double last_seen_before;
    {
        sqlite3 *db;
        CHECK(sqlite3_open(TEST_DB_PATH, &db) == SQLITE_OK, "reopen the DB to capture last_seen before reload");
        sqlite3_stmt *stmt;
        CHECK(sqlite3_prepare_v2(db, "SELECT last_seen FROM nodes WHERE id=4660", -1, &stmt, NULL) == SQLITE_OK,
              "prepare last_seen select (id=0x1234=4660) before reload");
        CHECK(sqlite3_step(stmt) == SQLITE_ROW, "node 0x1234 row exists before reload");
        last_seen_before = sqlite3_column_double(stmt, 0);
        CHECK(last_seen_before > 0.0, "last_seen was stamped by node_db_remember()");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    CHECK(db_sqlite_load_nodes(), "db_sqlite_load_nodes succeeds");

    {
        sqlite3 *db;
        CHECK(sqlite3_open(TEST_DB_PATH, &db) == SQLITE_OK, "reopen the DB to check last_seen after reload");
        sqlite3_stmt *stmt;
        CHECK(sqlite3_prepare_v2(db, "SELECT last_seen FROM nodes WHERE id=4660", -1, &stmt, NULL) == SQLITE_OK,
              "prepare last_seen select (id=0x1234=4660) after reload");
        CHECK(sqlite3_step(stmt) == SQLITE_ROW, "node 0x1234 row still exists after reload");
        double last_seen_after = sqlite3_column_double(stmt, 0);
        CHECK(last_seen_after == last_seen_before,
              "db_sqlite_load_nodes() must not clobber last_seen with the reload/restart time");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    node_record_t rec;
    CHECK(node_db_lookup(0x1234, &rec) && strcmp(rec.long_name, "Alice Node") == 0,
          "reloaded node 0x1234 has the persisted long_name");
    CHECK(rec.hw_model == 9 && rec.role == 1, "reloaded node 0x1234 has persisted hw_model/role");
    CHECK(node_db_lookup(0x5678, &rec) && strcmp(rec.short_name, "BOB1") == 0,
          "reloaded node 0x5678 has the persisted short_name");

    g_web_publish_calls = 0;
    CHECK(db_sqlite_replay_recent(24.0), "db_sqlite_replay_recent succeeds within the default window");
    CHECK(g_web_publish_calls >= 1, "replay pushed at least one historical row into web_publish_line");
    CHECK(strstr(g_web_publish_last, "replay me") != NULL, "replayed content matches the published row");

    g_web_publish_calls = 0;
    CHECK(!db_sqlite_replay_recent(0.0), "hours <= 0 is a documented no-op");
    CHECK(g_web_publish_calls == 0, "no-op replay calls web_publish_line zero times");

    db_sqlite_shutdown();
    reset_db_file();
}

static double now_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void publish_chat(uint32_t channel_hash, const char *text, const char *json)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.decrypted = true;
    ev.mc_channel_hash = channel_hash;
    strncpy(ev.mc_text, text, sizeof(ev.mc_text) - 1);
    db_sqlite_publish(&ev, json, strlen(json));
}

/* db_sqlite_query_messages_json() backs the dashboard's "load older
 * messages" scroll-back (GET /api/messages) -- it must page strictly
 * by ts, stay scoped to one channel_hash, and never confuse "no rows
 * yet" with a real failure. */
static void test_query_messages_json(void)
{
    reset_db_file();
    CHECK(db_sqlite_init(TEST_DB_PATH), "db_sqlite_init succeeds for messages-query test");

    publish_chat(0x0e, "msg-0", "{\"seq\":0}");
    usleep(2000);
    double t_after_0 = now_secs();
    usleep(2000);
    publish_chat(0x0e, "msg-1", "{\"seq\":1}");
    usleep(2000);
    publish_chat(0x0e, "msg-2", "{\"seq\":2}");
    usleep(2000);
    /* Different channel -- must never leak into channel 0x0e's results. */
    publish_chat(0x0f, "other-channel", "{\"seq\":99}");

    char *newest = db_sqlite_query_messages_json(0x0e, 0.0, 2);
    CHECK(newest != NULL, "query with no before bound returns non-NULL");
    CHECK(strstr(newest, "\"seq\":2") != NULL, "newest page (limit 2) contains seq 2");
    CHECK(strstr(newest, "\"seq\":1") != NULL, "newest page (limit 2) contains seq 1");
    CHECK(strstr(newest, "\"seq\":0") == NULL, "newest page (limit 2) excludes seq 0");
    CHECK(strstr(newest, "other-channel") == NULL, "newest page never leaks channel 0x0f's row");
    CHECK(strstr(newest, "\"more\":true") != NULL, "newest page reports more:true (seq 0 remains)");
    free(newest);

    /* t_after_0 was captured strictly between msg-0 and msg-1, so only
     * seq 0 should satisfy ts < t_after_0. */
    char *older = db_sqlite_query_messages_json(0x0e, t_after_0, 5);
    CHECK(older != NULL, "before=t_after_0 query returns non-NULL");
    CHECK(strstr(older, "\"seq\":0") != NULL, "before=t_after_0 page contains seq 0");
    CHECK(strstr(older, "\"seq\":1") == NULL, "before=t_after_0 page excludes seq 1 (published after cutoff)");
    CHECK(strstr(older, "\"seq\":2") == NULL, "before=t_after_0 page excludes seq 2");
    CHECK(strstr(older, "\"more\":false") != NULL, "before=t_after_0 page reports more:false (only seq 0 matches)");
    free(older);

    char *empty_channel = db_sqlite_query_messages_json(0xdead, 0.0, 5);
    CHECK(empty_channel != NULL, "query for a channel with zero rows still returns non-NULL");
    CHECK(strstr(empty_channel, "\"messages\":[]") != NULL, "channel with no chat rows returns an empty messages array");
    CHECK(strstr(empty_channel, "\"more\":false") != NULL, "empty result reports more:false");
    free(empty_channel);

    db_sqlite_shutdown();
    reset_db_file();
}

/* Publishes an ADVERT-typed row so bind_node_id()/mc_node_id() derives
 * a real, non-null node_id ("!aabbccdd"-style) from the pubkey prefix
 * -- publish_chat() above leaves mc_payload_type at its zeroed default,
 * which mc_node_id() doesn't recognize, so those rows never get a
 * node_id and can't be used to test the by-node-id query. */
static void publish_advert(uint8_t pk0, uint8_t pk1, uint8_t pk2, uint8_t pk3, const char *json)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.decrypted = true;
    ev.mc_payload_type = 4; /* MC_PAYLOAD_ADVERT */
    ev.mc_pubkey[0] = pk0; ev.mc_pubkey[1] = pk1; ev.mc_pubkey[2] = pk2; ev.mc_pubkey[3] = pk3;
    db_sqlite_publish(&ev, json, strlen(json));
}

/* db_sqlite_query_node_events_json() backs the repeater/node drawer's
 * history hydration (GET /api/node-history) -- same paging contract
 * as db_sqlite_query_messages_json() above, just scoped by node_id
 * instead of channel_hash, so mirror that test's shape. */
static void test_query_node_events_json(void)
{
    reset_db_file();
    CHECK(db_sqlite_init(TEST_DB_PATH), "db_sqlite_init succeeds for node-events-query test");

    publish_advert(0xaa, 0xbb, 0xcc, 0xdd, "{\"seq\":0}");
    usleep(2000);
    double t_after_0 = now_secs();
    usleep(2000);
    publish_advert(0xaa, 0xbb, 0xcc, 0xdd, "{\"seq\":1}");
    usleep(2000);
    publish_advert(0xaa, 0xbb, 0xcc, 0xdd, "{\"seq\":2}");
    usleep(2000);
    /* Different node -- must never leak into !aabbccdd's results. */
    publish_advert(0x11, 0x22, 0x33, 0x44, "{\"seq\":99}");

    char *missing = db_sqlite_query_node_events_json(NULL, 0.0, 5);
    CHECK(missing == NULL, "NULL node_id returns NULL, not a malformed query");
    char *empty_id = db_sqlite_query_node_events_json("", 0.0, 5);
    CHECK(empty_id == NULL, "empty node_id returns NULL");

    char *newest = db_sqlite_query_node_events_json("!aabbccdd", 0.0, 2);
    CHECK(newest != NULL, "query with no before bound returns non-NULL");
    CHECK(strstr(newest, "\"seq\":2") != NULL, "newest page (limit 2) contains seq 2");
    CHECK(strstr(newest, "\"seq\":1") != NULL, "newest page (limit 2) contains seq 1");
    CHECK(strstr(newest, "\"seq\":0") == NULL, "newest page (limit 2) excludes seq 0");
    CHECK(strstr(newest, "\"seq\":99") == NULL, "newest page never leaks a different node's row");
    CHECK(strstr(newest, "\"more\":true") != NULL, "newest page reports more:true (seq 0 remains)");
    free(newest);

    /* t_after_0 was captured strictly between seq 0 and seq 1, so only
     * seq 0 should satisfy ts < t_after_0. */
    char *older = db_sqlite_query_node_events_json("!aabbccdd", t_after_0, 5);
    CHECK(older != NULL, "before=t_after_0 query returns non-NULL");
    CHECK(strstr(older, "\"seq\":0") != NULL, "before=t_after_0 page contains seq 0");
    CHECK(strstr(older, "\"seq\":1") == NULL, "before=t_after_0 page excludes seq 1 (published after cutoff)");
    CHECK(strstr(older, "\"more\":false") != NULL, "before=t_after_0 page reports more:false (only seq 0 matches)");
    free(older);

    char *other_node = db_sqlite_query_node_events_json("!00000001", 0.0, 5);
    CHECK(other_node != NULL, "query for a node with zero rows still returns non-NULL");
    CHECK(strstr(other_node, "\"events\":[]") != NULL, "node with no rows returns an empty events array");
    CHECK(strstr(other_node, "\"more\":false") != NULL, "empty result reports more:false");
    free(other_node);

    db_sqlite_shutdown();
    reset_db_file();
}

static void publish_meshcore_typed(const char *type_name)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.decrypted = true;
    strncpy(ev.mc_type_name, type_name, sizeof(ev.mc_type_name) - 1);
    const char *json = "{}";
    db_sqlite_publish(&ev, json, strlen(json));
}

static void publish_meshcore_channel(uint32_t channel_hash, const char *channel_name)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.decrypted = true;
    ev.mc_channel_hash = channel_hash;
    if (channel_name) strncpy(ev.channel_name, channel_name, sizeof(ev.channel_name) - 1);
    const char *json = "{}";
    db_sqlite_publish(&ev, json, strlen(json));
}

/* db_sqlite_query_known_channel_names() backs main.c's cross-restart
 * MeshCore channel-key recovery (see its doc comment in db_sqlite.h):
 * without it, a channel already cracked in a previous session decrypts
 * nothing until fresh traffic happens to re-trigger discovery. Must
 * return exactly one (the most recent) name per distinct channel_hash,
 * skip hashes that were only ever seen undecrypted (channel_name NULL),
 * and never include an empty string. */
static void test_query_known_channel_names(void)
{
    reset_db_file();
    CHECK(db_sqlite_init(TEST_DB_PATH), "db_sqlite_init succeeds for known-channel-names test");

    publish_meshcore_channel(1, "Public");
    publish_meshcore_channel(3, "fr-48");
    usleep(2000);
    publish_meshcore_channel(3, "fr-48"); /* same hash+name again -- must not duplicate */
    /* Never-named hash -- every message on it arrived undecrypted. */
    publish_meshcore_channel(9, NULL);

    char names[8][40];
    size_t n = db_sqlite_query_known_channel_names(names, 8);
    CHECK(n == 2, "known channel names: exactly 2 distinct named hashes (1 and 3), not 3");

    bool have_public = false, have_fr48 = false;
    for (size_t i = 0; i < n; ++i) {
        if (!strcmp(names[i], "Public")) have_public = true;
        if (!strcmp(names[i], "fr-48")) have_fr48 = true;
    }
    CHECK(have_public, "known channel names: includes 'Public'");
    CHECK(have_fr48, "known channel names: includes 'fr-48', not duplicated despite 2 rows");

    char tiny[1][40];
    size_t capped = db_sqlite_query_known_channel_names(tiny, 1);
    CHECK(capped == 1, "known channel names: respects a max_out smaller than the result set");

    db_sqlite_shutdown();
    reset_db_file();

    CHECK(db_sqlite_init(TEST_DB_PATH), "db_sqlite_init succeeds for empty known-channel-names test");
    size_t empty = db_sqlite_query_known_channel_names(names, 8);
    CHECK(empty == 0, "known channel names: a DB with no named channels returns 0, not garbage");
    db_sqlite_shutdown();
    reset_db_file();
}

static void publish_meshcore_crc(bool has_crc, bool crc_ok, bool crc_corrected)
{
    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore = true;
    ev.decrypted = true;
    ev.has_crc = has_crc;
    ev.payload_crc_ok = crc_ok;
    ev.crc_corrected = crc_corrected;
    const char *json = "{}";
    db_sqlite_publish(&ev, json, strlen(json));
}

/* Statistics tab backing queries: db_sqlite_query_stats_by_type_json(),
 * _by_channel_json(), _crc_json(). Covers the top-7-plus-"Other" fold
 * (more than 7 distinct groups must collapse the tail into one bucket,
 * not silently drop it or emit an 8th+ individual label), the
 * omit-channel_name-when-unnamed contract, the CRC bucket semantics
 * matching the dashboard's existing per-message badge classification,
 * and since_ts actually excluding older rows. */
static void test_query_stats_json(void)
{
    reset_db_file();
    CHECK(db_sqlite_init(TEST_DB_PATH), "db_sqlite_init succeeds for stats-query test");

    /* --- by_type: 9 distinct types, strictly decreasing counts so
     * DESC ordering is unambiguous -- top 7 (counts 9..3) get their own
     * label, the bottom 2 (counts 2,1) fold into "Other" (sum 3). */
    static const char *types[] = {
        "GRP_TXT", "ADVERT", "TRACE", "ACK", "TXT_MSG", "REQ", "RESPONSE", "PATH", "ANON_REQ",
    };
    static const int type_counts[] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i)
        for (int k = 0; k < type_counts[i]; ++k) publish_meshcore_typed(types[i]);

    char *by_type = db_sqlite_query_stats_by_type_json(0.0);
    CHECK(by_type != NULL, "by_type query returns non-NULL");
    CHECK(strstr(by_type, "\"label\":\"GRP_TXT\",\"count\":9") != NULL, "by_type: top type (GRP_TXT, 9) present with correct count");
    CHECK(strstr(by_type, "\"label\":\"RESPONSE\",\"count\":3") != NULL, "by_type: 7th-ranked type (RESPONSE, 3) still gets its own label");
    CHECK(strstr(by_type, "\"label\":\"PATH\"") == NULL, "by_type: 8th-ranked type (PATH) does not get its own label");
    CHECK(strstr(by_type, "\"label\":\"ANON_REQ\"") == NULL, "by_type: 9th-ranked type (ANON_REQ) does not get its own label");
    CHECK(strstr(by_type, "\"label\":\"Other\",\"count\":3") != NULL, "by_type: overflow folds into Other with the correct summed count (2+1)");
    free(by_type);

    /* --- by_channel: same shape, plus the channel_name presence/omission contract. */
    publish_meshcore_channel(1, "Public");
    for (int i = 0; i < 8; ++i) publish_meshcore_channel(2, NULL);
    for (int i = 0; i < 7; ++i) publish_meshcore_channel(3, "fr-48");
    for (int i = 0; i < 6; ++i) publish_meshcore_channel(4, NULL);
    for (int i = 0; i < 5; ++i) publish_meshcore_channel(5, NULL);
    for (int i = 0; i < 4; ++i) publish_meshcore_channel(6, NULL);
    for (int i = 0; i < 3; ++i) publish_meshcore_channel(7, NULL);
    for (int i = 0; i < 8; ++i) publish_meshcore_channel(1, "Public"); /* bring hash 1 up to count 9, ranked #1 */
    for (int i = 0; i < 2; ++i) publish_meshcore_channel(8, NULL);
    publish_meshcore_channel(9, NULL);

    char *by_channel = db_sqlite_query_stats_by_channel_json(0.0);
    CHECK(by_channel != NULL, "by_channel query returns non-NULL");
    CHECK(strstr(by_channel, "\"channel_hash\":1,\"channel_name\":\"Public\",\"count\":9") != NULL,
          "by_channel: named channel (hash 1, 'Public', 9) present with channel_name");
    CHECK(strstr(by_channel, "\"channel_hash\":2,\"count\":8") != NULL,
          "by_channel: unnamed channel (hash 2, 8) omits the channel_name key entirely");
    CHECK(strstr(by_channel, "\"channel_hash\":2,\"channel_name\"") == NULL,
          "by_channel: confirms no channel_name key at all for hash 2 (not even JSON null)");
    CHECK(strstr(by_channel, "\"channel_hash\":7,\"count\":3") != NULL,
          "by_channel: 7th-ranked channel (hash 7, 3) still gets its own entry");
    CHECK(strstr(by_channel, "\"channel_hash\":8") == NULL, "by_channel: 8th-ranked channel (hash 8) folds into Other");
    CHECK(strstr(by_channel, "\"channel_hash\":9") == NULL, "by_channel: 9th-ranked channel (hash 9) folds into Other");
    CHECK(strstr(by_channel, "\"label\":\"Other\",\"count\":3") != NULL,
          "by_channel: overflow folds into Other with the correct summed count (2+1)");
    free(by_channel);

    /* --- crc: mirrors the dashboard's existing per-message badge logic
     * exactly -- crc_ok=1,corrected=0 -> ok; crc_ok=1,corrected=1 ->
     * corrected; crc_ok=0 -> failed; has_crc=false (crc_ok IS NULL in
     * the DB) is excluded from all three buckets. */
    for (int i = 0; i < 3; ++i) publish_meshcore_crc(true, true, false);   /* ok */
    for (int i = 0; i < 2; ++i) publish_meshcore_crc(true, true, true);    /* corrected */
    for (int i = 0; i < 4; ++i) publish_meshcore_crc(true, false, false);  /* failed */
    for (int i = 0; i < 5; ++i) publish_meshcore_crc(false, false, false); /* no CRC at all -- excluded */

    char *crc = db_sqlite_query_stats_crc_json(0.0);
    CHECK(crc != NULL, "crc query returns non-NULL");
    CHECK(strcmp(crc, "{\"ok\":3,\"corrected\":2,\"failed\":4}") == 0,
          "crc buckets match exactly (ok=3, corrected=2, failed=4), excluding the 5 no-CRC rows entirely");
    free(crc);

    /* --- since_ts filtering: a row published before a checkpoint must
     * not appear when querying with that checkpoint as since_ts. */
    double t_checkpoint = now_secs();
    usleep(2000);
    publish_meshcore_typed("MULTIPART");

    char *by_type_filtered = db_sqlite_query_stats_by_type_json(t_checkpoint);
    CHECK(by_type_filtered != NULL, "since_ts-filtered by_type query returns non-NULL");
    CHECK(strstr(by_type_filtered, "\"label\":\"MULTIPART\",\"count\":1") != NULL,
          "since_ts filter includes the row published after the checkpoint");
    CHECK(strstr(by_type_filtered, "\"label\":\"GRP_TXT\"") == NULL,
          "since_ts filter excludes rows published well before the checkpoint");
    free(by_type_filtered);

    db_sqlite_shutdown();
    reset_db_file();
}

int main(void)
{
    test_publish_before_init_is_noop();
    test_meshcore_row();
    test_node_reload_and_event_replay();
    test_query_messages_json();
    test_query_node_events_json();
    test_query_known_channel_names();
    test_query_stats_json();

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall checks passed\n");
    return 0;
}
