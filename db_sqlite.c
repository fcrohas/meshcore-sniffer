/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: SQLite persistence sink. See db_sqlite.h.
 *
 * Mirrors archive.c's sink shape (init/publish/shutdown, single mutex
 * serializing writes) but stores structured SQL rows instead of
 * gzipped JSONL. WAL mode lets a read-only consumer (future history
 * API, or a live `sqlite3 db.sqlite3` shell) query the DB while the
 * sniffer keeps writing.
 */

#include "db_sqlite.h"
#include "meshcore.h"
#include "meshtastic.h"
#include "node_db.h"

#include <stdio.h>

#ifdef HAVE_SQLITE3

#include <sqlite3.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/* Ad-hoc extern, matching the convention already used by feed.c /
 * geofence.c / main.c -- web_publish_line() isn't declared in web.h. */
extern void web_publish_line(const char *json, size_t len);

static sqlite3        *g_db = NULL;
static sqlite3_stmt    *g_insert_stmt = NULL;
static sqlite3_stmt    *g_node_upsert_stmt = NULL;
static pthread_mutex_t  g_mu = PTHREAD_MUTEX_INITIALIZER;

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS events ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts REAL NOT NULL,"
    "  protocol TEXT NOT NULL,"
    "  type TEXT,"
    "  route_type INTEGER,"
    "  payload_type INTEGER,"
    "  decrypted INTEGER,"
    "  crc_ok INTEGER,"
    "  crc_corrected INTEGER,"
    "  crc_corrected_bits INTEGER,"
    "  rssi_db REAL,"
    "  snr_db REAL,"
    "  sf INTEGER,"
    "  cr INTEGER,"
    "  bw_hz INTEGER,"
    "  node_id TEXT,"
    "  channel_name TEXT,"
    "  channel_hash INTEGER,"
    "  text TEXT,"
    "  route_path_hex TEXT,"
    "  lat REAL,"
    "  lon REAL,"
    "  raw_hex TEXT,"
    "  json TEXT,"
    "  telemetry_json TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);"
    "CREATE INDEX IF NOT EXISTS idx_events_node_id ON events(node_id);"
    "CREATE INDEX IF NOT EXISTS idx_events_channel_ts_chat ON events(channel_hash, ts) WHERE text IS NOT NULL;"
    /* idx_events_telemetry_ts is NOT created here: on a pre-existing
     * DB from before telemetry_json existed, CREATE TABLE IF NOT
     * EXISTS above is a no-op (column still missing) and a partial
     * index predicate referencing a nonexistent column fails at
     * CREATE INDEX time -- which aborts this entire multi-statement
     * exec (sqlite3_exec stops at the first error), so db_sqlite_init()
     * would fail outright on every upgrade from an older DB. Created
     * unconditionally, AFTER the ALTER TABLE ADD COLUMN migration
     * below instead, which guarantees the column exists first (fresh
     * DBs already have it from the CREATE TABLE column list, so this
     * is just a harmless IF NOT EXISTS no-op for them). */
    "CREATE TABLE IF NOT EXISTS nodes ("
    "  id INTEGER PRIMARY KEY,"
    "  long_name TEXT NOT NULL DEFAULT '',"
    "  short_name TEXT NOT NULL DEFAULT '',"
    "  hw_model INTEGER NOT NULL DEFAULT 0,"
    "  role INTEGER NOT NULL DEFAULT 0,"
    "  last_seen REAL"
    ");";

/* Partial-update semantics matching node_db_remember(): only
 * overwrite a field when the incoming value is non-empty/non-zero,
 * so (for example) a POSITION-derived id lookup that doesn't carry a
 * name never blanks out a name learned from an earlier NODEINFO. */
static const char *NODE_UPSERT_SQL =
    "INSERT INTO nodes (id, long_name, short_name, hw_model, role, last_seen) "
    "VALUES (?,?,?,?,?,?) "
    "ON CONFLICT(id) DO UPDATE SET "
    "  long_name = CASE WHEN excluded.long_name <> '' THEN excluded.long_name ELSE nodes.long_name END,"
    "  short_name = CASE WHEN excluded.short_name <> '' THEN excluded.short_name ELSE nodes.short_name END,"
    "  hw_model = CASE WHEN excluded.hw_model <> 0 THEN excluded.hw_model ELSE nodes.hw_model END,"
    "  role = CASE WHEN excluded.role <> 0 THEN excluded.role ELSE nodes.role END,"
    "  last_seen = excluded.last_seen";

static const char *INSERT_SQL =
    "INSERT INTO events ("
    "  ts, protocol, type, route_type, payload_type, decrypted, crc_ok,"
    "  crc_corrected, crc_corrected_bits, rssi_db, snr_db, sf, cr, bw_hz, node_id,"
    "  channel_name, channel_hash, text, route_path_hex, lat, lon,"
    "  raw_hex, json, telemetry_json"
    ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

/* Same derivation as mc_derive_from_id() in feed_meshcore_json.c
 * (kept independent rather than exported/shared, since this is the
 * only other consumer and the two files are otherwise unrelated):
 * ADVERT/ANON_REQ key off the sender's pubkey prefix, GRP_TXT/GRP_DATA
 * key off the channel hash (tagged, so group traffic groups together
 * without colliding with a real node id), REQ/RESPONSE/PATH/TXT_MSG
 * key off whatever dest/src hash bytes are visible, everything else
 * has no usable identity. */
static uint32_t mc_node_id(const mesh_event_t *ev)
{
    if (ev->mc_payload_type == MC_PAYLOAD_ADVERT ||
        ev->mc_payload_type == MC_PAYLOAD_ANON_REQ) {
        return ((uint32_t)ev->mc_pubkey[0] << 24) |
               ((uint32_t)ev->mc_pubkey[1] << 16) |
               ((uint32_t)ev->mc_pubkey[2] << 8)  |
                (uint32_t)ev->mc_pubkey[3];
    }
    if (ev->mc_payload_type == MC_PAYLOAD_GRP_TXT ||
        ev->mc_payload_type == MC_PAYLOAD_GRP_DATA) {
        return 0x80000000u | ev->mc_channel_hash;
    }
    if (ev->mc_dest_hash || ev->mc_src_hash) {
        return 0x40000000u | ((uint32_t)ev->mc_dest_hash << 8) | ev->mc_src_hash;
    }
    return 0;
}

static void bind_node_id(sqlite3_stmt *stmt, int idx, const mesh_event_t *ev)
{
    char buf[16];
    uint32_t id = ev->is_meshcore ? mc_node_id(ev) : ev->header.from;
    if (!id) { sqlite3_bind_null(stmt, idx); return; }
    snprintf(buf, sizeof(buf), "!%08x", id);
    sqlite3_bind_text(stmt, idx, buf, -1, SQLITE_TRANSIENT);
}

static void bind_route_path_hex(sqlite3_stmt *stmt, int idx, const mesh_event_t *ev)
{
    if (!ev->is_meshcore || ev->mc_hdr_path_len <= 0) {
        sqlite3_bind_null(stmt, idx);
        return;
    }
    static const char H[] = "0123456789abcdef";
    char hex[2 * sizeof(ev->mc_hdr_path) + 1];
    int n = ev->mc_hdr_path_len;
    for (int k = 0; k < n; ++k) {
        hex[2*k]     = H[(ev->mc_hdr_path[k] >> 4) & 0xF];
        hex[2*k + 1] = H[ ev->mc_hdr_path[k]       & 0xF];
    }
    hex[2 * n] = '\0';
    sqlite3_bind_text(stmt, idx, hex, -1, SQLITE_TRANSIENT);
}

bool db_sqlite_init(const char *path)
{
    if (g_db) return true;
    if (!path || !*path) return false;

    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: cannot open %s: %s\n", path, sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return false;
    }

    /* WAL: writer doesn't block a concurrent reader (sqlite3 CLI,
     * future history API) inspecting the DB live. */
    char *errmsg = NULL;
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }
    sqlite3_exec(g_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }

    if (sqlite3_exec(g_db, SCHEMA_SQL, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: schema init failed: %s\n", errmsg ? errmsg : "?");
        sqlite3_free(errmsg);
        sqlite3_close(g_db);
        g_db = NULL;
        return false;
    }

    /* Lightweight migration: SCHEMA_SQL's CREATE TABLE IF NOT EXISTS
     * only lays out the full column set for a brand-new DB file. An
     * existing DB from before crc_corrected_bits was added won't get
     * the column added by that statement, so add it explicitly here.
     * Errors are expected (and ignored) on any DB that already has
     * the column -- SQLite has no ADD COLUMN IF NOT EXISTS, and this
     * file has no other versioned-migration mechanism to hook into. */
    sqlite3_exec(g_db, "ALTER TABLE events ADD COLUMN crc_corrected_bits INTEGER;",
                 NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }
    sqlite3_exec(g_db, "ALTER TABLE events ADD COLUMN telemetry_json TEXT;",
                 NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }
    sqlite3_exec(g_db,
                 "CREATE INDEX IF NOT EXISTS idx_events_telemetry_ts "
                 "ON events(ts) WHERE telemetry_json IS NOT NULL;",
                 NULL, NULL, &errmsg);
    if (errmsg) { sqlite3_free(errmsg); errmsg = NULL; }

    if (sqlite3_prepare_v2(g_db, INSERT_SQL, -1, &g_insert_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: prepare insert failed: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return false;
    }

    if (sqlite3_prepare_v2(g_db, NODE_UPSERT_SQL, -1, &g_node_upsert_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: prepare node upsert failed: %s\n", sqlite3_errmsg(g_db));
        sqlite3_finalize(g_insert_stmt); g_insert_stmt = NULL;
        sqlite3_close(g_db);
        g_db = NULL;
        return false;
    }

    fprintf(stderr, "db_sqlite: writing %s\n", path);
    return true;
}

void db_sqlite_publish(const mesh_event_t *ev, const char *json_line, size_t json_len)
{
    if (!g_db || !g_insert_stmt || !ev) return;

    pthread_mutex_lock(&g_mu);

    sqlite3_reset(g_insert_stmt);
    sqlite3_clear_bindings(g_insert_stmt);

    struct timespec ts_now;
    clock_gettime(CLOCK_REALTIME, &ts_now);
    double ts = (double)ts_now.tv_sec + (double)ts_now.tv_nsec / 1e9;

    int i = 1;
    sqlite3_bind_double(g_insert_stmt, i++, ts);
    sqlite3_bind_text(g_insert_stmt, i++, ev->is_meshcore ? "meshcore" : "meshtastic", -1, SQLITE_STATIC);

    if (ev->is_meshcore) {
        sqlite3_bind_text(g_insert_stmt, i++, ev->mc_type_name[0] ? ev->mc_type_name : "UNKNOWN", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(g_insert_stmt, i++, ev->mc_route_type);
        sqlite3_bind_int(g_insert_stmt, i++, ev->mc_payload_type);
    } else {
        sqlite3_bind_text(g_insert_stmt, i++, mesh_port_name(ev->portnum), -1, SQLITE_STATIC);
        sqlite3_bind_null(g_insert_stmt, i++);
        sqlite3_bind_int(g_insert_stmt, i++, (int)ev->portnum);
    }

    sqlite3_bind_int(g_insert_stmt, i++, ev->decrypted ? 1 : 0);
    if (ev->has_crc) sqlite3_bind_int(g_insert_stmt, i++, ev->payload_crc_ok ? 1 : 0);
    else              sqlite3_bind_null(g_insert_stmt, i++);
    sqlite3_bind_int(g_insert_stmt, i++, ev->crc_corrected ? 1 : 0);
    sqlite3_bind_int(g_insert_stmt, i++, ev->crc_corrected_bits);

    if (ev->rssi_db != 0.0f) sqlite3_bind_double(g_insert_stmt, i++, ev->rssi_db);
    else                     sqlite3_bind_null(g_insert_stmt, i++);
    if (ev->snr_db != 0.0f)  sqlite3_bind_double(g_insert_stmt, i++, ev->snr_db);
    else                     sqlite3_bind_null(g_insert_stmt, i++);

    if (ev->sf > 0) {
        sqlite3_bind_int(g_insert_stmt, i++, ev->sf);
        sqlite3_bind_int(g_insert_stmt, i++, ev->cr);
        sqlite3_bind_int(g_insert_stmt, i++, ev->bw_hz);
    } else {
        sqlite3_bind_null(g_insert_stmt, i++);
        sqlite3_bind_null(g_insert_stmt, i++);
        sqlite3_bind_null(g_insert_stmt, i++);
    }

    bind_node_id(g_insert_stmt, i++, ev);

    if (ev->channel_name[0]) sqlite3_bind_text(g_insert_stmt, i++, ev->channel_name, -1, SQLITE_TRANSIENT);
    else                     sqlite3_bind_null(g_insert_stmt, i++);
    if (ev->is_meshcore && ev->mc_channel_hash) sqlite3_bind_int(g_insert_stmt, i++, ev->mc_channel_hash);
    else                                        sqlite3_bind_null(g_insert_stmt, i++);

    /* text: only populated for protocols/ports where mesh_event_t
     * carries a direct plaintext field -- MeshCore GRP_TXT/GRP_DATA
     * (mc_text) and Meshtastic TEXT_MESSAGE_APP (payload is UTF-8
     * directly, per mesh_packet.h). Everything else still has its
     * full decoded shape in the json column. */
    if (ev->decrypted && ev->is_meshcore && ev->mc_text[0]) {
        sqlite3_bind_text(g_insert_stmt, i++, ev->mc_text, -1, SQLITE_TRANSIENT);
    } else if (ev->decrypted && !ev->is_meshcore &&
               ev->portnum == MESH_PORT_TEXT_MESSAGE && ev->payload && ev->payload_len) {
        char text[256];
        size_t n = ev->payload_len < sizeof(text) - 1 ? ev->payload_len : sizeof(text) - 1;
        memcpy(text, ev->payload, n);
        text[n] = 0;
        sqlite3_bind_text(g_insert_stmt, i++, text, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(g_insert_stmt, i++);
    }

    bind_route_path_hex(g_insert_stmt, i++, ev);

    if (ev->is_meshcore && ev->decrypted && ev->mc_has_latlon) {
        sqlite3_bind_double(g_insert_stmt, i++, ev->mc_lat);
        sqlite3_bind_double(g_insert_stmt, i++, ev->mc_lon);
    } else {
        sqlite3_bind_null(g_insert_stmt, i++);
        sqlite3_bind_null(g_insert_stmt, i++);
    }

    if (ev->raw_hex[0]) sqlite3_bind_text(g_insert_stmt, i++, ev->raw_hex, -1, SQLITE_TRANSIENT);
    else                 sqlite3_bind_null(g_insert_stmt, i++);

    if (json_line && json_len) sqlite3_bind_text(g_insert_stmt, i++, json_line, (int)json_len, SQLITE_TRANSIENT);
    else                        sqlite3_bind_null(g_insert_stmt, i++);

    if (ev->is_meshcore && ev->decrypted && ev->mc_telemetry_json[0])
        sqlite3_bind_text(g_insert_stmt, i++, ev->mc_telemetry_json, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(g_insert_stmt, i++);

    if (sqlite3_step(g_insert_stmt) != SQLITE_DONE) {
        fprintf(stderr, "db_sqlite: insert failed: %s\n", sqlite3_errmsg(g_db));
    }

    pthread_mutex_unlock(&g_mu);
}

void db_sqlite_shutdown(void)
{
    pthread_mutex_lock(&g_mu);
    if (g_insert_stmt)      { sqlite3_finalize(g_insert_stmt); g_insert_stmt = NULL; }
    if (g_node_upsert_stmt) { sqlite3_finalize(g_node_upsert_stmt); g_node_upsert_stmt = NULL; }
    if (g_db)               { sqlite3_close(g_db); g_db = NULL; }
    pthread_mutex_unlock(&g_mu);
}

/* Real implementation of node_db.h's pluggable persistence hook: every
 * node_db_remember() call upserts here too, so a restart can reload
 * the table via db_sqlite_load_nodes() below. No-op if --sqlite-db
 * isn't configured (g_db/g_node_upsert_stmt still NULL). */
void node_db_persist_hook(uint32_t id, const char *long_name,
                          const char *short_name, uint32_t hw_model, uint32_t role)
{
    if (!g_db || !g_node_upsert_stmt) return;

    pthread_mutex_lock(&g_mu);
    sqlite3_reset(g_node_upsert_stmt);
    sqlite3_clear_bindings(g_node_upsert_stmt);

    struct timespec ts_now;
    clock_gettime(CLOCK_REALTIME, &ts_now);
    double ts = (double)ts_now.tv_sec + (double)ts_now.tv_nsec / 1e9;

    sqlite3_bind_int64(g_node_upsert_stmt, 1, (sqlite3_int64)id);
    sqlite3_bind_text(g_node_upsert_stmt, 2, long_name ? long_name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_node_upsert_stmt, 3, short_name ? short_name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(g_node_upsert_stmt, 4, (int)hw_model);
    sqlite3_bind_int(g_node_upsert_stmt, 5, (int)role);
    sqlite3_bind_double(g_node_upsert_stmt, 6, ts);

    if (sqlite3_step(g_node_upsert_stmt) != SQLITE_DONE) {
        fprintf(stderr, "db_sqlite: node upsert failed: %s\n", sqlite3_errmsg(g_db));
    }
    pthread_mutex_unlock(&g_mu);
}

bool db_sqlite_load_nodes(void)
{
    if (!g_db) return false;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL = "SELECT id, long_name, short_name, hw_model, role FROM nodes";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: load nodes failed: %s\n", sqlite3_errmsg(g_db));
        return false;
    }

    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint32_t id        = (uint32_t)sqlite3_column_int64(stmt, 0);
        const char *ln     = (const char *)sqlite3_column_text(stmt, 1);
        const char *sn     = (const char *)sqlite3_column_text(stmt, 2);
        uint32_t hw_model  = (uint32_t)sqlite3_column_int(stmt, 3);
        uint32_t role      = (uint32_t)sqlite3_column_int(stmt, 4);
        node_db_load(id, ln, sn, hw_model, role);
        ++n;
    }
    sqlite3_finalize(stmt);
    fprintf(stderr, "db_sqlite: reloaded %d node(s) from the database\n", n);
    return true;
}

bool db_sqlite_replay_recent(double hours)
{
    if (!g_db || hours <= 0.0) return false;

    struct timespec ts_now;
    clock_gettime(CLOCK_REALTIME, &ts_now);
    double now = (double)ts_now.tv_sec + (double)ts_now.tv_nsec / 1e9;
    double since = now - hours * 3600.0;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT json FROM events WHERE ts >= ? AND json IS NOT NULL ORDER BY ts ASC";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: replay query failed: %s\n", sqlite3_errmsg(g_db));
        return false;
    }
    sqlite3_bind_double(stmt, 1, since);

    /* web_publish_line() replays into the SSE history ring only
     * (broadcasts to zero connected clients this early at startup) --
     * it does not re-insert into this same table or re-fire archive/
     * webhook sinks, so this can't create duplicate rows or resend
     * old webhooks. The ring itself caps at 1024 slots regardless of
     * how many rows this query returns (oldest simply falls off). */
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (txt && len > 0) {
            web_publish_line((const char *)txt, (size_t)len);
            ++n;
        }
    }
    sqlite3_finalize(stmt);
    fprintf(stderr, "db_sqlite: replayed %d historical event(s) from the last %.1fh\n", n, hours);
    return true;
}

char *db_sqlite_query_messages_json(uint32_t channel_hash, double before_ts, int limit)
{
    if (!g_db) return NULL;
    if (limit <= 0) limit = 1;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT json FROM events WHERE channel_hash = ?1 AND text IS NOT NULL "
        "AND (?2 <= 0 OR ts < ?2) ORDER BY ts DESC LIMIT ?3";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: messages query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)channel_hash);
    sqlite3_bind_double(stmt, 2, before_ts);
    /* Fetch one extra row so "more" can be derived without a second
     * COUNT(*) query -- if the (limit+1)th row exists, there's more. */
    sqlite3_bind_int(stmt, 3, limit + 1);

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "{\"messages\":[");

    int row_count = 0;
    bool first = true, more = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (row_count >= limit) { more = true; break; }
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (!txt || len <= 0) continue;

        /* Grow to fit: current length + "," + this row + room for the
         * closing "],\"more\":false}" tail written after the loop. */
        size_t need = (size_t)n + 1 + (size_t)len + 24;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        if (!first) buf[n++] = ',';
        first = false;
        memcpy(buf + n, txt, (size_t)len);
        n += len;
        ++row_count;
    }
    sqlite3_finalize(stmt);

    n += snprintf(buf + n, cap - (size_t)n, "],\"more\":%s}", more ? "true" : "false");
    return buf;
}

char *db_sqlite_query_node_events_json(const char *node_id, double before_ts, int limit)
{
    if (!g_db) return NULL;
    if (!node_id || !node_id[0]) return NULL;
    if (limit <= 0) limit = 1;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT json FROM events WHERE node_id = ?1 "
        "AND (?2 <= 0 OR ts < ?2) ORDER BY ts DESC LIMIT ?3";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: node-events query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }
    sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 2, before_ts);
    /* Fetch one extra row so "more" can be derived without a second
     * COUNT(*) query -- if the (limit+1)th row exists, there's more. */
    sqlite3_bind_int(stmt, 3, limit + 1);

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "{\"events\":[");

    int row_count = 0;
    bool first = true, more = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (row_count >= limit) { more = true; break; }
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (!txt || len <= 0) continue;

        size_t need = (size_t)n + 1 + (size_t)len + 24;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        if (!first) buf[n++] = ',';
        first = false;
        memcpy(buf + n, txt, (size_t)len);
        n += len;
        ++row_count;
    }
    sqlite3_finalize(stmt);

    n += snprintf(buf + n, cap - (size_t)n, "],\"more\":%s}", more ? "true" : "false");
    return buf;
}

char *db_sqlite_query_telemetry_json(double before_ts, int limit)
{
    if (!g_db) return NULL;
    if (limit <= 0) limit = 1;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT json FROM events WHERE telemetry_json IS NOT NULL "
        "AND (?1 <= 0 OR ts < ?1) ORDER BY ts DESC LIMIT ?2";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: telemetry query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }
    sqlite3_bind_double(stmt, 1, before_ts);
    /* Fetch one extra row so "more" can be derived without a second
     * COUNT(*) query -- if the (limit+1)th row exists, there's more. */
    sqlite3_bind_int(stmt, 2, limit + 1);

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "{\"telemetry\":[");

    int row_count = 0;
    bool first = true, more = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (row_count >= limit) { more = true; break; }
        const unsigned char *txt = sqlite3_column_text(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        if (!txt || len <= 0) continue;

        size_t need = (size_t)n + 1 + (size_t)len + 24;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        if (!first) buf[n++] = ',';
        first = false;
        memcpy(buf + n, txt, (size_t)len);
        n += len;
        ++row_count;
    }
    sqlite3_finalize(stmt);

    n += snprintf(buf + n, cap - (size_t)n, "],\"more\":%s}", more ? "true" : "false");
    return buf;
}

/* Escape a raw string for embedding in a JSON string literal (quote,
 * backslash, and C0 control chars) -- node long/short names are free
 * text heard over the mesh, not trusted input. UTF-8 multi-byte
 * sequences (the emoji all over real node names) pass through
 * unescaped, since they're already legal inside a JSON string.
 * Truncates safely if outcap is too small for the full escaped output. */
static void json_escape_str(const char *src, char *out, size_t outcap)
{
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p && o + 7 < outcap; ++p) {
        if (*p == '"' || *p == '\\') {
            out[o++] = '\\'; out[o++] = (char)*p;
        } else if (*p < 0x20) {
            o += (size_t)snprintf(out + o, outcap - o, "\\u%04x", *p);
        } else {
            out[o++] = (char)*p;
        }
    }
    out[o] = 0;
}

char *db_sqlite_query_nodes_json(void)
{
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT id, long_name, short_name, hw_model, role, last_seen FROM nodes";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: nodes query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "[");
    bool first = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint32_t id = (uint32_t)sqlite3_column_int64(stmt, 0);
        const unsigned char *ln = sqlite3_column_text(stmt, 1);
        const unsigned char *sn = sqlite3_column_text(stmt, 2);
        int hw_model = sqlite3_column_int(stmt, 3);
        int role = sqlite3_column_int(stmt, 4);
        double last_seen = sqlite3_column_type(stmt, 5) == SQLITE_NULL
                            ? 0.0 : sqlite3_column_double(stmt, 5);

        /* Escape long_name/short_name minimally (quote/backslash/control
         * chars) -- these are free-text node names from the mesh, not
         * trusted input. Worst case per input byte is 6 output bytes
         * (\u00XX), sized into the growth check below. */
        char ln_esc[6 * NODE_DB_LONG_NAME + 8];
        char sn_esc[6 * NODE_DB_SHORT_NAME + 8];
        json_escape_str(ln ? (const char *)ln : "", ln_esc, sizeof(ln_esc));
        json_escape_str(sn ? (const char *)sn : "", sn_esc, sizeof(sn_esc));

        size_t need = (size_t)n + strlen(ln_esc) + strlen(sn_esc) + 128;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        n += snprintf(buf + n, cap - (size_t)n,
                      "%s{\"id\":\"!%08x\",\"long_name\":\"%s\",\"short_name\":\"%s\","
                      "\"hw_model\":%d,\"role\":%d,\"last_seen\":%.3f}",
                      first ? "" : ",", id, ln_esc, sn_esc, hw_model, role, last_seen);
        first = false;
    }
    sqlite3_finalize(stmt);

    n += snprintf(buf + n, cap - (size_t)n, "]");
    (void)n;
    return buf;
}

char *db_sqlite_query_positions_json(void)
{
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    /* Last known position per node_id. Relies on SQLite's documented
     * "bare columns in an aggregate query" behavior: when a non-aggregated
     * column appears alongside MAX() in a GROUP BY query, SQLite returns
     * that column's value from the same row that produced the MAX --
     * so lat/lon here are guaranteed to be the pair from each node's
     * most recent position, not an arbitrary/mismatched row. */
    static const char *SQL =
        "SELECT node_id, lat, lon, MAX(ts) FROM events "
        "WHERE lat IS NOT NULL AND node_id IS NOT NULL GROUP BY node_id";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: positions query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "[");
    bool first = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *node_id = sqlite3_column_text(stmt, 0);
        double lat = sqlite3_column_double(stmt, 1);
        double lon = sqlite3_column_double(stmt, 2);
        double ts  = sqlite3_column_double(stmt, 3);
        if (!node_id) continue;

        size_t need = (size_t)n + strlen((const char *)node_id) + 96;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        n += snprintf(buf + n, cap - (size_t)n,
                      "%s{\"node_id\":\"%s\",\"lat\":%.7f,\"lon\":%.7f,\"ts\":%.3f}",
                      first ? "" : ",", (const char *)node_id, lat, lon, ts);
        first = false;
    }
    sqlite3_finalize(stmt);

    n += snprintf(buf + n, cap - (size_t)n, "]");
    (void)n;
    return buf;
}

char *db_sqlite_query_stats_by_type_json(double since_ts)
{
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT COALESCE(type,'UNKNOWN'), COUNT(*) AS cnt FROM events "
        "WHERE protocol='meshcore' AND ts >= ?1 GROUP BY type ORDER BY cnt DESC";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: stats-by-type query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }
    sqlite3_bind_double(stmt, 1, since_ts);

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "[");
    bool first = true;
    int row_index = 0;
    long other_sum = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *type = sqlite3_column_text(stmt, 0);
        long cnt = (long)sqlite3_column_int64(stmt, 1);
        if (row_index >= 7) {
            other_sum += cnt;
            ++row_index;
            continue;
        }
        char esc[136];
        json_escape_str(type ? (const char *)type : "UNKNOWN", esc, sizeof(esc));

        size_t need = (size_t)n + strlen(esc) + 64;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        n += snprintf(buf + n, cap - (size_t)n, "%s{\"label\":\"%s\",\"count\":%ld}",
                      first ? "" : ",", esc, cnt);
        first = false;
        ++row_index;
    }
    sqlite3_finalize(stmt);

    if (other_sum > 0) {
        size_t need = (size_t)n + 64;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
            cap = newcap;
        }
        n += snprintf(buf + n, cap - (size_t)n, "%s{\"label\":\"Other\",\"count\":%ld}",
                      first ? "" : ",", other_sum);
    }

    n += snprintf(buf + n, cap - (size_t)n, "]");
    (void)n;
    return buf;
}

char *db_sqlite_query_stats_by_channel_json(double since_ts)
{
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT channel_hash, channel_name, COUNT(*) AS cnt FROM events "
        "WHERE protocol='meshcore' AND ts >= ?1 AND channel_hash IS NOT NULL "
        "GROUP BY channel_hash ORDER BY cnt DESC";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: stats-by-channel query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }
    sqlite3_bind_double(stmt, 1, since_ts);

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "[");
    bool first = true;
    int row_index = 0;
    long other_sum = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        long channel_hash = (long)sqlite3_column_int64(stmt, 0);
        const unsigned char *cname = sqlite3_column_text(stmt, 1);
        long cnt = (long)sqlite3_column_int64(stmt, 2);
        if (row_index >= 7) {
            other_sum += cnt;
            ++row_index;
            continue;
        }
        bool has_name = cname && *cname;
        char esc[256] = {0};
        if (has_name) json_escape_str((const char *)cname, esc, sizeof(esc));

        size_t need = (size_t)n + (has_name ? strlen(esc) : 0) + 96;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        if (has_name) {
            n += snprintf(buf + n, cap - (size_t)n,
                          "%s{\"channel_hash\":%ld,\"channel_name\":\"%s\",\"count\":%ld}",
                          first ? "" : ",", channel_hash, esc, cnt);
        } else {
            n += snprintf(buf + n, cap - (size_t)n,
                          "%s{\"channel_hash\":%ld,\"count\":%ld}",
                          first ? "" : ",", channel_hash, cnt);
        }
        first = false;
        ++row_index;
    }
    sqlite3_finalize(stmt);

    if (other_sum > 0) {
        size_t need = (size_t)n + 64;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
            cap = newcap;
        }
        n += snprintf(buf + n, cap - (size_t)n, "%s{\"label\":\"Other\",\"count\":%ld}",
                      first ? "" : ",", other_sum);
    }

    n += snprintf(buf + n, cap - (size_t)n, "]");
    (void)n;
    return buf;
}

char *db_sqlite_query_stats_crc_json(double since_ts)
{
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT "
        "  SUM(CASE WHEN crc_ok=1 AND crc_corrected=0 THEN 1 ELSE 0 END), "
        "  SUM(CASE WHEN crc_ok=1 AND crc_corrected=1 THEN 1 ELSE 0 END), "
        "  SUM(CASE WHEN crc_ok=0 THEN 1 ELSE 0 END) "
        "FROM events WHERE protocol='meshcore' AND ts >= ?1";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: stats-crc query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }
    sqlite3_bind_double(stmt, 1, since_ts);

    long ok = 0, corrected = 0, failed = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        ok        = sqlite3_column_type(stmt, 0) == SQLITE_NULL ? 0 : (long)sqlite3_column_int64(stmt, 0);
        corrected = sqlite3_column_type(stmt, 1) == SQLITE_NULL ? 0 : (long)sqlite3_column_int64(stmt, 1);
        failed    = sqlite3_column_type(stmt, 2) == SQLITE_NULL ? 0 : (long)sqlite3_column_int64(stmt, 2);
    }
    sqlite3_finalize(stmt);

    char *buf = malloc(96);
    if (!buf) return NULL;
    snprintf(buf, 96, "{\"ok\":%ld,\"corrected\":%ld,\"failed\":%ld}", ok, corrected, failed);
    return buf;
}

char *db_sqlite_query_channel_names_json(void)
{
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    /* Bare-column trick (documented SQLite behavior): with a single
     * MAX() aggregate and GROUP BY, non-aggregated columns in the
     * result set are taken from the row that produced the max value --
     * so channel_name here is always the most recently observed name
     * for that hash, not an arbitrary row's (which could be NULL, from
     * an undecrypted frame sharing the same channel_hash bucket).
     *
     * The outer query joins back onto ALL events for a named hash (not
     * just the ones carrying a name) to get a real total/decrypted/
     * last_ts -- otherwise a channel whose PSK was only cracked partway
     * through its history would undercount messages seen before the
     * crack. Without this, the dashboard's Channels-tab bootstrap
     * (bootstrapChannelsFromApi() in web.c) had nothing but a name for
     * a channel with no *live* traffic yet this session, and seeded
     * total=0/ts=0 stand-ins that rendered as "0 messages" and a
     * decades-long "ago" despite the channel having real history. */
    static const char *SQL =
        "SELECT e.channel_hash, names.channel_name, COUNT(*), "
        "SUM(CASE WHEN e.decrypted = 1 THEN 1 ELSE 0 END), MAX(e.ts) "
        "FROM events e JOIN ("
        "  SELECT channel_hash, channel_name, MAX(ts) AS name_ts FROM events "
        "  WHERE protocol='meshcore' AND channel_hash IS NOT NULL "
        "  AND channel_name IS NOT NULL AND channel_name != '' "
        "  GROUP BY channel_hash"
        ") names ON names.channel_hash = e.channel_hash "
        "WHERE e.protocol='meshcore' AND e.channel_hash IS NOT NULL "
        "GROUP BY e.channel_hash";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: channel-names query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }

    size_t cap = 256;
    char *buf = malloc(cap);
    if (!buf) { sqlite3_finalize(stmt); return NULL; }
    int n = snprintf(buf, cap, "[");
    bool first = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        long channel_hash = (long)sqlite3_column_int64(stmt, 0);
        const unsigned char *cname = sqlite3_column_text(stmt, 1);
        long total = (long)sqlite3_column_int64(stmt, 2);
        long decrypted = (long)sqlite3_column_int64(stmt, 3);
        double last_ts = sqlite3_column_double(stmt, 4);

        char esc[256];
        json_escape_str(cname ? (const char *)cname : "", esc, sizeof(esc));

        size_t need = (size_t)n + strlen(esc) + 128;
        if (need > cap) {
            size_t newcap = cap * 2;
            while (newcap < need) newcap *= 2;
            char *nb = realloc(buf, newcap);
            if (!nb) { free(buf); sqlite3_finalize(stmt); return NULL; }
            buf = nb;
            cap = newcap;
        }
        n += snprintf(buf + n, cap - (size_t)n,
                      "%s{\"channel_hash\":%ld,\"channel_name\":\"%s\","
                      "\"protocol\":\"meshcore\",\"total\":%ld,\"decrypted\":%ld,"
                      "\"last_ts\":%.3f}",
                      first ? "" : ",", channel_hash, esc, total, decrypted, last_ts);
        first = false;
    }
    sqlite3_finalize(stmt);

    n += snprintf(buf + n, cap - (size_t)n, "]");
    (void)n;
    return buf;
}

db_sqlite_undecrypted_row_t *db_sqlite_query_undecrypted_channel_rows(uint8_t channel_hash, size_t *out_n)
{
    if (out_n) *out_n = 0;
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT id, ts, sf, cr, bw_hz, rssi_db, snr_db, raw_hex FROM events "
        "WHERE protocol='meshcore' AND channel_hash=?1 AND decrypted=0 "
        "AND raw_hex IS NOT NULL AND payload_type IN (5, 6)"; /* MC_PAYLOAD_GRP_TXT, MC_PAYLOAD_GRP_DATA */
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: undecrypted-rows query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }
    sqlite3_bind_int(stmt, 1, (int)channel_hash);

    size_t cap = 16, n = 0;
    db_sqlite_undecrypted_row_t *rows = malloc(cap * sizeof(*rows));
    if (!rows) { sqlite3_finalize(stmt); return NULL; }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *raw_hex = sqlite3_column_text(stmt, 7);
        if (!raw_hex || !*raw_hex) continue;
        if (n == cap) {
            cap *= 2;
            db_sqlite_undecrypted_row_t *nb = realloc(rows, cap * sizeof(*rows));
            if (!nb) break;
            rows = nb;
        }
        db_sqlite_undecrypted_row_t *r = &rows[n];
        r->id      = sqlite3_column_int64(stmt, 0);
        r->ts      = sqlite3_column_double(stmt, 1);
        r->sf      = sqlite3_column_int(stmt, 2);
        r->cr      = sqlite3_column_int(stmt, 3);
        r->bw_hz   = sqlite3_column_int(stmt, 4);
        r->rssi_db = sqlite3_column_double(stmt, 5);
        r->snr_db  = sqlite3_column_double(stmt, 6);
        snprintf(r->raw_hex, sizeof(r->raw_hex), "%s", (const char *)raw_hex);
        ++n;
    }
    sqlite3_finalize(stmt);

    if (n == 0) { free(rows); rows = NULL; }
    if (out_n) *out_n = n;
    return rows;
}

bool db_sqlite_apply_redecrypt(int64_t id, const char *channel_name,
                               const char *text, const char *json, size_t json_len)
{
    if (!g_db) return false;

    static const char *SQL =
        "UPDATE events SET decrypted=1, channel_name=?1, text=?2, json=?3 WHERE id=?4";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: redecrypt update prepare failed: %s\n", sqlite3_errmsg(g_db));
        return false;
    }

    pthread_mutex_lock(&g_mu);
    if (channel_name && channel_name[0]) sqlite3_bind_text(stmt, 1, channel_name, -1, SQLITE_TRANSIENT);
    else                                  sqlite3_bind_null(stmt, 1);
    if (text && text[0]) sqlite3_bind_text(stmt, 2, text, -1, SQLITE_TRANSIENT);
    else                  sqlite3_bind_null(stmt, 2);
    if (json && json_len) sqlite3_bind_text(stmt, 3, json, (int)json_len, SQLITE_TRANSIENT);
    else                   sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)id);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(g_db) > 0;
    if (!ok) fprintf(stderr, "db_sqlite: redecrypt update failed for id=%lld: %s\n",
                     (long long)id, sqlite3_errmsg(g_db));
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_mu);
    return ok;
}

db_sqlite_crc_fail_row_t *db_sqlite_query_meshcore_crc_fail_rows(size_t *out_n)
{
    if (out_n) *out_n = 0;
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT id, ts, sf, cr, bw_hz, rssi_db, snr_db, raw_hex FROM events "
        "WHERE protocol='meshcore' AND crc_ok=0 AND raw_hex IS NOT NULL";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: crc-fail-rows query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }

    size_t cap = 16, n = 0;
    db_sqlite_crc_fail_row_t *rows = malloc(cap * sizeof(*rows));
    if (!rows) { sqlite3_finalize(stmt); return NULL; }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *raw_hex = sqlite3_column_text(stmt, 7);
        if (!raw_hex || !*raw_hex) continue;
        if (n == cap) {
            cap *= 2;
            db_sqlite_crc_fail_row_t *nb = realloc(rows, cap * sizeof(*rows));
            if (!nb) break;
            rows = nb;
        }
        db_sqlite_crc_fail_row_t *r = &rows[n];
        r->id      = sqlite3_column_int64(stmt, 0);
        r->ts      = sqlite3_column_double(stmt, 1);
        r->sf      = sqlite3_column_int(stmt, 2);
        r->cr      = sqlite3_column_int(stmt, 3);
        r->bw_hz   = sqlite3_column_int(stmt, 4);
        r->rssi_db = sqlite3_column_double(stmt, 5);
        r->snr_db  = sqlite3_column_double(stmt, 6);
        snprintf(r->raw_hex, sizeof(r->raw_hex), "%s", (const char *)raw_hex);
        ++n;
    }
    sqlite3_finalize(stmt);

    if (n == 0) { free(rows); rows = NULL; }
    if (out_n) *out_n = n;
    return rows;
}

bool db_sqlite_apply_crc_recover(int64_t id, int crc_corrected_bits, bool decrypted,
                                  const char *channel_name, const char *text,
                                  const char *json, size_t json_len)
{
    if (!g_db) return false;

    static const char *SQL =
        "UPDATE events SET crc_ok=1, crc_corrected=1, crc_corrected_bits=?1, "
        "decrypted=?2, channel_name=?3, text=?4, json=?5 WHERE id=?6";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: crc-recover update prepare failed: %s\n", sqlite3_errmsg(g_db));
        return false;
    }

    pthread_mutex_lock(&g_mu);
    sqlite3_bind_int(stmt, 1, crc_corrected_bits);
    sqlite3_bind_int(stmt, 2, decrypted ? 1 : 0);
    if (channel_name && channel_name[0]) sqlite3_bind_text(stmt, 3, channel_name, -1, SQLITE_TRANSIENT);
    else                                  sqlite3_bind_null(stmt, 3);
    if (text && text[0]) sqlite3_bind_text(stmt, 4, text, -1, SQLITE_TRANSIENT);
    else                  sqlite3_bind_null(stmt, 4);
    if (json && json_len) sqlite3_bind_text(stmt, 5, json, (int)json_len, SQLITE_TRANSIENT);
    else                   sqlite3_bind_null(stmt, 5);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)id);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(g_db) > 0;
    if (!ok) fprintf(stderr, "db_sqlite: crc-recover update failed for id=%lld: %s\n",
                     (long long)id, sqlite3_errmsg(g_db));
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_mu);
    return ok;
}

db_sqlite_region_scope_row_t *db_sqlite_query_region_scope_rows(size_t *out_n)
{
    if (out_n) *out_n = 0;
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT id, ts, sf, cr, bw_hz, rssi_db, snr_db, raw_hex FROM events "
        "WHERE protocol='meshcore' AND route_type IN (0,3) AND raw_hex IS NOT NULL";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: region-scope-rows query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }

    size_t cap = 16, n = 0;
    db_sqlite_region_scope_row_t *rows = malloc(cap * sizeof(*rows));
    if (!rows) { sqlite3_finalize(stmt); return NULL; }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *raw_hex = sqlite3_column_text(stmt, 7);
        if (!raw_hex || !*raw_hex) continue;
        if (n == cap) {
            cap *= 2;
            db_sqlite_region_scope_row_t *nb = realloc(rows, cap * sizeof(*rows));
            if (!nb) break;
            rows = nb;
        }
        db_sqlite_region_scope_row_t *r = &rows[n];
        r->id      = sqlite3_column_int64(stmt, 0);
        r->ts      = sqlite3_column_double(stmt, 1);
        r->sf      = sqlite3_column_int(stmt, 2);
        r->cr      = sqlite3_column_int(stmt, 3);
        r->bw_hz   = sqlite3_column_int(stmt, 4);
        r->rssi_db = sqlite3_column_double(stmt, 5);
        r->snr_db  = sqlite3_column_double(stmt, 6);
        snprintf(r->raw_hex, sizeof(r->raw_hex), "%s", (const char *)raw_hex);
        ++n;
    }
    sqlite3_finalize(stmt);

    if (n == 0) { free(rows); rows = NULL; }
    if (out_n) *out_n = n;
    return rows;
}

bool db_sqlite_apply_region_recover(int64_t id, const char *json, size_t json_len)
{
    if (!g_db) return false;

    static const char *SQL = "UPDATE events SET json=?1 WHERE id=?2";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: region-recover update prepare failed: %s\n", sqlite3_errmsg(g_db));
        return false;
    }

    pthread_mutex_lock(&g_mu);
    if (json && json_len) sqlite3_bind_text(stmt, 1, json, (int)json_len, SQLITE_TRANSIENT);
    else                   sqlite3_bind_null(stmt, 1);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)id);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(g_db) > 0;
    if (!ok) fprintf(stderr, "db_sqlite: region-recover update failed for id=%lld: %s\n",
                     (long long)id, sqlite3_errmsg(g_db));
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_mu);
    return ok;
}

db_sqlite_telemetry_candidate_row_t *db_sqlite_query_telemetry_candidates(size_t *out_n)
{
    if (out_n) *out_n = 0;
    if (!g_db) return NULL;

    sqlite3_stmt *stmt = NULL;
    static const char *SQL =
        "SELECT id, ts, sf, cr, bw_hz, rssi_db, snr_db, raw_hex FROM events "
        "WHERE protocol='meshcore' AND payload_type=6 AND decrypted=1 "
        "AND telemetry_json IS NULL AND raw_hex IS NOT NULL";
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: telemetry-candidates query failed: %s\n", sqlite3_errmsg(g_db));
        return NULL;
    }

    size_t cap = 16, n = 0;
    db_sqlite_telemetry_candidate_row_t *rows = malloc(cap * sizeof(*rows));
    if (!rows) { sqlite3_finalize(stmt); return NULL; }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *raw_hex = sqlite3_column_text(stmt, 7);
        if (!raw_hex || !*raw_hex) continue;
        if (n == cap) {
            cap *= 2;
            db_sqlite_telemetry_candidate_row_t *nb = realloc(rows, cap * sizeof(*rows));
            if (!nb) break;
            rows = nb;
        }
        db_sqlite_telemetry_candidate_row_t *r = &rows[n];
        r->id      = sqlite3_column_int64(stmt, 0);
        r->ts      = sqlite3_column_double(stmt, 1);
        r->sf      = sqlite3_column_int(stmt, 2);
        r->cr      = sqlite3_column_int(stmt, 3);
        r->bw_hz   = sqlite3_column_int(stmt, 4);
        r->rssi_db = sqlite3_column_double(stmt, 5);
        r->snr_db  = sqlite3_column_double(stmt, 6);
        snprintf(r->raw_hex, sizeof(r->raw_hex), "%s", (const char *)raw_hex);
        ++n;
    }
    sqlite3_finalize(stmt);

    if (n == 0) { free(rows); rows = NULL; }
    if (out_n) *out_n = n;
    return rows;
}

bool db_sqlite_apply_telemetry_recover(int64_t id, const char *telemetry_json,
                                       const char *json, size_t json_len)
{
    if (!g_db) return false;

    static const char *SQL = "UPDATE events SET telemetry_json=?1, json=?2 WHERE id=?3";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "db_sqlite: telemetry-recover update prepare failed: %s\n", sqlite3_errmsg(g_db));
        return false;
    }

    pthread_mutex_lock(&g_mu);
    if (telemetry_json && telemetry_json[0]) sqlite3_bind_text(stmt, 1, telemetry_json, -1, SQLITE_TRANSIENT);
    else                                       sqlite3_bind_null(stmt, 1);
    if (json && json_len) sqlite3_bind_text(stmt, 2, json, (int)json_len, SQLITE_TRANSIENT);
    else                   sqlite3_bind_null(stmt, 2);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)id);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(g_db) > 0;
    if (!ok) fprintf(stderr, "db_sqlite: telemetry-recover update failed for id=%lld: %s\n",
                     (long long)id, sqlite3_errmsg(g_db));
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&g_mu);
    return ok;
}

#else /* !HAVE_SQLITE3 */

bool db_sqlite_init(const char *path)
{
    (void)path;
    fprintf(stderr, "db_sqlite: built without libsqlite3 -- --sqlite-db is a no-op\n");
    return false;
}

void db_sqlite_publish(const mesh_event_t *ev, const char *json_line, size_t json_len)
{
    (void)ev; (void)json_line; (void)json_len;
}

void db_sqlite_shutdown(void) { }

void node_db_persist_hook(uint32_t id, const char *long_name,
                          const char *short_name, uint32_t hw_model, uint32_t role)
{
    (void)id; (void)long_name; (void)short_name; (void)hw_model; (void)role;
}

bool db_sqlite_load_nodes(void) { return false; }
bool db_sqlite_replay_recent(double hours) { (void)hours; return false; }
char *db_sqlite_query_messages_json(uint32_t channel_hash, double before_ts, int limit)
{ (void)channel_hash; (void)before_ts; (void)limit; return NULL; }
char *db_sqlite_query_node_events_json(const char *node_id, double before_ts, int limit)
{ (void)node_id; (void)before_ts; (void)limit; return NULL; }
char *db_sqlite_query_telemetry_json(double before_ts, int limit)
{ (void)before_ts; (void)limit; return NULL; }
char *db_sqlite_query_nodes_json(void) { return NULL; }
char *db_sqlite_query_positions_json(void) { return NULL; }
char *db_sqlite_query_stats_by_type_json(double since_ts) { (void)since_ts; return NULL; }
char *db_sqlite_query_stats_by_channel_json(double since_ts) { (void)since_ts; return NULL; }
char *db_sqlite_query_stats_crc_json(double since_ts) { (void)since_ts; return NULL; }
char *db_sqlite_query_channel_names_json(void) { return NULL; }
size_t db_sqlite_query_known_channel_names(char out[][40], size_t max_out)
{ (void)out; (void)max_out; return 0; }
db_sqlite_undecrypted_row_t *db_sqlite_query_undecrypted_channel_rows(uint8_t channel_hash, size_t *out_n)
{ (void)channel_hash; if (out_n) *out_n = 0; return NULL; }
bool db_sqlite_apply_redecrypt(int64_t id, const char *channel_name,
                               const char *text, const char *json, size_t json_len)
{ (void)id; (void)channel_name; (void)text; (void)json; (void)json_len; return false; }
db_sqlite_crc_fail_row_t *db_sqlite_query_meshcore_crc_fail_rows(size_t *out_n)
{ if (out_n) *out_n = 0; return NULL; }
bool db_sqlite_apply_crc_recover(int64_t id, int crc_corrected_bits, bool decrypted,
                                  const char *channel_name, const char *text,
                                  const char *json, size_t json_len)
{ (void)id; (void)crc_corrected_bits; (void)decrypted; (void)channel_name;
  (void)text; (void)json; (void)json_len; return false; }
db_sqlite_region_scope_row_t *db_sqlite_query_region_scope_rows(size_t *out_n)
{ if (out_n) *out_n = 0; return NULL; }
bool db_sqlite_apply_region_recover(int64_t id, const char *json, size_t json_len)
{ (void)id; (void)json; (void)json_len; return false; }
db_sqlite_telemetry_candidate_row_t *db_sqlite_query_telemetry_candidates(size_t *out_n)
{ if (out_n) *out_n = 0; return NULL; }
bool db_sqlite_apply_telemetry_recover(int64_t id, const char *telemetry_json,
                                       const char *json, size_t json_len)
{ (void)id; (void)telemetry_json; (void)json; (void)json_len; return false; }

#endif /* HAVE_SQLITE3 */
