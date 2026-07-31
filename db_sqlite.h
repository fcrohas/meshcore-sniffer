/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: SQLite persistence sink.
 *
 * Long-term structured storage alongside archive.c's gzipped JSONL.
 * Every event that reaches feed_publish_event() (both protocols,
 * decrypted or not, CRC-pass/fail/corrected) gets one row: structured
 * columns for the fields an operator would filter/sort/join on (time,
 * protocol, node id, position, channel, CRC provenance...), plus the
 * exact serialized JSON line for anything not broken out into its own
 * column. Compiled to a no-op when libsqlite3 isn't found at configure
 * time (see CMakeLists.txt HAVE_SQLITE3).
 */

#ifndef DB_SQLITE_H
#define DB_SQLITE_H

#include "mesh_packet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Open (creating if absent) the SQLite DB at path and create the
 * events table/indexes if missing. Safe to call once at startup;
 * returns false (and logs to stderr) on any failure, in which case
 * db_sqlite_publish() is a no-op. */
bool db_sqlite_init(const char *path);

/* Insert one row for ev. json_line/json_len is the exact bytes
 * feed_publish_event() already serialized (avoids re-serializing).
 * No-op if db_sqlite_init() was never called or failed. */
void db_sqlite_publish(const mesh_event_t *ev, const char *json_line, size_t json_len);

void db_sqlite_shutdown(void);

/* Cross-restart recovery: call once at startup, after db_sqlite_init()
 * succeeds, so the process doesn't start with a blank node list / SSE
 * dashboard on a fresh restart.
 *
 * db_sqlite_load_nodes() reloads every row of the `nodes` table (kept
 * up to date automatically via node_db.c's node_db_persist_hook())
 * back into the in-memory node_db so path-drawing/labeling has the
 * full known node set immediately, not just nodes seen since restart.
 * Uncapped -- node_db's own 1024-entry limit is the only bound.
 *
 * db_sqlite_replay_recent(hours) replays the `json` column of every
 * `events` row newer than `hours` ago straight into web_publish_line(),
 * seeding the SSE history ring the exact same way live traffic does --
 * so the first browser connection after a restart sees recent
 * conversation history and debug frames instead of a blank dashboard.
 * Bounded by the ring's own 1024-slot cap regardless of how many rows
 * match the time window. No-op (returns false) if hours <= 0 or
 * db_sqlite_init() wasn't called/failed. */
bool db_sqlite_load_nodes(void);
bool db_sqlite_replay_recent(double hours);

/* On-demand chat/channel history for the dashboard's "load older
 * messages" scroll-back, independent of the SSE ring's 1024-slot cap:
 * queries the `events` table directly (rows with text IS NOT NULL,
 * i.e. chat/text frames) for one channel_hash, newest first.
 *
 * before_ts <= 0 means "no upper bound" (start from the newest row);
 * otherwise only rows with ts < before_ts are returned, so the caller
 * pages backward in time by passing the oldest ts it already has.
 * limit is clamped by the caller; this function trusts its argument.
 *
 * Returns a malloc'd, NUL-terminated JSON string of the form
 *   {"messages":[<json>,...],"more":bool}
 * where each array element is the verbatim stored `json` column value
 * (same shape as an SSE event line) -- the caller reuses its existing
 * per-event JS parsing, no server-side re-mapping needed. "more" is
 * true iff there may be additional, older rows beyond the last one
 * returned. Caller must free() the result.
 *
 * Returns NULL if db_sqlite_init() was never called/failed, or on a
 * genuine DB/allocation error. A channel with zero matching rows still
 * returns a valid {"messages":[],"more":false}, not NULL. */
char *db_sqlite_query_messages_json(uint32_t channel_hash, double before_ts, int limit);

/* On-demand per-node history for the repeater/node drawer, same
 * rationale as db_sqlite_query_messages_json() above: the frontend's
 * nodes[id]._hist (messages/positions/SNR/channels-seen) is built
 * only from live SSE traffic in memory, capped and reset on every
 * reconnect/reload -- clicking an older or quiet repeater otherwise
 * shows a near-empty drawer even though the DB has plenty of history.
 * Queries the `events` table directly by node_id (see bind_node_id()
 * in this file), newest first.
 *
 * before_ts <= 0 means "no upper bound" (start from the newest row);
 * otherwise only rows with ts < before_ts are returned. limit is
 * clamped by the caller; this function trusts its argument.
 *
 * Returns a malloc'd, NUL-terminated JSON string of the form
 *   {"events":[<json>,...],"more":bool}
 * where each array element is the verbatim stored `json` column value
 * (same shape as an SSE event line) -- the caller builds the drawer's
 * msgs/positions/snr/channels rings from these the same way it
 * already processes live events, just in bulk. Caller must free()
 * the result.
 *
 * Returns NULL if db_sqlite_init() was never called/failed, or on a
 * genuine DB/allocation error. A node_id with zero matching rows
 * still returns a valid {"events":[],"more":false}, not NULL. */
char *db_sqlite_query_node_events_json(const char *node_id, double before_ts, int limit);

/* On-demand telemetry history for the Telemetry tab, same paging
 * shape as db_sqlite_query_messages_json()/_node_events_json() above.
 * Queries the `events` table for rows with telemetry_json IS NOT NULL
 * (GRP_DATA frames whose blob decoded as CayenneLPP -- see
 * meshcore_lpp.c), newest first. MeshCore GRP_TXT/GRP_DATA carries no
 * sender identity (see feed_meshcore_json.c's own comment on this),
 * so there is no node_id filter here -- only channel-scoped and
 * global views make sense.
 *
 * before_ts <= 0 means "no upper bound"; limit is clamped by the
 * caller.
 *
 * Returns a malloc'd, NUL-terminated JSON string of the form
 *   {"telemetry":[<json>,...],"more":bool}
 * where each array element is the verbatim stored `json` column value
 * (same shape as an SSE event line, including its own "telemetry"
 * field -- see feed_meshcore_json.c). Caller must free() the result.
 *
 * Returns NULL if db_sqlite_init() was never called/failed, or on a
 * genuine DB/allocation error. Zero matching rows still returns a
 * valid {"telemetry":[],"more":false}, not NULL. */
char *db_sqlite_query_telemetry_json(double before_ts, int limit);

/* Dashboard bootstrap-on-load, so a browser tab opened after a sniffer
 * restart isn't blank -- node_db (and the frontend's live-traffic-only
 * `nodes`/`markers` state) never persists to disk on their own, but the
 * `nodes` and `events` SQL tables do, so these read straight from them.
 *
 * db_sqlite_query_nodes_json() returns every row of the `nodes` table:
 *   [{"id":"!xxxxxxxx","long_name":..,"short_name":..,"hw_model":N,"role":N,"last_seen":ts}, ...]
 * "id" is pre-formatted "!%08x" to match the `from` field already used
 * as the frontend's `nodes{}`/`markers{}` object keys (see bind_node_id()
 * above and es.onmessage's `const id = p.from;` in web.c) -- no
 * client-side reformatting of a possibly-huge integer needed.
 *
 * db_sqlite_query_positions_json() returns each node's last known
 * position (by max ts) among all events that carried lat/lon:
 *   [{"node_id":"!xxxxxxxx","lat":..,"lon":..,"ts":..}, ...]
 *
 * Both return a malloc'd, NUL-terminated JSON array string (caller
 * frees); NULL only if db_sqlite_init() was never called/failed. An
 * empty result is a valid "[]", not NULL. */
char *db_sqlite_query_nodes_json(void);
char *db_sqlite_query_positions_json(void);

/* Statistics tab (MeshCore-only, protocol='meshcore'). since_ts is the
 * caller-computed lower bound (current time minus the requested
 * window); rows older than since_ts are excluded. All three return a
 * malloc'd JSON fragment (caller frees); NULL only if db_sqlite_init()
 * was never called/failed -- an empty result set is a valid empty
 * array/zeroed object, not NULL.
 *
 * db_sqlite_query_stats_by_type_json() / _by_channel_json(): GROUP BY
 * aggregate, ORDER BY count DESC, folded server-side to at most 8
 * entries -- the top 7 by count, plus (only if more than 7 distinct
 * groups exist) one trailing {"label":"Other","count":N} aggregate of
 * the remainder. Channel rows also carry "channel_hash" (int) and, when
 * known, "channel_name" (string) -- the key is OMITTED from the JSON
 * object (not sent as JSON null) when the channel hasn't been named
 * yet, so the frontend's existing `p.channel_name || ('0x'+hash...)`
 * fallback idiom (already used at several call sites in web.c) works
 * unmodified. The "Other" row for either endpoint omits channel_hash/
 * channel_name entirely, distinguishing it structurally from a real
 * group rather than via a magic sentinel value.
 *
 * db_sqlite_query_stats_crc_json(): single-row aggregate (no GROUP BY),
 * three mutually exclusive buckets matching the dashboard's existing
 * per-message CRC badge classification (web.c, msgCrcBadge()-style
 * logic): crc_ok=1,crc_corrected=0 -> "ok"; crc_ok=1,crc_corrected=1 ->
 * "corrected"; crc_ok=0 -> "failed". Rows with crc_ok IS NULL (no CRC
 * to evaluate at all) are excluded from all three buckets. */
char *db_sqlite_query_stats_by_type_json(double since_ts);
char *db_sqlite_query_stats_by_channel_json(double since_ts);
char *db_sqlite_query_stats_crc_json(double since_ts);

/* Dashboard bootstrap-on-load for the Channels tab, mirroring
 * db_sqlite_query_nodes_json() above: the frontend's `channels{}` state
 * is live-traffic-only in memory (built up from SSE packet/discovery
 * events), so a browser tab refresh loses every channel_hash->name
 * mapping until fresh traffic happens to arrive on each channel again
 * -- even though the server/DB already knows it. Returns the latest
 * known name for every channel_hash that has ever carried one:
 *   [{"channel_hash":N,"channel_name":".."}, ...]
 * (hashes with no name ever recorded are omitted -- nothing useful to
 * bootstrap for those; the frontend already falls back to the raw hex
 * hash). Malloc'd, NUL-terminated JSON array string (caller frees);
 * NULL only if db_sqlite_init() was never called/failed. */
char *db_sqlite_query_channel_names_json(void);

/* Retroactive re-decrypt support (see meshcore_redecrypt.c): a channel
 * whose secret becomes known *after* some of its traffic was already
 * captured -- via a manual dashboard add or the background hashtag-
 * dictionary attack -- only decrypts frames from that point forward
 * unless something goes back and retries every already-stored,
 * still-undecrypted row on that channel_hash. These two functions are
 * the generic (protocol-decode-free) DB half of that: db_sqlite.c
 * itself has no MeshCore crypto/decode knowledge, so the actual
 * parse-and-decrypt attempt happens in meshcore_redecrypt.c, which
 * calls these to fetch candidates and persist any hits. */

typedef struct {
    int64_t id;
    double  ts;
    int     sf, cr, bw_hz;
    double  rssi_db, snr_db;
    char    raw_hex[513]; /* matches mesh_event_t.raw_hex (mesh_packet.h) */
} db_sqlite_undecrypted_row_t;

/* Every still-undecrypted (decrypted=0) MeshCore GRP_TXT/GRP_DATA row
 * for channel_hash, as a malloc'd array of *out_n entries (caller
 * frees). Rows with no raw_hex (shouldn't happen for MeshCore, but
 * guarded) are skipped. NULL and *out_n=0 if db_sqlite_init() wasn't
 * called/failed, or nothing matches. */
db_sqlite_undecrypted_row_t *db_sqlite_query_undecrypted_channel_rows(uint8_t channel_hash, size_t *out_n);

/* Persist a successful retroactive decrypt of row `id`: flips
 * decrypted=1, sets channel_name/text, and overwrites the stored json
 * column with newly re-serialized JSON (caller re-serializes via
 * feed_serialize_event_meshcore() with ts_override set to the row's
 * original ts, so the regenerated JSON's own "ts" field stays
 * consistent with this row's ts column instead of jumping to "now").
 * Returns false if db_sqlite_init() wasn't called/failed, or the
 * UPDATE affected no row. */
bool db_sqlite_apply_redecrypt(int64_t id, const char *channel_name,
                               const char *text, const char *json, size_t json_len);

#endif /* DB_SQLITE_H */
