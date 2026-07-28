/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: in-memory node-info cache.
 *
 * Tiny map from from-node id (uint32) to last-seen long/short name and
 * hardware-model. Populated by NODEINFO packets, queried by POSITION
 * packets so CoT republish can label markers with a real callsign.
 *
 */

#ifndef NODE_DB_H
#define NODE_DB_H

#include <stdbool.h>
#include <stdint.h>

#define NODE_DB_LONG_NAME 64
#define NODE_DB_SHORT_NAME 8

typedef struct node_record {
    uint32_t id;
    char     long_name[NODE_DB_LONG_NAME];
    char     short_name[NODE_DB_SHORT_NAME];
    uint32_t hw_model;
    uint32_t role;
} node_record_t;

void node_db_remember(uint32_t id, const char *long_name,
                      const char *short_name, uint32_t hw_model, uint32_t role);

/* Returns true and fills *out if known; returns false otherwise. */
bool node_db_lookup(uint32_t id, node_record_t *out);

/* Pluggable persistence backend, called by node_db_remember() on
 * every learned/updated node so a restart can reload the table
 * instead of starting blank. Same (id, long_name, short_name,
 * hw_model, role) shape and "only overwrite non-empty/non-zero
 * fields" semantics as node_db_remember() itself.
 *
 * Real implementation lives in db_sqlite.c (upserts into a `nodes`
 * table, no-op if --sqlite-db isn't configured); node_db_persist_stub.c
 * provides a plain no-op for binaries that link node_db.c but not
 * db_sqlite.c (mirrors meshcore_hashtag_dict_stub.c's role for
 * meshcore_hashtag_dict_enqueue()). Exactly one of the two must be
 * linked into any binary that links node_db.c. */
void node_db_persist_hook(uint32_t id, const char *long_name,
                          const char *short_name, uint32_t hw_model, uint32_t role);

#endif
