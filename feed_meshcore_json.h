/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: JSON serialization of MeshCore mesh_event_t
 * events (split out of feed.c for unit testability -- see
 * feed_meshcore_json.c for the rationale).
 */

#ifndef FEED_MESHCORE_JSON_H
#define FEED_MESHCORE_JSON_H

#include "jw.h"
#include "mesh_packet.h"

/* Serialize a MeshCore mesh_event_t (ev->is_meshcore == true) to `j`.
 * `station_id` is opt_station_id from options.h (or NULL); passed as
 * a parameter rather than read from a global so this file has no
 * dependency on options.c and can be linked standalone in tests. */
void feed_serialize_event_meshcore(jw_t *j, const mesh_event_t *ev,
                                   const char *station_id);

#endif /* FEED_MESHCORE_JSON_H */
