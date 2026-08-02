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
 * dependency on options.c and can be linked standalone in tests.
 *
 * `ts_override`: 0 (the common case) stamps "ts" with the current
 * wall-clock time, matching live capture. A positive value is used
 * verbatim instead -- for meshcore_redecrypt.c re-serializing a
 * historically-stored row whose original capture time must be
 * preserved (not the time the retroactive decrypt happens to run).
 *
 * `have_station`/`station_lat`/`station_lon`/`station_alt_m`: this
 * station's own position (from --gpsd or --rx-lat/--rx-lon), same
 * computation feed.c's Meshtastic path already does -- passed in
 * rather than read from gpsd.h/options.h globals for the same
 * standalone-testability reason as `station_id` above. All five
 * retroactive-recover callers (meshcore_redecrypt.c, crc_recover.c,
 * meshcore_region_recover.c, meshcore_lpp_recover.c,
 * meshcore_control_recover.c) correctly pass have_station=false:
 * they're re-serializing a HISTORICAL row, and this process's
 * current station position has no bearing on where the station was
 * when that row was originally captured. station_alt_m is only
 * emitted when nonzero, matching feed.c's own convention. */
void feed_serialize_event_meshcore(jw_t *j, const mesh_event_t *ev,
                                   const char *station_id, double ts_override,
                                   bool have_station, double station_lat,
                                   double station_lon, double station_alt_m);

#endif /* FEED_MESHCORE_JSON_H */
