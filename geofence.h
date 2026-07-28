/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: geofence alerts.
 *
 * When --geofence=PATH is set, polygons are loaded from a simple
 * INI-style file:
 *
 *     # any line starting with # is a comment
 *     [polygon-name]
 *     lat, lon
 *     lat, lon
 *     lat, lon   ; first vertex is implicitly closed back to last
 *
 *     [another-polygon]
 *     lat, lon
 *     ...
 *
 * Every POSITION_APP event runs through point-in-polygon tests
 * against each known polygon. State transitions per (node_id,
 * polygon) emit GEOFENCE_ENTRY / GEOFENCE_EXIT JSON events on the
 * regular feed channel.
 */

#ifndef GEOFENCE_H
#define GEOFENCE_H

#include <stdbool.h>
#include <stdint.h>

bool geofence_init(const char *path);
void geofence_shutdown(void);

/* Called from feed.c whenever a POSITION_APP event decodes. node_id
 * is the !XXXXXXXX numeric form. Emits JSON events on entry/exit. */
void geofence_check(uint32_t node_id, double lat, double lon);

#endif /* GEOFENCE_H */
