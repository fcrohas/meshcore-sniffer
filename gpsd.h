/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: gpsd client.
 *
 * Connects to gpsd over TCP (default localhost:2947), subscribes to
 * JSON-mode TPV reports, exposes the latest 2D/3D fix via a thread-
 * safe getter. The feed serialiser tags every emitted JSON event with
 * station_lat / station_lon / station_alt_m when a recent fix is
 * available; a multi-station deployment can then group same-packet
 * observations by station and time.
 */

#ifndef GPSD_H
#define GPSD_H

#include <stdbool.h>

/* Start the background thread. `endpoint` is "host:port" or NULL for
 * "localhost:2947". Returns true on success. Reconnects on failure. */
bool gpsd_init(const char *endpoint);

/* Stop the background thread + join. */
void gpsd_shutdown(void);

/* Return true and fill out_* iff a 2D-or-better fix has been seen. The
 * caller should consult out_age_s and skip the fix if it's stale; we
 * don't filter here so a deployment with intermittent GPS still gets
 * the most-recent value plus an honest age. */
bool gpsd_get_fix(double *out_lat, double *out_lon,
                  double *out_alt_m, double *out_age_s);

#endif /* GPSD_H */
