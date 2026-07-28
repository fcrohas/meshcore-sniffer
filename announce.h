/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: fusion auto-announce.
 *
 * When --announce-to=URL is set, a background thread periodically
 * POSTs this sensor's registry entry to the fusion's /api/sensors
 * endpoint. The fusion deduplicates by name and updates the entry
 * (zmq endpoint, api endpoint, position) on each POST so the
 * dashboard shows live sensors without manual entry.
 */

#ifndef ANNOUNCE_H
#define ANNOUNCE_H

#include <stdbool.h>

/* Start the background announce loop. `url` is the full POST URL
 * (e.g. http://fusion.local:9000/api/sensors). Returns false on
 * malformed URL; true otherwise (failures during POST are logged
 * and retried). */
bool announce_init(const char *url);

/* Stop the announce thread + join. */
void announce_shutdown(void);

#endif /* ANNOUNCE_H */
