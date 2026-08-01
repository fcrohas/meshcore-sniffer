/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: JSON serialization of MeshCore mesh_event_t
 * events into the LetsMesh/MeshRank "observer" schema (flat
 * origin/origin_id/timestamp/type/direction/... object, as produced
 * by the reference meshcoretomqtt bridge and consumed by
 * analyzer.letsmesh.net / meshrank.net). Split out like
 * feed_meshcore_json.c so it's unit testable standalone.
 */

#ifndef FEED_MESHCORE_OBSERVER_H
#define FEED_MESHCORE_OBSERVER_H

#include "jw.h"
#include "mesh_packet.h"

/* Serialize a MeshCore mesh_event_t (ev->is_meshcore == true) to `j`
 * in the observer schema. `origin` is a human-readable label for this
 * observer (opt_station_id, or "observer" if unset); `origin_id` is
 * the stable identity from --mqtt-observer-id.
 *
 * Deliberately does NOT emit a "hash" field: real MeshCore firmware's
 * packet hash is SHA256(payload_type [+ path_len if TRACE] + payload)
 * computed over the on-air payload bytes (see Packet::calculatePacketHash
 * in the firmware's src/Packet.cpp), but by the time an event reaches
 * this serializer its payload buffer has already been decrypted in
 * place for decodable types (see feed_meshcore_json.c's per-port
 * switch), so recomputing that hash here would silently produce a
 * value that doesn't match what real repeaters report for the same
 * packet -- worse than omitting it, since LetsMesh/MeshRank correlate
 * sightings across observers by that hash. Revisit if/when the raw
 * pre-decrypt payload bytes are threaded through separately. */
void feed_serialize_event_observer(jw_t *j, const mesh_event_t *ev,
                                   const char *origin, const char *origin_id);

#endif /* FEED_MESHCORE_OBSERVER_H */
