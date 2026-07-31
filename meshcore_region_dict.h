/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore region-scope (v1.10+ "Region Management")
 * name resolution.
 *
 * MeshCore's flood-scoping feature tags a packet with two opaque
 * uint16 "transport codes" (see meshcore_packet.h has_transport_codes/
 * transport_code1/transport_code2) instead of a human-readable region
 * name. transport_code1 is HMAC-SHA256(key, payload_type_byte ||
 * payload)[0:2], where key = SHA256(region_name)[0:16] for any
 * publicly-known ("hashtag-style") region name -- see upstream's
 * TransportKeyStore::getAutoKeyFor()/calcTransportCode(). Privately
 * keyed regions (upstream's hardware keystore path) are not
 * resolvable this way, same limitation as MeshCore's private
 * (non-hashtag) channels.
 *
 * Since the code is payload-dependent, it changes on every packet --
 * unlike a channel hash, there is no single reusable "region_hash ->
 * name" mapping, so resolving a code means trying every candidate
 * name in a wordlist (a couple hundred entries -- see
 * meshcore_region_dict.c). That's too expensive to run unconditionally
 * on the live decode hot path (regressed real-time decode throughput
 * in practice when it was tried), so this module splits resolution
 * into two tiers:
 *
 *   - meshcore_region_resolve_fast(): checks only names ALREADY
 *     confirmed on this network (a small, bounded cache) -- cheap,
 *     safe to call inline on every transport-coded packet.
 *   - meshcore_region_resolve_full(): the full wordlist scan --
 *     expensive, meant for offline/batch use (meshcore_region_
 *     recover.c's one-shot --region-recover pass) where there is no
 *     real-time constraint.
 *
 * The live decode path (meshcore_decoders.c) calls the fast tier
 * inline and, on a miss, hands the frame to
 * meshcore_region_dict_enqueue() for a background worker thread to
 * run the full scan on its own time -- exactly the same
 * enqueue-and-forget shape as the channel hashtag dictionary attack
 * (meshcore_hashtag_dict.c). A successful background match only
 * benefits *later* packets on that same region (via the fast-path
 * cache); it can't retroactively add a name to a message already
 * published/stored -- meshcore_region_recover.c's one-shot
 * --region-recover flag exists specifically to backfill those.
 */

#ifndef MESHCORE_REGION_DICT_H
#define MESHCORE_REGION_DICT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Cheap, cache-only lookup: tries only region names already confirmed
 * on this network (via meshcore_region_resolve_full() or the
 * background worker started by meshcore_region_dict_enqueue()). Safe
 * to call inline on the live decode path -- bounded by a small fixed
 * cache size, no wordlist scan. On a match, writes the resolved name
 * (without a leading '#') into name_out and returns true; otherwise
 * returns false and leaves name_out untouched. */
bool meshcore_region_resolve_fast(uint8_t payload_type, const uint8_t *payload,
                                  size_t payload_len, uint16_t code,
                                  char *name_out, size_t name_cap);

/* Full dictionary attack: tries every candidate name in the built-in
 * wordlist (public region names + the generated fr-<dept>/fr-<region>
 * set), with case variants and an optional leading '#'. Expensive
 * (a couple hundred HMAC-SHA256 attempts worst case) -- call this
 * directly only from offline/batch contexts with no real-time
 * constraint (meshcore_region_recover.c). On a match, also adds the
 * name to the fast-path cache, and writes the resolved name into
 * name_out. */
bool meshcore_region_resolve_full(uint8_t payload_type, const uint8_t *payload,
                                  size_t payload_len, uint16_t code,
                                  char *name_out, size_t name_cap);

/* Queues a transport-coded frame for the full dictionary scan on a
 * background worker thread (started lazily on first call). Fire-and-
 * forget: no result is returned to the caller, and a match only
 * populates the fast-path cache for future lookups -- it does not
 * (cannot) patch whatever event this specific frame already produced.
 * Bounded queue; drops the oldest pending frame if full, same
 * trade-off as meshcore_hashtag_dict_enqueue(). No-op if payload_len
 * is 0. */
void meshcore_region_dict_enqueue(uint8_t payload_type, const uint8_t *payload,
                                  size_t payload_len, uint16_t code);

#endif /* MESHCORE_REGION_DICT_H */
