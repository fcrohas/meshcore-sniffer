/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive region-scope resolution of
 * historically-stored MeshCore rows. Companion to crc_recover.c /
 * meshcore_redecrypt.c -- this retries meshcore_region_resolve_full()
 * (meshcore_region_dict.c) against every already-captured row that
 * carries a region scope, useful after the wordlist grows (e.g. the
 * fr-<dept>/fr-<region> set) past what was available when the row was
 * first captured.
 */

#ifndef MESHCORE_REGION_RECOVER_H
#define MESHCORE_REGION_RECOVER_H

#include "meshcore.h"

#include <stddef.h>

typedef struct {
    size_t total_candidates; /* transport-coded MeshCore rows examined */
    size_t resolved;         /* now have a region_name that either was missing
                               * before, or is being re-confirmed/updated */
    size_t decode_failed;    /* re-parse/re-decode of the stored raw_hex failed
                               * (malformed header etc.) -- shouldn't normally happen */
} region_recover_stats_t;

/* Re-attempts meshcore_region_resolve() (via a full re-decode, which
 * already calls it internally) against every stored MeshCore row
 * whose route_type carries transport codes, and persists any row
 * whose resolved region_name changed via
 * db_sqlite_apply_region_recover(). No-op (returns 0) if
 * --sqlite-db wasn't configured or nothing matches. Returns the
 * total number of rows updated; `stats`, if non-NULL, receives the
 * full breakdown for reporting. */
int meshcore_region_recover_scan(const meshcore_channelset_t *channels, region_recover_stats_t *stats);

#endif /* MESHCORE_REGION_RECOVER_H */
