/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive CRC recovery of historically-stored,
 * still-failing MeshCore rows. Companion to meshcore_redecrypt.c (which
 * retries decrypt once a channel key becomes known) -- this retries the
 * CRC bruteforce tiers themselves, useful after upgrading to a build
 * with a stronger recovery tier (e.g. the 2-bit fallback) than the one
 * that originally captured the row.
 */

#ifndef CRC_RECOVER_H
#define CRC_RECOVER_H

#include "meshcore.h"

#include <stddef.h>

typedef struct {
    size_t total_candidates;  /* crc_ok=0 MeshCore rows examined */
    size_t fixed_1bit;        /* recovered, single-bit (trusted unconditionally
                                * unless the payload type has an authentication
                                * mechanism available, in which case it must
                                * also pass -- see mesh_event_crc2bit_trusted()) */
    size_t fixed_2bit;        /* recovered, two-bit AND independently authenticated */
    size_t untrusted;         /* a CRC match was found (either tier) but failed
                                * the authentication gate where one applied --
                                * left as crc_ok=0, not persisted */
    size_t decode_failed;     /* CRC now matches but re-decode/parse itself
                                * failed (malformed header etc.) -- shouldn't
                                * normally happen */
} crc_recover_stats_t;

/* Re-attempts the CRC bruteforce tiers (lora_crc_bruteforce_correct,
 * then lora_crc_bruteforce_correct_2bit) against every still-failing
 * (crc_ok=0) MeshCore row's stored raw_hex, re-decodes any that now
 * pass, gates two-bit fixes on mesh_event_crc2bit_trusted() against
 * `channels` (the channelset to attempt GRP_TXT/GRP_DATA decrypt
 * with), and persists successes via db_sqlite_apply_crc_recover().
 * No-op (returns 0) if --sqlite-db wasn't configured or nothing
 * matches. Returns the total number of rows fixed (1-bit + 2-bit);
 * `stats`, if non-NULL, receives the full breakdown for reporting. */
int meshcore_crc_recover_scan(const meshcore_channelset_t *channels, crc_recover_stats_t *stats);

#endif /* CRC_RECOVER_H */
