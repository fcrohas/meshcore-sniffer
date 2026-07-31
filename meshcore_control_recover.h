/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive CONTROL node-discovery resolution of
 * historically-stored MeshCore rows. Companion to crc_recover.c /
 * meshcore_redecrypt.c / meshcore_region_recover.c / meshcore_lpp_
 * recover.c -- this retries meshcore_decoders.c's decode_control()
 * (added after some CONTROL rows were already captured and stored
 * with decrypted=0 via the old decode_unknown() fallback) against
 * every already-stored CONTROL row.
 *
 * Unlike the other _recover tools, this needs no channel keys or
 * wordlist: CONTROL's NODE_DISCOVER_REQ/_RESP convention (see
 * MC_CTL_TYPE_NODE_DISCOVER_REQ in meshcore.h) is fully cleartext
 * when it matches at all, so a plain re-parse of raw_hex is enough.
 */

#ifndef MESHCORE_CONTROL_RECOVER_H
#define MESHCORE_CONTROL_RECOVER_H

#include <stddef.h>

typedef struct {
    size_t total_candidates; /* decrypted=0 CONTROL rows examined */
    size_t resolved;         /* now match NODE_DISCOVER_REQ/_RESP */
    size_t decode_failed;    /* re-parse of the stored raw_hex failed
                               * (malformed header etc.) -- shouldn't
                               * normally happen */
} control_recover_stats_t;

/* Re-attempts decode_control() (via a full re-decode, which already
 * calls it internally) against every stored CONTROL row still marked
 * decrypted=0, and persists any row that now matches the
 * NODE_DISCOVER_REQ/_RESP convention via
 * db_sqlite_apply_control_recover(). No channelset needed -- CONTROL
 * carries no encryption of its own. No-op (returns 0) if --sqlite-db
 * wasn't configured or nothing matches. Returns the total number of
 * rows updated; `stats`, if non-NULL, receives the full breakdown for
 * reporting. */
int meshcore_control_recover_scan(control_recover_stats_t *stats);

#endif /* MESHCORE_CONTROL_RECOVER_H */
