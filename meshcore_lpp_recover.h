/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive telemetry (CayenneLPP-over-GRP_DATA)
 * resolution of historically-stored MeshCore rows. Companion to
 * crc_recover.c / meshcore_redecrypt.c / meshcore_region_recover.c --
 * this retries meshcore_decode_grp_data()'s LPP decode (added after
 * some GRP_DATA rows were already captured and decrypted) against
 * every already-decrypted row that never got a telemetry_json value.
 *
 * Unlike meshcore_region_recover.c, this genuinely needs to
 * re-decrypt (the LPP blob only exists inside the AES-128-ECB+HMAC
 * plaintext), so the supplied channelset must already hold the right
 * channel secret for a row to be recoverable -- see
 * meshcore_lpp_recover_scan()'s doc comment.
 */

#ifndef MESHCORE_LPP_RECOVER_H
#define MESHCORE_LPP_RECOVER_H

#include "meshcore.h"

#include <stddef.h>

typedef struct {
    size_t total_candidates; /* already-decrypted GRP_DATA rows examined */
    size_t resolved;         /* now have a telemetry_json that was previously unset */
    size_t decode_failed;    /* re-parse/re-decrypt of the stored raw_hex failed
                               * (channel not loaded, malformed header, etc.) */
} telemetry_recover_stats_t;

/* Re-attempts meshcore_decode_grp_data()'s CayenneLPP decode (via a
 * full re-decode, which already calls it internally) against every
 * stored, already-decrypted MeshCore GRP_DATA row whose
 * telemetry_json is unset, and persists any row that now resolves
 * via db_sqlite_apply_telemetry_recover(). `channels` must already
 * contain the channel secret each candidate row was originally
 * decrypted with (see build_meshcore_channels() plus the DB-restored
 * known-channel-names step main.c's --telemetry-recover path adds on
 * top of it) -- a row whose channel isn't loaded fails to re-decrypt
 * and is skipped, same limitation crc_recover.c/
 * meshcore_region_recover.c already have. No-op (returns 0) if
 * --sqlite-db wasn't configured or nothing matches. Returns the
 * total number of rows updated; `stats`, if non-NULL, receives the
 * full breakdown for reporting. */
int meshcore_lpp_recover_scan(const meshcore_channelset_t *channels, telemetry_recover_stats_t *stats);

#endif /* MESHCORE_LPP_RECOVER_H */
