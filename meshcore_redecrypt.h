/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: retroactive re-decrypt of historically-stored
 * MeshCore GRP_TXT/GRP_DATA rows once their channel secret becomes
 * known after the fact (manual dashboard add, or the background
 * hashtag-dictionary attack). Without this, a channel added/cracked
 * after some of its traffic was already captured only decrypts
 * *future* frames -- every already-logged message on that channel
 * stays permanently encrypted in the dashboard's chat history and the
 * SQLite events table, even though the now-known secret would
 * decrypt them just as well as a live frame.
 */

#ifndef MESHCORE_REDECRYPT_H
#define MESHCORE_REDECRYPT_H

#include "meshcore.h"

/* Re-attempts decrypt on every already-stored, still-undecrypted
 * GRP_TXT/GRP_DATA row for channel_hash (via db_sqlite's events
 * table) against `channels` -- the live channelset, expected to now
 * contain the just-learned secret for that hash -- and persists any
 * that succeed. No-op (returns 0) if --sqlite-db wasn't configured or
 * nothing matches. Returns the number of rows fixed. */
int meshcore_redecrypt_channel(uint8_t channel_hash, const meshcore_channelset_t *channels);

#endif /* MESHCORE_REDECRYPT_H */
