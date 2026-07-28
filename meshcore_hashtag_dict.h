/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore hashtag-channel dictionary attack.
 *
 * When --meshcore-hashtag-wordlist=PATH is set, every undecrypted
 * GRP_TXT/GRP_DATA frame is queued for a background thread that tries
 * each wordlist entry (plus case variants, see
 * meshcore_name_case_variants()) as a candidate hashtag-channel name.
 * On a successful decode the discovered channel is added to the
 * runtime meshcore_channelset_t (so subsequent frames on that channel
 * decrypt normally) and an MC_CHANNEL_DISCOVERED event is emitted.
 *
 * This only applies to hashtag channels (secret derived from a
 * human-typed name -- see meshcore_channel_hashtag_secret()); private
 * channels use a real random PSK and are not in scope for a wordlist
 * attack. See recover/meshcore-recover.c for the offline, single-frame
 * equivalent of this same attack.
 *
 * Wordlist format: one candidate channel name per line. Lines starting
 * with '#' are comments, blank lines are skipped.
 */

#ifndef MESHCORE_HASHTAG_DICT_H
#define MESHCORE_HASHTAG_DICT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool meshcore_hashtag_dict_init(const char *wordlist_path);
void meshcore_hashtag_dict_shutdown(void);

/* Push an undecrypted GRP_TXT/GRP_DATA frame for background-thread
 * analysis. Caller still holds the source bytes; the queue copies
 * what it needs. No-op unless meshcore_hashtag_dict_init() succeeded. */
void meshcore_hashtag_dict_enqueue(const uint8_t *frame_bytes, size_t frame_len,
                                   float rssi_db, float snr_db,
                                   int sf, int cr, int bw_hz);

#endif /* MESHCORE_HASHTAG_DICT_H */
