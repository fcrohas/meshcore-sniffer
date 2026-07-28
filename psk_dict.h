/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: PSK dictionary attack.
 *
 * When --psk-wordlist=PATH is set, every undecrypted frame is queued
 * for a background thread that tries each wordlist entry as a candidate
 * PSK. On a successful decode the discovered key is added to the
 * runtime keyset (so subsequent frames on that channel decrypt
 * normally) and a PSK_DISCOVERED event is emitted.
 *
 * Wordlist format: one PSK spec per line. Same grammar as --keys:
 *   default | simple0..simple10 | hex:HHHH... | base64:....
 * Optional 'Name=' prefix (not significant for the attack -- the
 * channel name is recovered separately).
 *
 * Lines starting with '#' are comments, blank lines are skipped.
 */

#ifndef PSK_DICT_H
#define PSK_DICT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool psk_dict_init(const char *wordlist_path);
void psk_dict_shutdown(void);

/* Push an undecrypted frame for background-thread analysis. Caller
 * still holds the source bytes; psk_dict copies what it needs. */
void psk_dict_enqueue(const uint8_t *frame_bytes, size_t frame_len,
                      float rssi_db, float snr_db,
                      int sf, int cr, int bw_hz);

#endif /* PSK_DICT_H */
