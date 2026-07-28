/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * No-op stub for meshcore_hashtag_dict_enqueue(), the hook
 * meshcore_decoders.c fires on undecrypted GRP_TXT/GRP_DATA frames in
 * the live sniffer. Linked by binaries that pull in meshcore_decoders.c
 * but don't want the live background dictionary-attack thread (unit
 * tests, and recover/meshcore-recover.c which does its own explicit
 * offline attack instead) -- avoids dragging in the real module's
 * dependency on app_get_meshcore_channels()/web_publish_line()/
 * webhook_publish(), which only the main sniffer binary provides.
 * Mirrors recover/stubs.c's psk_dict_enqueue() stub for the same reason.
 */

#include <stddef.h>
#include <stdint.h>

void meshcore_hashtag_dict_enqueue(const uint8_t *frame_bytes, size_t frame_len,
                                   float rssi_db, float snr_db,
                                   int sf, int cr, int bw_hz)
{
    (void)frame_bytes; (void)frame_len; (void)rssi_db; (void)snr_db;
    (void)sf; (void)cr; (void)bw_hz;
}
