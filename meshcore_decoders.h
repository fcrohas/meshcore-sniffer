/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore per-payload-type decoders + the
 * meshcore_packet_decode_with_radio() entry point (MeshCore analogue
 * of mesh_packet_decode_with_radio()).
 */

#ifndef MESHCORE_DECODERS_H
#define MESHCORE_DECODERS_H

#include "meshcore.h"
#include "meshcore_packet.h"
#include "mesh_packet.h"   /* mesh_event_t / mesh_event_cb_t reused */

/* One-shot decode of a raw MeshCore LoRa frame. Mirrors
 * mesh_packet_decode_with_radio()'s signature but takes a
 * meshcore_channelset_t instead of a Meshtastic keyset_t. Returns 0
 * if an event was emitted, -1 if the frame is malformed. */
int meshcore_packet_decode_with_radio(const uint8_t *frame, size_t frame_len,
                                      float rssi_db, float snr_db,
                                      int sf, int cr, int bw_hz,
                                      const meshcore_channelset_t *channels,
                                      mesh_event_cb_t cb, void *user);

/* Individual decoders, exposed for unit testing. All fill in the
 * mc_* fields of an already-zeroed mesh_event_t; the caller is
 * responsible for header/route/payload_type/hash bookkeeping shared
 * across payload types. */
bool meshcore_decode_advert(const meshcore_packet_t *pkt, mesh_event_t *ev);

/* Verify the Ed25519 signature covering pubkey(32)+timestamp(4)+
 * app_data(app_data_len), as found in an ADVERT payload. `signature`
 * must point at 64 bytes (MC_SIGNATURE_SIZE). Returns true iff the
 * signature verifies against `pubkey` (32 bytes, MC_PUB_KEY_SIZE).
 * Exposed for unit testing and reused by meshcore_decode_advert(). */
bool meshcore_advert_verify_signature(const uint8_t *pubkey, uint32_t timestamp,
                                      const uint8_t *app_data, size_t app_data_len,
                                      const uint8_t *signature);
bool meshcore_decode_trace(const meshcore_packet_t *pkt, mesh_event_t *ev);
bool meshcore_decode_grp_txt(const meshcore_packet_t *pkt,
                             const meshcore_channelset_t *channels,
                             mesh_event_t *ev);
bool meshcore_decode_grp_data(const meshcore_packet_t *pkt,
                              const meshcore_channelset_t *channels,
                              mesh_event_t *ev);

#endif /* MESHCORE_DECODERS_H */
