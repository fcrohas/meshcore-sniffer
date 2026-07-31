/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: packet decoder.
 *
 * Takes raw bytes from the LoRa demod (16-byte radio header + N
 * encrypted payload bytes), routes by channel hash to the keyset,
 * AES-CTR decrypts, parses the protobuf Data envelope, and emits a
 * structured event to a callback.
 *
 */

#ifndef MESH_PACKET_H
#define MESH_PACKET_H

#include "keyset.h"
#include "meshcore.h"
#include "meshtastic.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct mesh_event {
    /* Radio-header fields */
    mesh_header_t  header;
    int            hop_limit;
    int            hop_start;
    bool           want_ack;
    bool           via_mqtt;

    /* Decryption metadata */
    bool           decrypted;
    char           channel_name[32];   /* matched key entry; "" if none matched */

    /* Reception quality (filled in by the LoRa demod via lora_frame_meta_t,
     * 0/0 when frame originates from a non-LoRa source like the selftest). */
    float          rssi_db;
    float          snr_db;

    /* Radio-layer parameters of the channel this frame arrived on. 0 when
     * the source isn't a tuned LoRa decoder. preset_name is "" when (sf,
     * cr, bw_hz) doesn't match any canonical Meshtastic preset. */
    int            sf;
    int            cr;             /* 5..8 = 4/5..4/8 */
    int            bw_hz;
    uint64_t       freq_hz;        /* RF center freq of the slot the frame arrived on; 0 = unknown */
    char           preset_name[24]; /* "LongFast" / "LongSlow" / ... or "" */

    /* Decoder slot index (0..CHANNELIZER_MAX_CHANNELS-1) -- which of the
     * many parallel demodulator slots caught this frame. Lets operators
     * map a JSON event back to the specific (frequency, BW, SF, CR) tuple
     * the decoder was tuned to, independent of the in-protocol channel
     * hash byte. -1 when the frame didn't come from a tuned LoRa slot
     * (synthetic test events, etc.). */
    int            slot_id;

    /* RF-quality telemetry from the LoRa demod. The fields below are
     * computed for every received frame; main.c stamps them onto the
     * event before publish via on_mesh_event. Defaults (zero / false)
     * mean "no useful value to report" and feed.c suppresses them. */
    bool           has_crc;          /* payload had a trailing CRC16 trailer */
    bool           payload_crc_ok;   /* CRC verified; meaningful only when has_crc */
    bool           crc_corrected;    /* payload_crc_ok is true only via a
                                       * brute-force fix (see crc_corrected_bits);
                                       * see lora_frame_meta_t.crc_corrected */
    int            crc_corrected_bits; /* 0/1/2; see lora_frame_meta_t.crc_corrected_bits.
                                       * A value of 2 is NOT trustworthy on CRC
                                       * agreement alone -- call
                                       * mesh_event_crc2bit_trusted() before
                                       * treating it as genuine. main.c's
                                       * on_mesh_event already does this and
                                       * resets an untrusted 2-bit fix back to
                                       * an ordinary CRC failure before publish,
                                       * so any crc_corrected_bits==2 reaching
                                       * feed.c/db_sqlite.c is already trusted. */
    float          cfo_hz;           /* carrier-frequency offset estimate */

    /* Per-station capture timestamp + self-reported accuracy (ns).
     * station_t_ns is host wall-clock at receive time (ns since epoch).
     * station_t_acc_ns is this station's clock-discipline class:
     *     <= 100         GPSDO + 1PPS-locked SDR sample counter
     *     <= 10000       chrony + PPS host clock
     *     <= 1000000     chrony + NTP host clock
     *     1000000+       unsynchronized / unknown
     * The fusion-side mlat solver uses station_t_acc_ns to weight
     * observations; a poorly-synchronized station effectively votes
     * less than a GPSDO-locked one. 0 means "not populated". */
    uint64_t       station_t_ns;
    uint32_t       station_t_acc_ns;

    /* TDOA metadata: SDR-rate absolute sample index at the moment of
     * preamble lock for this frame, plus the sample rate so fusion can
     * convert sample deltas into seconds. preamble_lock_sample_idx is
     * monotonically increasing per station; cross-station alignment
     * requires GPSDO/PPS clocks (see station_t_acc_ns). Both 0 when
     * the source isn't a tuned LoRa decoder. */
    uint64_t       preamble_lock_sample_idx;
    uint64_t       sample_rate_sps;
    /* Fractional-sample timing offset of the preamble peak, in
     * SDR-sample units. Combines with preamble_lock_sample_idx:
     *     toa_sample = preamble_lock_sample_idx + preamble_lock_sample_frac
     * Read-only metadata; the decoder does not feed this back into
     * STO/CFO/SFO. 0 when no fractional estimate was available. */
    float          preamble_lock_sample_frac;
    /* CLOCK_REALTIME at the moment preamble lock was detected.
     * Strictly earlier than station_t_ns (which the dedup ring
     * stamps when the first replica is buffered, after the frame
     * has fully demodulated). Fusion uses this as a software-lock
     * timing source when present; it is not a sample-derived
     * GPSDO-grade TOA -- PFB / scheduling / buffering latency are
     * still baked in. 0 when not populated. */
    uint64_t       preamble_lock_t_ns;

    /* Inner Data envelope (when decrypted == true) */
    uint32_t       portnum;
    const uint8_t *payload;
    size_t         payload_len;

    /* Raw over-the-air frame (radio header + payload, as demodulated),
     * hex-encoded. Populated unconditionally for both protocols --
     * including CRC failures and undecrypted frames -- so the web
     * dashboard's Debug tab can show exactly what was received
     * regardless of decode outcome. Truncated to 256 raw bytes (512
     * hex chars) if longer. */
    char           raw_hex[513];
    uint32_t       request_id;         /* protobuf field 6 (or 0) */
    uint32_t       reply_id;           /* protobuf field 7 (or 0) */
    bool           want_response;      /* protobuf field 4 */

    /* Optional: extracted typed fields per port. */
    /* TEXT_MESSAGE_APP: payload is UTF-8 text directly. */
    /* POSITION_APP / NODEINFO_APP / TELEMETRY_APP: cooked into the
     * structs below by mesh_decoders.c (TODO). */

    /* ---- MeshCore-specific fields (--protocol=meshcore) ----
     * Left zeroed/false for the Meshtastic path; feed.c branches on
     * is_meshcore before touching any Meshtastic-only field above
     * that doesn't apply (header.to/from/packet_id, portnum, etc). */
    bool     is_meshcore;
    int      mc_route_type;
    int      mc_payload_type;    /* mc_payload_type_t */
    int      mc_payload_ver;
    char     mc_type_name[16];   /* "ADVERT" / "TXT_MSG" / ... */
    uint8_t  mc_dest_hash;
    uint8_t  mc_src_hash;
    uint8_t  mc_channel_hash;
    uint32_t mc_timestamp;       /* decoded uint32 LE timestamp, when present */
    char     mc_node_name[40];   /* ADVERT app_data name, when parsed */
    char     mc_text[256];       /* TXT_MSG / GRP_TXT decoded text */
    uint8_t  mc_pubkey[32];      /* ADVERT / ANON_REQ pubkey material */
    int      mc_path_hop_count;
    uint8_t  mc_path_snrs[MC_MAX_PATH_SIZE];
    uint8_t  mc_path_hashes[MC_MAX_PATH_SIZE];
    /* Header-level routing path (distinct from mc_path_hashes/snrs
     * above, which are the TRACE *payload's* hop table). This is the
     * path[] field carried in every MeshCore packet's framing -- the
     * accumulated relay-hash trail for FLOOD routing, or the intended
     * hop sequence for DIRECT routing. Present on any payload_type,
     * including GRP_TXT/GRP_DATA channel broadcasts, so it's the only
     * per-message "path" available for ordinary channel traffic. */
    int      mc_hdr_path_hash_count;  /* number of hops in mc_hdr_path[] */
    int      mc_hdr_path_hash_size;   /* bytes per hop hash: 1, 2, or 3 */
    int      mc_hdr_path_len;         /* bytes actually copied into mc_hdr_path[] */
    uint8_t  mc_hdr_path[MC_MAX_PATH_SIZE];
    bool     mc_sig_valid;       /* ADVERT: Ed25519 signature verified against mc_pubkey */
    uint16_t mc_data_type;       /* GRP_DATA: data_type field (u16 LE) */
    uint16_t mc_data_len;        /* GRP_DATA: data_len field (u8 on the wire, widened here) */
    uint8_t  mc_txt_type;        /* GRP_TXT: TXT_TYPE_PLAIN(0)/CLI_DATA(1)/SIGNED_PLAIN(2) */
    /* GRP_DATA: best-effort CayenneLPP decode of the blob (see
     * meshcore_lpp.h) -- "" when the blob didn't parse as valid LPP
     * (most GRP_DATA traffic isn't telemetry; mc_text still carries
     * the hex-dump fallback in that case). JSON array, e.g.
     * [{"ch":1,"type":103,"name":"temperature","unit":"C","value":23.4}].
     * MeshCore GRP_DATA carries no sender identity -- only channel_name/
     * mc_channel_hash attribute this reading to anything. */
    char     mc_telemetry_json[1024];

    /* ADVERT app_data (AdvertDataBuilder/Parser format): flags byte
     * (bits[3:0]=adv_type, bits[7:4]=presence flags) followed by
     * optional lat/lon, extra1, extra2, and name. See mc_adv_type_t /
     * ADV_*_MASK in meshcore.h. */
    uint8_t  mc_adv_type;        /* ADVERT: flags & ADV_TYPE_MASK */
    bool     mc_has_latlon;      /* ADVERT: ADV_LATLON_MASK was set */
    double   mc_lat;             /* ADVERT: decoded latitude, degrees */
    double   mc_lon;             /* ADVERT: decoded longitude, degrees */
    bool     mc_has_name;        /* ADVERT: ADV_NAME_MASK was set */
    uint16_t mc_extra1;          /* ADVERT: ADV_FEAT1_MASK payload, when present */
    uint16_t mc_extra2;          /* ADVERT: ADV_FEAT2_MASK payload, when present */

    /* Region scope (v1.10+ "Region Management" flood-scoping), present
     * only when mc_route_type is TRANSPORT_FLOOD/TRANSPORT_DIRECT --
     * see meshcore_packet.h's has_transport_codes. code1 is the
     * sender's declared scope, code2 a reply-routing hint; both are
     * opaque HMAC codes unless meshcore_region_resolve_fast()/_full()
     * matched code1 against a known public region name. */
    bool     mc_has_region_scope;
    uint16_t mc_region_code1;
    uint16_t mc_region_code2;
    char     mc_region_name[32]; /* resolved name for code1, empty if unresolved */

    /* MULTIPART (payload_type 0x0A): the core protocol adds no
     * encryption of its own here -- payload[0]'s high nibble is the
     * number of packets still remaining in this multipart sequence,
     * low nibble is the WRAPPED payload's real mc_payload_type_t,
     * followed by that inner payload verbatim (see upstream
     * Mesh::forwardMultipartDirect()). Only ACK -- also fully
     * cleartext -- is unwrapped one level further (into mc_timestamp,
     * same ack_crc reuse as a direct ACK payload); any other inner
     * type is genuinely opaque without that payload type's own
     * envelope/crypto, same as if it had arrived un-wrapped. */
    uint8_t  mc_multipart_remaining;
    int      mc_multipart_inner_type; /* mc_payload_type_t of the wrapped payload */

    /* CONTROL (payload_type 0x0B) node-discovery convention -- see
     * MC_CTL_TYPE_NODE_DISCOVER_REQ/_RESP in meshcore.h for the
     * application-vs-protocol caveat. mc_ctl_subtype is "" for a
     * CONTROL payload that doesn't match this specific convention.
     * DISCOVER_RESP reuses mc_pubkey/mc_adv_type below (same fields
     * ADVERT uses) since it's the same kind of information -- a node
     * revealing its identity in the clear. */
    char     mc_ctl_subtype[24];  /* "NODE_DISCOVER_REQ" / "NODE_DISCOVER_RESP" / "" */
    uint32_t mc_ctl_tag;          /* correlation tag, both REQ and RESP */
    uint8_t  mc_ctl_filter;       /* REQ only: ADV_TYPE_* bitmask being discovered */
    uint32_t mc_ctl_since;        /* REQ only: optional "modified since" ts, 0 if absent */
    float    mc_ctl_snr;          /* RESP only: SNR of the REQ as heard by the responder */
} mesh_event_t;

typedef void (*mesh_event_cb_t)(const mesh_event_t *ev, void *user);

/* One-shot decode of a complete LoRa-frame payload.
 * `frame` must include the 16-byte radio header followed by the
 * encrypted (or plaintext) inner Data bytes.
 *
 * Returns 0 if a packet was emitted (regardless of decryption success;
 * the callback receives the header even if no key matched), -1 if the
 * frame is malformed (too short). */
int mesh_packet_decode(const uint8_t *frame, size_t frame_len,
                       const keyset_t *keys,
                       mesh_event_cb_t cb, void *user);

/* Same, with explicit RSSI/SNR metadata to thread through to the
 * mesh_event_t. mesh_packet_decode() is just a wrapper that calls
 * this with rssi=snr=0. */
int mesh_packet_decode_with_meta(const uint8_t *frame, size_t frame_len,
                                 float rssi_db, float snr_db,
                                 const keyset_t *keys,
                                 mesh_event_cb_t cb, void *user);

/* Same as _with_meta, but also threads the radio-layer parameters
 * (sf/cr/bw_hz) so the JSON feed and CoT remarks can identify which
 * Meshtastic preset the frame arrived on. Pass 0 for any unknown value. */
int mesh_packet_decode_with_radio(const uint8_t *frame, size_t frame_len,
                                  float rssi_db, float snr_db,
                                  int sf, int cr, int bw_hz,
                                  const keyset_t *keys,
                                  mesh_event_cb_t cb, void *user);

/* True if a crc_corrected_bits>=2 frame carries independent
 * authentication that also validates -- MeshCore GRP_TXT/GRP_DATA's
 * per-channel 2-byte truncated HMAC (ev->decrypted, checked in
 * meshcore_verify_and_decrypt()) or ADVERT's Ed25519 signature
 * (ev->mc_sig_valid, checked unconditionally in
 * meshcore_advert_verify_signature()). A bare 2-bit CRC16 match
 * collides with wrong content often enough (see
 * lora_crc_bruteforce_correct_2bit's doc) that CRC agreement alone
 * is not sufficient evidence; two independent ~1-in-65536 checks
 * passing by accident on the same wrong content is ~1-in-4-billion.
 * Every other payload type (no MAC/signature in this codebase) and
 * the entire Meshtastic protocol path (is_meshcore false, no
 * equivalent authentication) always return false here. A pure
 * function so it's directly unit-testable; the actual gate lives in
 * main.c's on_mesh_event(). */
bool mesh_event_crc2bit_trusted(const mesh_event_t *ev);

#endif
