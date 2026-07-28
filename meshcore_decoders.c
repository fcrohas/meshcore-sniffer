/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: MeshCore per-payload-type decoders.
 */

#include "meshcore_decoders.h"
#include "meshcore_hashtag_dict.h"

#include <ctype.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* Copy up to `max-1` printable bytes from [p, p+n) into out, NUL
 * terminated, stopping at the first NUL/control byte. Used for the
 * ADVERT app_data node-name field, which is free-form text. */
static void copy_printable(const uint8_t *p, size_t n, char *out, size_t max)
{
    size_t i = 0;
    for (; i < n && i < max - 1; ++i) {
        uint8_t c = p[i];
        if (c == 0) break;
        out[i] = (char)c;
    }
    out[i] = 0;
}

/* Render up to (max-1)/2 bytes of [p, p+n) as lowercase hex into out,
 * NUL terminated. Generic fallback for binary blobs (GRP_DATA
 * payloads) whose data_type isn't yet decoded by a dedicated case. */
static void hex_dump(const uint8_t *p, size_t n, char *out, size_t max)
{
    static const char digits[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < max; ++i) {
        out[o++] = digits[(p[i] >> 4) & 0xF];
        out[o++] = digits[p[i] & 0xF];
    }
    out[o] = 0;
}

/* Ed25519 signature verification (ADVERT). The signed message is
 * pubkey(32) + timestamp(4, LE) + app_data(app_data_len). Ed25519 is
 * a "pure" scheme in OpenSSL's EVP API: no digest is fed
 * incrementally via EVP_DigestVerifyUpdate(); the entire message is
 * passed to a single EVP_DigestVerify() call after
 * EVP_DigestVerifyInit() with a NULL digest type. */
bool meshcore_advert_verify_signature(const uint8_t *pubkey, uint32_t timestamp,
                                      const uint8_t *app_data, size_t app_data_len,
                                      const uint8_t *signature)
{
    if (!pubkey || !signature) return false;
    if (!app_data && app_data_len > 0) return false;

    uint8_t msg[MC_PUB_KEY_SIZE + 4 + MC_MAX_PACKET_PAYLOAD];
    size_t msg_len = MC_PUB_KEY_SIZE + 4 + app_data_len;
    if (msg_len > sizeof(msg)) return false;

    memcpy(msg, pubkey, MC_PUB_KEY_SIZE);
    msg[MC_PUB_KEY_SIZE + 0] = (uint8_t)(timestamp);
    msg[MC_PUB_KEY_SIZE + 1] = (uint8_t)(timestamp >> 8);
    msg[MC_PUB_KEY_SIZE + 2] = (uint8_t)(timestamp >> 16);
    msg[MC_PUB_KEY_SIZE + 3] = (uint8_t)(timestamp >> 24);
    if (app_data_len > 0) memcpy(msg + MC_PUB_KEY_SIZE + 4, app_data, app_data_len);

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                 pubkey, MC_PUB_KEY_SIZE);
    if (!pkey) return false;

    bool ok = false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1) {
            /* Ed25519: single-shot verify, no *Update() calls. */
            ok = EVP_DigestVerify(ctx, signature, MC_SIGNATURE_SIZE,
                                  msg, msg_len) == 1;
        }
        EVP_MD_CTX_free(ctx);
    }
    EVP_PKEY_free(pkey);
    return ok;
}

/* Real-world range check, plus the classic "no GPS fix" (0,0)
 * sentinel. Used to drop an ADVERT's lat/lon when radio corruption (or
 * the CRC bruteforce recovery guessing the wrong bit on a CRC-fail
 * frame) has flipped a bit in this field -- otherwise wild,
 * unmistakably bogus coordinates get persisted/published as a node's
 * live position (seen in practice: a repeater's marker jumping
 * thousands of km, or landing on null island). */
static bool mc_latlon_plausible(double lat, double lon)
{
    if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) return false;
    if (lat == 0.0 && lon == 0.0) return false;
    return true;
}

/* ---- ADVERT (payload_type 4): in-the-clear ---- */
bool meshcore_decode_advert(const meshcore_packet_t *pkt, mesh_event_t *ev)
{
    const uint8_t *p = pkt->payload;
    size_t len = pkt->payload_len;
    if (len < MC_PUB_KEY_SIZE + 4 + MC_SIGNATURE_SIZE) return false;

    memcpy(ev->mc_pubkey, p, MC_PUB_KEY_SIZE);
    p += MC_PUB_KEY_SIZE;

    ev->mc_timestamp = rd_le32(p);
    p += 4;

    /* signature(64) covers pubkey+timestamp+app_data. */
    const uint8_t *signature = p;
    p += MC_SIGNATURE_SIZE;

    const uint8_t *app_data = p;
    size_t app_data_len = (size_t)((pkt->payload + len) - p);

    ev->mc_sig_valid = meshcore_advert_verify_signature(ev->mc_pubkey, ev->mc_timestamp,
                                                        app_data, app_data_len, signature);

    if (app_data_len >= 1) {
        /* app_data[0] is a flags byte (AdvertDataBuilder/Parser format,
         * see upstream src/helpers/AdvertDataHelpers.cpp):
         *   bits[3:0] = adv_type
         *   0x10 = has lat/lon (int32 LE each, degrees*1e6)
         *   0x20 = has extra1 (uint16 LE)
         *   0x40 = has extra2 (uint16 LE)
         *   0x80 = has name (remaining bytes, NOT null-terminated on
         *          the wire)
         * Fields are read in that fixed order; each read is bounds
         * checked against app_data_len before touching the buffer, to
         * tolerate malformed/truncated frames from a live radio
         * stream (upstream's own Arduino parser doesn't bother). */
        uint8_t flags = app_data[0];
        size_t i = 1;

        ev->mc_adv_type = flags & ADV_TYPE_MASK;

        if (flags & ADV_LATLON_MASK) {
            if (app_data_len >= i + 8) {
                int32_t lat_e6 = (int32_t)rd_le32(app_data + i);
                i += 4;
                int32_t lon_e6 = (int32_t)rd_le32(app_data + i);
                i += 4;
                double lat = (double)lat_e6 / 1e6;
                double lon = (double)lon_e6 / 1e6;
                /* Drop just the lat/lon on an implausible fix rather
                 * than failing the whole ADVERT -- name/adv_type/
                 * sig_valid decoded from the same frame are still
                 * good. */
                if (mc_latlon_plausible(lat, lon)) {
                    ev->mc_has_latlon = true;
                    ev->mc_lat = lat;
                    ev->mc_lon = lon;
                }
            } else {
                i = app_data_len; /* truncated: stop parsing further fields */
            }
        }

        if ((flags & ADV_FEAT1_MASK) && app_data_len >= i + 2) {
            ev->mc_extra1 = rd_le16(app_data + i);
            i += 2;
        } else if (flags & ADV_FEAT1_MASK) {
            i = app_data_len;
        }

        if ((flags & ADV_FEAT2_MASK) && app_data_len >= i + 2) {
            ev->mc_extra2 = rd_le16(app_data + i);
            i += 2;
        } else if (flags & ADV_FEAT2_MASK) {
            i = app_data_len;
        }

        if ((flags & ADV_NAME_MASK) && app_data_len >= i) {
            ev->mc_has_name = true;
            copy_printable(app_data + i, app_data_len - i,
                           ev->mc_node_name, sizeof(ev->mc_node_name));
        }
    }

    strncpy(ev->mc_type_name, "ADVERT", sizeof(ev->mc_type_name) - 1);
    ev->decrypted = true;  /* nothing to decrypt -- payload is in the clear */
    return true;
}

/* ---- TRACE (payload_type 9): in-the-clear ---- */
bool meshcore_decode_trace(const meshcore_packet_t *pkt, mesh_event_t *ev)
{
    const uint8_t *p = pkt->payload;
    size_t len = pkt->payload_len;
    if (len < 4 + 4 + 1) return false;

    /* tag(4) + auth_code(4) are parsed but not currently surfaced on
     * mesh_event_t; add fields if a consumer needs them. */
    p += 4 + 4;
    uint8_t flags = *p++;

    /* Firmware (Mesh::onRecvPacket, v1.11+): the lower 2 bits of the
     * flags byte select the *route* hash-entry size, entry_size =
     * 1 << (flags & 0x03) bytes (1/2/4/8) -- a separate encoding from
     * the outer packet framing's path_hash_size (1/2/3, from the
     * path_len byte). The destination route -- the list of node
     * hashes the trace is meant to visit -- is embedded directly in
     * the payload right after this flags byte, one entry per intended
     * hop, using that entry size.
     *
     * Per-hop SNRs are NOT in the payload at all: as a TRACE packet
     * is forwarded hop by hop, each relay appends one signed SNR byte
     * to the packet's own header path[] field (Mesh.cpp:
     * pkt->path[pkt->path_len++] = (int8_t)(pkt->getSNR()*4)) --
     * already parsed generically by meshcore_packet_parse() into
     * pkt->path[]/path_hash_count (hash_size stays 1 for TRACE, since
     * setPathHashSizeAndCount() is never called on it). This function
     * used to read both SNRs *and* hashes out of the payload as two
     * n_hops-sized arrays, which doesn't match the wire format at
     * all. */
    int route_entry_size = 1 << (flags & 0x03);
    size_t have = (size_t)((pkt->payload + len) - p);
    int n_route_hops = (int)(have / (size_t)route_entry_size);
    if (n_route_hops > MC_MAX_PATH_SIZE) n_route_hops = MC_MAX_PATH_SIZE;

    int n_snr_hops = pkt->path_hash_count;
    if (n_snr_hops < 0) n_snr_hops = 0;
    if (n_snr_hops > MC_MAX_PATH_SIZE) n_snr_hops = MC_MAX_PATH_SIZE;

    for (int i = 0; i < n_snr_hops; ++i)
        ev->mc_path_snrs[i] = pkt->path[i];
    for (int i = 0; i < n_route_hops; ++i) {
        /* mc_path_hashes[] is a 1-byte-per-hop table; when the route
         * uses a >1-byte hash (rare -- only path_sz>0 deployments),
         * only the first byte of each entry is kept here. */
        ev->mc_path_hashes[i] = p[(size_t)i * (size_t)route_entry_size];
    }
    ev->mc_path_hop_count = n_route_hops > n_snr_hops ? n_route_hops : n_snr_hops;

    strncpy(ev->mc_type_name, "TRACE", sizeof(ev->mc_type_name) - 1);
    ev->decrypted = true;
    return true;
}

/* Shared helper for GRP_TXT/GRP_DATA: payload = channel_hash(1) +
 * MAC(2) + enc(...). Tries the channel(s) matching the hash byte,
 * falling back to brute-forcing every configured channel. */
static bool grp_decrypt(const meshcore_packet_t *pkt,
                        const meshcore_channelset_t *channels,
                        uint8_t *plain, size_t *plain_len,
                        uint8_t *matched_channel_idx)
{
    if (pkt->payload_len < 1 + MC_CIPHER_MAC_SIZE) return false;
    if (!channels) return false;

    uint8_t channel_hash = pkt->payload[0];
    const uint8_t *enc_with_mac = pkt->payload + 1;
    size_t enc_len = pkt->payload_len - 1;

    int idx[MC_CHANNEL_MAX_ENTRIES];
    meshcore_channelset_rdlock((meshcore_channelset_t *)channels);
    int n = meshcore_channelset_lookup(channels, channel_hash, idx, MC_CHANNEL_MAX_ENTRIES);
    bool ok = false;
    for (int i = 0; i < n && !ok; ++i) {
        const meshcore_channel_t *ch = &channels->entries[idx[i]];
        if (meshcore_verify_and_decrypt(ch->secret, ch->secret_len, enc_with_mac, enc_len,
                                        plain, plain_len) == 0) {
            ok = true;
            if (matched_channel_idx) *matched_channel_idx = (uint8_t)idx[i];
        }
    }
    meshcore_channelset_rdunlock((meshcore_channelset_t *)channels);
    return ok;
}

bool meshcore_decode_grp_txt(const meshcore_packet_t *pkt,
                             const meshcore_channelset_t *channels,
                             mesh_event_t *ev)
{
    uint8_t plain[MC_MAX_PACKET_PAYLOAD + MC_CIPHER_BLOCK_SIZE];
    size_t  plain_len = 0;
    uint8_t chan_idx = 0;
    if (!grp_decrypt(pkt, channels, plain, &plain_len, &chan_idx)) {
        strncpy(ev->mc_type_name, "GRP_TXT", sizeof(ev->mc_type_name) - 1);
        ev->mc_channel_hash = pkt->payload_len > 0 ? pkt->payload[0] : 0;
        ev->decrypted = false;
        return true;
    }
    if (plain_len < 5) return false;
    ev->mc_timestamp = rd_le32(plain);
    /* plain[4] = txt_type byte: firmware (BaseChatMesh::onGroupDataRecv)
     * accepts any of TXT_TYPE_PLAIN(0)/CLI_DATA(1)/SIGNED_PLAIN(2) --
     * checked there via (txt_type >> 2) != 0, i.e. only bits 2+ must be
     * zero -- and treats plain[5:] as the "name: msg" text for all of
     * them alike (no per-type branch, unlike the 1:1 TXT_MSG path).
     * Reject anything else as unrecognized rather than assuming 0. */
    uint8_t txt_type = plain[4];
    if ((txt_type >> 2) != 0) return false;
    ev->mc_txt_type = txt_type;
    copy_printable(plain + 5, plain_len - 5, ev->mc_text, sizeof(ev->mc_text));
    strncpy(ev->channel_name, channels->entries[chan_idx].name, sizeof(ev->channel_name) - 1);
    ev->mc_channel_hash = channels->entries[chan_idx].hash;
    strncpy(ev->mc_type_name, "GRP_TXT", sizeof(ev->mc_type_name) - 1);
    ev->decrypted = true;
    return true;
}

bool meshcore_decode_grp_data(const meshcore_packet_t *pkt,
                              const meshcore_channelset_t *channels,
                              mesh_event_t *ev)
{
    uint8_t plain[MC_MAX_PACKET_PAYLOAD + MC_CIPHER_BLOCK_SIZE];
    size_t  plain_len = 0;
    uint8_t chan_idx = 0;
    if (!grp_decrypt(pkt, channels, plain, &plain_len, &chan_idx)) {
        strncpy(ev->mc_type_name, "GRP_DATA", sizeof(ev->mc_type_name) - 1);
        ev->mc_channel_hash = pkt->payload_len > 0 ? pkt->payload[0] : 0;
        ev->decrypted = false;
        return true;
    }
    if (plain_len < 3) return false;
    /* Real wire format (BaseChatMesh::sendGroupData): data_type(u16 LE) +
     * data_len(u8) + blob -- NO leading timestamp, and data_len is a
     * single byte, not u16. Dispatch by data_type below; default falls
     * back to a generic hex dump of the blob since the exact MeshCore
     * data_type registry isn't confirmed yet. */
    {
        uint16_t data_type = rd_le16(plain);
        uint8_t  data_len  = plain[2];
        size_t avail = plain_len - 3;
        size_t n = data_len < avail ? data_len : avail;

        ev->mc_data_type = data_type;
        ev->mc_data_len  = data_len;

        switch (data_type) {
        /* TODO: ajouter des décodeurs spécifiques quand la doc
         * MeshCore des data_type sera confirmée (ex: position,
         * telemetry...). */
        default:
            hex_dump(plain + 3, n, ev->mc_text, sizeof(ev->mc_text));
            break;
        }
    }
    strncpy(ev->channel_name, channels->entries[chan_idx].name, sizeof(ev->channel_name) - 1);
    ev->mc_channel_hash = channels->entries[chan_idx].hash;
    strncpy(ev->mc_type_name, "GRP_DATA", sizeof(ev->mc_type_name) - 1);
    ev->decrypted = true;
    return true;
}

/* ---- Envelope-only parsers (no key material available in a
 * passive sniffer): REQ/RESPONSE/ANON_REQ/PATH. Extracts the
 * metadata that's visible without decrypting. ---- */
static bool decode_envelope_only(const meshcore_packet_t *pkt, mesh_event_t *ev,
                                 const char *name, bool has_pubkey)
{
    size_t hdr_len = has_pubkey ? (1 + MC_PUB_KEY_SIZE + MC_CIPHER_MAC_SIZE)
                                : (2 + MC_CIPHER_MAC_SIZE);
    if (pkt->payload_len < hdr_len) return false;

    const uint8_t *p = pkt->payload;
    ev->mc_dest_hash = p[0];
    if (has_pubkey) {
        memcpy(ev->mc_pubkey, p + 1, MC_PUB_KEY_SIZE);
    } else {
        ev->mc_src_hash = p[1];
    }
    strncpy(ev->mc_type_name, name, sizeof(ev->mc_type_name) - 1);
    ev->decrypted = false;  /* passive sniffer can't decrypt without the peer key */
    return true;
}

static bool decode_ack(const meshcore_packet_t *pkt, mesh_event_t *ev)
{
    if (pkt->payload_len < 4) return false;
    ev->mc_timestamp = rd_le32(pkt->payload); /* actually a CRC, reused field for convenience */
    strncpy(ev->mc_type_name, "ACK", sizeof(ev->mc_type_name) - 1);
    ev->decrypted = true; /* ACK payload is not encrypted */
    return true;
}

static bool decode_unknown(const meshcore_packet_t *pkt, mesh_event_t *ev)
{
    strncpy(ev->mc_type_name, mc_payload_type_name(pkt->payload_type),
            sizeof(ev->mc_type_name) - 1);
    ev->decrypted = false;
    return true;
}

int meshcore_packet_decode_with_radio(const uint8_t *frame, size_t frame_len,
                                      float rssi_db, float snr_db,
                                      int sf, int cr, int bw_hz,
                                      const meshcore_channelset_t *channels,
                                      mesh_event_cb_t cb, void *user)
{
    meshcore_packet_t pkt;
    if (meshcore_packet_parse(frame, frame_len, &pkt) < 0) return -1;

    mesh_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.is_meshcore     = true;
    ev.rssi_db         = rssi_db;
    ev.snr_db          = snr_db;
    ev.sf              = sf;
    ev.cr              = cr;
    ev.bw_hz           = bw_hz;
    ev.slot_id         = -1;
    ev.mc_route_type   = pkt.route_type;
    ev.mc_payload_type = pkt.payload_type;
    ev.mc_payload_ver  = pkt.payload_ver;
    ev.mc_hdr_path_hash_count = pkt.path_hash_count;
    ev.mc_hdr_path_hash_size  = pkt.path_hash_size;
    ev.mc_hdr_path_len = pkt.path_len < sizeof(ev.mc_hdr_path)
                        ? (int)pkt.path_len : (int)sizeof(ev.mc_hdr_path);
    memcpy(ev.mc_hdr_path, pkt.path, (size_t)ev.mc_hdr_path_len);
    hex_dump(frame, frame_len > 256 ? 256 : frame_len, ev.raw_hex, sizeof(ev.raw_hex));

    bool ok;
    switch (pkt.payload_type) {
    case MC_PAYLOAD_ADVERT:
        ok = meshcore_decode_advert(&pkt, &ev);
        break;
    case MC_PAYLOAD_TRACE:
        ok = meshcore_decode_trace(&pkt, &ev);
        break;
    case MC_PAYLOAD_GRP_TXT:
        ok = meshcore_decode_grp_txt(&pkt, channels, &ev);
        break;
    case MC_PAYLOAD_GRP_DATA:
        ok = meshcore_decode_grp_data(&pkt, channels, &ev);
        break;
    case MC_PAYLOAD_ACK:
        ok = decode_ack(&pkt, &ev);
        break;
    case MC_PAYLOAD_TXT_MSG:
    case MC_PAYLOAD_REQ:
    case MC_PAYLOAD_RESPONSE:
    case MC_PAYLOAD_PATH:
        /* All four share the same envelope: dest_hash(1) + src_hash(1) +
         * MAC(2), undecryptable by a passive sniffer without the ECDH
         * shared secret (see Packet.h upstream: "PAYLOAD_TYPE_TXT_MSG
         * 0x02 // ... prefixed with dest/src hashes, MAC"). TXT_MSG used
         * to be missing from this switch entirely and fell through to
         * decode_unknown(), losing dest_hash/src_hash for every 1:1 text
         * message. */
        ok = decode_envelope_only(&pkt, &ev, mc_payload_type_name(pkt.payload_type), false);
        break;
    case MC_PAYLOAD_ANON_REQ:
        ok = decode_envelope_only(&pkt, &ev, "ANON_REQ", true);
        break;
    case MC_PAYLOAD_MULTIPART:
    case MC_PAYLOAD_CONTROL:
    case MC_PAYLOAD_RAW_CUSTOM:
    default:
        ok = decode_unknown(&pkt, &ev);
        break;
    }

    if (!ok) return -1;
    if (cb) cb(&ev, user);

    if ((pkt.payload_type == MC_PAYLOAD_GRP_TXT || pkt.payload_type == MC_PAYLOAD_GRP_DATA) &&
        !ev.decrypted) {
        /* Ship the undecrypted frame to the hashtag-channel dictionary
         * attack thread (no-op unless --meshcore-hashtag-wordlist is
         * configured). On success the discovered channel is added to
         * the runtime channelset so subsequent frames decrypt normally. */
        meshcore_hashtag_dict_enqueue(frame, frame_len, rssi_db, snr_db, sf, cr, bw_hz);
    }
    return 0;
}
