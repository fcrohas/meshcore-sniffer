/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshcore-sniffer: CLI option parsing and shared runtime state.
 *
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "sdr.h"

/* SDR backend selection -- one and only one of these is active per run. */
typedef enum {
    SDR_BACKEND_NONE = 0,
    SDR_BACKEND_HACKRF,
    SDR_BACKEND_BLADERF,
    SDR_BACKEND_RTLSDR,
    SDR_BACKEND_SOAPYSDR,
    SDR_BACKEND_SDRPLAY,
    SDR_BACKEND_AIRSPY,
    SDR_BACKEND_USRP,
    SDR_BACKEND_VITA49,
    SDR_BACKEND_FILE,
} sdr_backend_t;

typedef enum {
    OP_MODE_DECODE = 0,        /* default: stare at standard grid + decode */
    OP_MODE_SCAN,              /* off-grid LoRa discovery only */
    OP_MODE_SCAN_AND_DECODE,   /* both: decode the grid, alert on off-grid */
} op_mode_t;

/* Application-layer protocol running over the LoRa CSS physical
 * layer. MESHTASTIC is the default and exercises the pre-existing
 * decode path unchanged; MESHCORE is strictly additive. */
typedef enum {
    MESH_PROTOCOL_MESHTASTIC = 0,
    MESH_PROTOCOL_MESHCORE,
} mesh_protocol_t;

/* ---- Shared runtime state ---- */

extern volatile sig_atomic_t running;  /* set to 0 by SIGINT/SIGTERM */
extern double  samp_rate;              /* resolved sample rate (Hz, double for SDR APIs) */
extern double  center_freq;            /* resolved center frequency (Hz) */
extern int     bias_tee;
extern double  ppm_correction;

/* ---- Top-level user input ---- */

extern sdr_backend_t opt_sdr_backend;
extern char         *opt_sdr_serial;
extern uint64_t      opt_center_freq_hz;  /* user override; 0 = derive from region */
extern uint32_t      opt_sample_rate;     /* user override; 0 = SDR max */
extern int           opt_clock_src;       /* CLOCK_SRC_* from sdr.h */
/* Log level: 0 = silent (warnings still go to stderr via warnx),
 *            1 = -v   INFO  (config, channel adds, frame decodes),
 *            2 = -vv  DEBUG (per-frame meta, decryption attempts),
 *            3 = -vvv TRACE (per-symbol state machine). */
extern int           verbose;
extern bool          opt_force_simd_generic;
extern op_mode_t     opt_op_mode;
extern bool          opt_alert_off_grid;
extern bool          opt_list_devices;
extern bool          opt_print_schema;
extern bool          opt_trusted_only;
/* Single-bit CRC brute-force correction for CRC-fail LoRa frames (see
 * lora_crc_bruteforce_correct in lora.h/.c). Default on; --no-crc-bruteforce
 * disables it for operators who want raw CRC-fail visibility unmodified. */
extern bool          opt_crc_bruteforce;
/* Two-bit CRC brute-force fallback, tried only when the single-bit
 * search above fails (see lora_crc_bruteforce_correct_2bit in
 * lora.h/.c). Off by default: a bare 2-bit CRC16 match is not
 * trustworthy on its own (see that function's doc), so this only
 * benefits MeshCore GRP_TXT/GRP_DATA/ADVERT traffic, where
 * mesh_event_crc2bit_trusted() (meshcore_decoders.c) can independently
 * authenticate the result before it's published as corrected --
 * --crc-bruteforce-2bit enables it. */
extern bool          opt_crc_bruteforce_2bit;
/* One-shot maintenance mode (see crc_recover.h): re-attempts the CRC
 * bruteforce tiers against every already-stored, still-failing
 * (crc_ok=0) MeshCore row in --sqlite-db, persists any that now
 * recover (gated the same way live capture is -- see
 * mesh_event_crc2bit_trusted()), prints a report, and exits without
 * touching any SDR/radio input. Requires --sqlite-db=PATH. */
extern bool          opt_crc_recover;
/* --region-recover: one-shot, re-resolve MeshCore region-scope names
 * (meshcore_region_dict.c) against every already-captured
 * transport-coded row in --sqlite-db, persist any newly-resolved
 * name, print a report, and exit without touching any SDR/radio
 * input. Requires --sqlite-db=PATH. */
extern bool          opt_region_recover;
extern bool          opt_telemetry_recover;
/* --control-recover: one-shot, re-decode MeshCore CONTROL rows
 * (meshcore_decoders.c's decode_control(), added after some CONTROL
 * rows were already captured opaque) against every already-captured
 * row in --sqlite-db, persist any newly-resolved
 * NODE_DISCOVER_REQ/_RESP, print a report, and exit without touching
 * any SDR/radio input. Requires --sqlite-db=PATH. */
extern bool          opt_control_recover;
/* --lora-soft: enable lora.c's soft-decision (LLR) decoding path on
 * every LoRa decoder created for the rest of this run. Off by
 * default -- costs ~50KB extra LLR storage per decoder and only
 * matters near the SNR floor. lora.c is also linked standalone into
 * a few diagnostic binaries (test_crc_bruteforce, test_oversample_
 * self, focused_demo) that don't link options.c at all, so this
 * can't be a direct opt_lora_soft reference over there -- main()
 * instead exports it as the MESHTASTIC_LORA_SOFT=1 env var
 * lora_decoder_create() already reads (see lora.c), so lora.c stays
 * fully decoupled from the options module. */
extern bool          opt_lora_soft;
extern bool          opt_show_untrusted;
extern bool          opt_diagnostics;

/* Deep-decode mode -- toggles the scan-then-focus pool. OFF keeps the
 * wideband-only path byte-identical to the pre-Phase-3 baseline; AUTO
 * provisions an IQ ring and a focused-worker pool that rewind and
 * deep-decode wideband-detected slots. */
typedef enum {
    DEEP_DECODE_OFF = 0,
    DEEP_DECODE_AUTO = 1,
} deep_decode_mode_t;
extern deep_decode_mode_t opt_deep_decode;
extern int           opt_focus_workers;       /* 1..4 */
extern double        opt_focus_hold_s;        /* hysteresis seconds */
extern int           opt_focus_rewind_ms;     /* rewind from "now" on promotion */
extern int           opt_focus_ring_ms;       /* raw-IQ ring history */
extern char         *opt_focus_freqs_csv;     /* optional allowlist Hz,Hz,... */
extern double        opt_focus_min_snr_db;    /* drop pool promotions below this SNR */
extern int           opt_focus_os;            /* 0=auto, otherwise 1/2/4/8 */

/* TDOA snapshot-store: per-event raw-IQ capture from the iq_ring.
 * Disabled when opt_snapshot_store_dir is NULL. min_snr_db < 0 means
 * "inherit from opt_focus_min_snr_db at startup". */
extern char         *opt_snapshot_store_dir;
extern int           opt_snapshot_window_pre_ms;
extern int           opt_snapshot_window_post_ms;
extern long long     opt_snapshot_disk_mb;
extern long long     opt_snapshot_age_s;
extern double        opt_snapshot_min_snr_db;

/* Meshtastic */
extern char         *opt_region;          /* "US", "EU_868", ... */
extern char         *opt_preset_csv;      /* "LongFast,LongSlow" or "all" */
extern char         *opt_keys_csv;        /* user key list */
extern char         *opt_keys_file;       /* path; one spec per line, # comments ok */
extern char         *opt_share_url;       /* meshtastic.org/e/ URL to import at startup */
extern char         *opt_iq_record;       /* path to write raw IQ to (tee from push_samples) */
extern char         *opt_stats_json;      /* path to dump 5s per-channel stats JSON */
/* FFTW wisdom persistence. NULL = disabled. Empty string "" = use the
 * default XDG cache path. Non-empty = use the explicit path. */
extern char         *opt_fftw_wisdom;

/* MeshCore (--protocol=meshcore). No region/preset table -- SF/BW/CR/freq
 * are plain CLI parameters (see --meshcore-freq/-sf/-bw/-cr). Channels
 * are (name, 32-byte secret) pairs, repeatable like --feed. */
extern mesh_protocol_t opt_protocol;
#define MESHCORE_CHANNEL_MAX 8
extern char         *opt_meshcore_channel[MESHCORE_CHANNEL_MAX];
extern int           opt_meshcore_channel_count;
extern uint64_t       opt_meshcore_freq_hz;
extern int            opt_meshcore_sf;
extern int            opt_meshcore_bw_hz;
extern int            opt_meshcore_cr;
extern bool           opt_meshcore_no_default_channel;

/* Webhook sink. NULL url = disabled. event_csv NULL/empty uses the
 * default allowlist (PSK_DISCOVERED, OFF_GRID_LORA, GEOFENCE_*).
 * format selects the wire shape: "raw" (default), "slack", "discord". */
extern char         *opt_webhook_url;
extern char         *opt_webhook_on;
extern char         *opt_webhook_format;
extern int           opt_webhook_timeout_ms;

/* Extra user-supplied off-grid slots (e.g. promoted from scan). */
#define EXTRA_FREQ_MAX 32
typedef struct {
    uint64_t freq_hz;
    int      bw_hz;
    int      sf;
    int      cr;
} extra_freq_t;
extern extra_freq_t opt_extra_freqs[EXTRA_FREQ_MAX];
extern int          opt_extra_freq_count;

/* SDR / file input */
extern char       *opt_input_file;       /* IQ file path for FILE backend */
extern iq_format_t iq_format;            /* FMT_CI8 / FMT_CI16 / FMT_CF32 */
extern bool        opt_iq_format_set;    /* true if --iq-format given on CLI */

/* Per-backend gain controls */
extern int  hackrf_lna_gain;             /* 0..40 step 8 */
extern int  hackrf_vga_gain;             /* 0..62 step 2 */
extern int  hackrf_amp_enable;
extern int  bladerf_gain_val;
extern int  rtl_dev_index;
extern int  rtl_gain_tenths_db;          /* tenths of dB; <0 = AGC */
extern int  airspy_gain_val;             /* 0..21; <0 = default */
extern char *sdrplay_serial;
extern int  sdrplay_gain_val;
extern int  sdrplay_lna_state;           /* -1 = default (0); explicit LNA reduction state, model/band-dependent max */
extern int  sdrplay_agc_mode;            /* -1 = derive from --gain sign (legacy); 0 = force manual; 1 = force AGC */
extern int  sdrplay_agc_setpoint_dbfs;   /* AGC target level in dBFS, default -30 */
extern int  soapy_num;
extern char *soapy_args;
#define SOAPY_GAINS_MAX 8
extern char  *soapy_gain_elem_names[SOAPY_GAINS_MAX];
extern double soapy_gain_elem_vals[SOAPY_GAINS_MAX];
extern int    soapy_gain_elem_count;
extern double soapy_gain_val;
extern int    soapy_gain_explicit;
#define SOAPY_SETTINGS_MAX 8
extern char  *soapy_setting_keys[SOAPY_SETTINGS_MAX];
extern char  *soapy_setting_vals[SOAPY_SETTINGS_MAX];
extern int    soapy_setting_count;
extern char  *uhd_args;
extern char  *opt_usrp_otw_format;  /* "sc16" (default) or "sc8" */
extern int    usrp_gain_val;
extern int   vita49_enabled;
extern char *vita49_endpoint;

/* Output sinks */
#define FEED_MAX 4
extern char *opt_feed_endpoint[FEED_MAX];
extern int   opt_feed_count;
extern char *opt_mqtt_host;
extern int   opt_mqtt_port;
extern char *opt_mqtt_topic;
/* MQTT auth/TLS. user/pass NULL = unauthenticated (prior behavior).
 * tls off = plain TCP (prior behavior); cafile NULL under tls means
 * "search common system CA bundle paths", falling back to an error
 * unless insecure is also set. */
extern char *opt_mqtt_user;
extern char *opt_mqtt_pass;
extern bool  opt_mqtt_tls;
extern char *opt_mqtt_cafile;
extern bool  opt_mqtt_insecure;
/* --mqtt-observer: publish MeshCore events to a LetsMesh/MeshRank-
 * compatible "observer" feed instead of the sniffer's native JSON
 * schema (see feed_meshcore_observer.h). Requires iata + observer_id
 * so the topic (meshcore/{iata}/{observer_id}/packets) is stable
 * across restarts -- these platforms correlate sightings by that
 * identity, so a fresh random id every run would fragment an
 * operator's own history on their dashboard. Meshtastic events are
 * not published in this mode: LetsMesh/MeshRank are MeshCore-only
 * consumers, and sending them the wrong schema would be worse than
 * silently dropping it from this sink. */
extern bool  opt_mqtt_observer;
extern char *opt_mqtt_iata;
extern char *opt_mqtt_observer_id;
extern char *opt_zmq_endpoint;
extern char *opt_cot_multicast;          /* "239.2.3.1:6969" or NULL */
extern int   opt_web_port;
extern char *opt_station_id;
extern char *opt_gpsd_endpoint;          /* "host:port"; NULL = disabled */
/* --rx-lat/--rx-lon: manually declared station position, for
 * deployments with no gpsd (fixed antenna install, no GPS receiver
 * at all). gpsd_get_fix() (gpsd.c) checks these FIRST -- if set, they
 * win over a live gpsd fix and are always reported as fresh (age 0s),
 * so every emitted JSON event gets station_lat/station_lon exactly
 * like the --gpsd path does (see feed.c's serialize_event()), and the
 * dashboard's Topology tab can place this station at its real
 * position on the map instead of falling back to an estimated
 * centroid. NAN means "unset"; both must be set together. */
extern double opt_rx_lat, opt_rx_lon;
extern char *opt_api_token;              /* bearer token for POST /api endpoints; NULL = unauthenticated */
extern char *opt_pcap_path;              /* path to pcap file; NULL = disabled */
extern char *opt_pcap_fifo;              /* path to pcap fifo; NULL = disabled */
extern char *opt_psk_wordlist;           /* path to wordlist; NULL = disabled */
/* Defaults to the bundled MIT-licensed French wordlist
 * (recover/wordlists/french.txt, MC_DEFAULT_HASHTAG_WORDLIST) so the
 * background hashtag-channel dictionary attack runs out of the box;
 * NULL only if that default file couldn't be resolved at build time.
 * --meshcore-hashtag-wordlist=PATH overrides it; --no-meshcore-hashtag-dict
 * disables the attack entirely regardless of this path. */
extern char *opt_meshcore_hashtag_wordlist;
extern bool  opt_meshcore_no_hashtag_dict;
extern char *opt_archive_dir;            /* JSONL archive directory; NULL = disabled */
extern char *opt_sqlite_db;              /* SQLite DB path; NULL = disabled */
/* Cross-restart recovery window: on startup, replay events.json rows
 * newer than this many hours into the SSE history ring (see
 * db_sqlite_replay_recent()). Node list reload is separate and
 * uncapped -- always happens whenever --sqlite-db is set. <= 0 disables
 * the event replay (node list reload still happens). */
extern double opt_history_replay_hours;
extern char *opt_geofence_file;          /* polygon file path; NULL = disabled */
extern char *opt_announce_to;            /* fusion /api/sensors URL; NULL = disabled */
extern char *opt_c2_dealer;              /* tcp://fusion:7009; NULL = HTTP-only */
extern char *opt_zmq_curve_secret;       /* path to Z85 secret key file; sets server CURVE on PUB */
extern char *opt_zmq_curve_keygen;       /* generate keypair to PATH (.pub written alongside) and exit */
extern uint32_t opt_station_t_acc_ns;    /* self-reported clock-discipline class in ns; default 1e6 (NTP) */

int  options_parse(int argc, char **argv);
void options_print_help(const char *prog);

#endif /* OPTIONS_H */
