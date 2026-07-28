# meshtastic-recover

Offline PSK recovery for Meshtastic LoRa captures. The aircrack-ng of
the Meshtastic audit suite.

## What it does

Reads a libpcap file produced by `meshcore-sniffer --pcap=PATH` and a
wordlist of candidate keys, and prints any keys that successfully
decrypt one or more captured frames. Output is in `--keys-file=`
compatible format so you can immediately re-feed the recovered keys to
`meshcore-sniffer` to decrypt past or future traffic on those
channels.

## Why it exists

- **Defensive auditing**: validate that your channel keys survive a
  wordlist attack (rockyou-class lists run in seconds).
- **Lost-key recovery**: get back into a channel whose
  `meshtastic.org/e/` URL you misplaced, when you still have a recent
  pcap from a sniffer that recorded the encrypted traffic.
- **Education**: demonstrate the security model -- the channel-hash
  byte is an 8-bit fingerprint of the key, AES-CTR has no integrity
  check, and the protobuf parse on a successful decrypt is the
  confirmation. Same primitives apply to anyone designing a similar
  scheme.
- **Authorized pentesting**: where Meshtastic is in scope. Same
  dual-use posture as aircrack-ng -- the binary is neutral, scope and
  authorization is the operator's responsibility.

## Algorithm

For each candidate (channel name, PSK) pair:

1. **Channel-hash prefilter** -- compute `xorHash(name) XOR xorHash(psk)`
   and skip any frame whose 1-byte header.channel field doesn't match.
   8-bit prefilter eliminates 99.6% of decrypt attempts per frame.
2. **AES-CTR decrypt** the still-encrypted Data envelope using the
   nonce from the cleartext header (packet_id + from + zeros).
3. **Protobuf parse** the result. A clean parse to a Data message with
   a non-zero portnum and non-empty payload is the confirmation that
   the candidate is the right key. Wrong-key decrypts produce uniform
   random bytes which essentially never satisfy this.

Wordlist entries can be:

| Form | Example | Behaviour |
|---|---|---|
| `base64:` prefix | `base64:AQ==` | raw 16/32-byte key, base64-encoded |
| `hex:` prefix | `hex:d4f1bb...01` | raw 16/32-byte key, hex-encoded |
| `simple<N>` | `simple1`, `simple7` | the firmware's simpleN derivation (1..255) |
| plain text | `hunter2`, `secret` | passphrase: padded/truncated to 16 bytes |

The `--simple-keys` flag also tries each of the 255 simpleN keys
against a built-in list of common channel names (`LongFast`,
`MediumFast`, etc.). Most factory-default Meshtastic deployments are
recovered instantly from this pass.

## Usage

```bash
# Capture some encrypted traffic with the sniffer
./meshcore-sniffer --hackrf --pcap=/tmp/session.pcap

# Recover keys from the capture
./meshtastic-recover --pcap=/tmp/session.pcap \
                     --simple-keys \
                     --wordlist=/usr/share/dict/words \
                     --output=/tmp/recovered.keys

# Re-decode the same capture with the recovered keys
./meshcore-sniffer --file=/tmp/session.pcap --keys-file=/tmp/recovered.keys
```

### Flags

```
--pcap=FILE              libpcap input (DLT_USER0 from --pcap=PATH on the sniffer)
--wordlist=FILE          candidate PSKs, one per line; supports base64:/hex:/simpleN/
                         plain-passphrase forms
--simple-keys            also try simple1..simple255 against common channel names
--output=FILE            recovered keys written here, --keys-file= compatible
                         (default: stdout)
--hashcat-export=FILE    emit each frame as a hashcat-format hash line for the
                         upcoming custom-mode plugin (mode 99001 in dev range)
--hashcat-export-merge=N with --hashcat-export, pack up to N consecutive frames
                         sharing the same channel identity into a single
                         $meshtastic$2 multi-frame line (N=2..16). The plugin
                         then requires a candidate PSK to decrypt every frame
                         in the line, eliminating single-frame false positives
                         at scale. Default N=1 keeps one-frame-per-line v1
                         output. Tail groups of size 1 still emit as
                         $meshtastic$1, so no capture data is silently dropped.
                         Pair with --channel-name= when grouping across a
                         multi-channel capture; with an empty name the only
                         grouping key is the one-byte channel hash, which can
                         collide across channels.
--channel-name=NAME      populate the <name_hex> field on hashcat export when
                         the channel name is known (matches WPA-EAPOL's
                         ESSID-in-hash pattern). Empty by default.
--max-frames=N           stop after testing N frames per candidate (0 = all)
-h, --help               this help
```

## Realistic attack surface

| Channel type | Recoverable? |
|---|---|
| Default key (PSK = `simple1` etc.) on a standard channel name | Instant via `--simple-keys` |
| Channel using a weak passphrase (in /usr/share/dict/words or rockyou) | Seconds with a wordlist pass |
| Channel using a strong random 16- or 32-byte key | Not feasible (2^128 search space) |

The sniffer's `--archive=DIR` and `--pcap=PATH` outputs are both
readable by this tool; pcap is preferred since the on-air bytes are
preserved exactly.

## Build

The recover binary is built alongside the main sniffer when you build
the parent project:

```bash
cd .. && mkdir -p build && cd build
cmake .. && make -j$(nproc)
# produces both build/meshcore-sniffer and build/meshtastic-recover
```

It links against OpenSSL (for AES-CTR). No FFTW / SDR dependencies --
the cracker is a pure offline tool.

## GPU acceleration (planned)

CPU is fast for typical wordlists (millions of trials per second per
core, OpenMP-parallelized across all cores, channel-hash prefilter
eliminates 99.6% of work). A GPU port makes sense only for very large
keyspaces or distributed cracking.

The chosen architecture is a **hashcat custom-mode plugin**, not a
private OpenCL kernel inside this binary. Reasons:

- Hashcat's AES kernels are mature, hand-tuned, audited, and cover
  NVIDIA / AMD / Apple Silicon. Re-implementing them risks crypto bugs.
- Hashcat ships rule-based attacks, masks, distributed cracking,
  workload tuning -- all for free once the plugin exists.
- Submitting upstream means the work benefits more users than just our
  own.

`meshtastic-recover --hashcat-export=FILE` produces a hash file in a
hashcat-idiomatic format the plugin consumes. Two line shapes:

```
v1 (one frame per line, the default):
$meshtastic$1*<chash>*<packet_id>*<from_node>*<name_hex>*<ciphertext>

v2 (multi-frame, emitted by --hashcat-export-merge=N for N>=2):
$meshtastic$2*<chash>*<name_hex>*<N>*<pkt1>*<from1>*<ct1>*…*<pktN>*<fromN>*<ctN>
```

| Field | Length | Meaning |
|---|---|---|
| `$meshtastic$` | 12 | scheme tag |
| `1` or `2` | 1 | format version (integer; v1 is one frame, v2 is N frames sharing a channel) |
| `<chash>` | 2 hex | 1-byte channel-hash from frame[13]; the same for every frame in a v2 line |
| `<name_hex>` | 0+ hex | UTF-8 channel name (when known); empty signals unknown |
| `<N>` (v2 only) | decimal | frame count, 2..16 |
| `<packet_id>` / `<pktN>` | 8 hex | uint32 LE from frame[8..11] |
| `<from_node>` / `<fromN>` | 8 hex | uint32 LE from frame[4..7] |
| `<ciphertext>` / `<ctN>` | variable hex | frame[16..end] (encrypted Data envelope) |

A v2 line totals `4 + 3*N` `*`-separated tokens. v1 lines stay accepted by the
plugin unchanged; v2 is purely additive. The plugin verifier requires every
frame in a v2 line to decrypt with the candidate PSK before reporting a crack,
which drops the structural-only false-positive rate from ~1/2^33 per frame to
~1/2^(33*N) per multi-frame line.

`--channel-name=NAME` populates the name field (matches WPA-EAPOL's
ESSID-in-hash pattern; the realistic attack model is "operator knows
the channel name from cleartext NodeInfo broadcasts and brute-forces
the PSK"). When empty (default), the future plugin iterates a builtin
list of common preset names per candidate.

**Format precedents** (so hashcat maintainers can match it on sight):

- The dollar-tag + star-delimited shape mirrors **mode 22400 / AES Crypt**
  (`$aescrypt$1*<iv>*<salt>*<ct>*<hmac>`) — closest existing structural twin.
- The "expose nonce components separately, let the kernel reconstruct"
  choice mirrors **mode 22000 / WPA** (`WPA*01*<pmkid>*<mac_ap>*<mac_sta>*<essid_hex>*<anonce>*<eapol>*<msg_pair>`).
  Lets the GPU kernel build the 16-byte AES-CTR nonce inline:
  `packet_id_LE || 4 zero bytes || from_node_LE || 4 zero bytes`
  matching `build_nonce()` in `mesh_packet.c`.
- Lowercase hex throughout, integer version, fixed-length signature
  token verified via `TOKEN_ATTR_VERIFY_SIGNATURE` (the standard
  hashcat parser path).

**Plugin verifier** given a candidate `(channel_name, psk)`:

1. Compute `xorHash(channel_name) XOR xorHash(psk)`; compare to `<chash>`. Skip on mismatch (8-bit prefilter, eliminates ~99.6% of work per frame).
2. AES-CTR decrypt `<ciphertext>` using `psk` as the AES key and the
   reconstructed 16-byte nonce.
3. Confirm decrypted bytes parse as a Meshtastic Data envelope with
   `portnum > 0` and non-empty payload (same gate the CPU `meshtastic-recover` uses).

**Hash-mode number:** to be assigned by hashcat maintainers when the
plugin PR is reviewed (their convention: 100-step increments, recently
35000-series and 70000-series). Until then, treat as draft. The format
is additive: `$meshtastic$1` and `$meshtastic$2` are both accepted by
the plugin, so adding the multi-frame shape did not break existing
v1-only consumers. Any future breaking change would bump to
`$meshtastic$3`. The pcap remains the canonical archive; the hashcat
export is just a derived view.

## Honest limitations

- **The AES nonce bytes must be intact.** Bit errors in the cleartext
  header at the `from` (4 bytes) or `packet_id` (4 bytes) positions
  mangle the AES-CTR nonce, breaking recovery even with the right
  key. Bit errors elsewhere in the frame (header tail bytes, body
  ciphertext) are tolerated as long as the protobuf-shape verifier
  still gates a clean parse on the decrypted bytes -- empirically
  recovery often succeeds against `payload_crc_ok: false` frames
  when the corruption misses the structural fields.
- **GPU support via hashcat is in flight, not yet upstream.** Working
  end-to-end on a sister branch (`meshtastic-plugin` in our hashcat
  fork). The `--hashcat-export` output here is the consumed format.
  CPU OpenMP-parallel is the default for now.
- **No PMKID-style attack.** Meshtastic doesn't have an EAPOL handshake;
  the per-frame channel-hash + ciphertext is the only side-channel the
  attacker has, and we use both.

## License

GPL-3.0-or-later. See `../LICENSE`. Copyright (c) 2026 CEMAXECUTER LLC.
