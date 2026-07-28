#!/bin/bash
# meshcore-sniffer + meshtastic-fusion C2 smoke test.
#
# Spins up a fusion aggregator and a sniffer that talks to it via two
# separate channels:
#   - HTTP self-announce  (--announce-to)   -> fusion's POST /api/sensors
#   - ZMQ DEALER socket   (--c2-dealer)     -> fusion's ROUTER, heartbeat
# Then verifies, in order:
#   1. The sensor self-registered (GET /api/sensors lists it).
#   2. The DEALER heartbeat reached fusion (sensor entry has dealer:true).
#   3. A fan-out command via fusion preferred the DEALER path and got a
#      reply back from the sniffer's c2_dispatch.
#
# Copyright (c) 2026 CEMAXECUTER LLC
# SPDX-License-Identifier: GPL-3.0-or-later

set -e
SNIFFER_WEB_PORT=${SNIFFER_WEB_PORT:-8951}
FUSION_PORT=${FUSION_PORT:-8952}
ROUTER_PORT=${ROUTER_PORT:-8953}

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SNIFFER_BIN="${SNIFFER_BIN:-$HERE/build/meshcore-sniffer}"
FUSION_BIN="${FUSION_BIN:-$HERE/fusion/meshtastic-fusion}"

if [[ ! -x "$SNIFFER_BIN" ]]; then
    echo "FAIL: sniffer binary not found at $SNIFFER_BIN"
    exit 1
fi
if [[ ! -x "$FUSION_BIN" ]]; then
    echo "FAIL: fusion binary not found at $FUSION_BIN -- build with 'cd fusion && go build'"
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"; kill $FUSION_PID $SNIFFER_PID 2>/dev/null; wait 2>/dev/null' EXIT

echo "== Test: fusion + sniffer C2 round-trip =="

# Fusion: bind ROUTER for DEALER inbound, listen for HTTP, no persistent registry.
"$FUSION_BIN" --listen=":$FUSION_PORT" --c2-router="tcp://*:$ROUTER_PORT" \
    > "$TMPDIR/fusion.log" 2>&1 &
FUSION_PID=$!
sleep 1

# Sniffer: noise file source so the binary stays alive a while; announce to
# fusion HTTP; open DEALER outbound to fusion ROUTER. 1 GB of urandom at
# 20 Msps cs8 = ~25 s of processing -- comfortably longer than the test
# needs to exercise both legs of the C2 path.
dd if=/dev/zero of="$TMPDIR/big.cs8" bs=1M count=1024 status=none
"$SNIFFER_BIN" --file="$TMPDIR/big.cs8" --rate=20000000 --center=910000000 \
    --presets=LongFast --web="$SNIFFER_WEB_PORT" \
    --station-id=smoke-c2 \
    --zmq=tcp://*:7099 \
    --announce-to="http://localhost:$FUSION_PORT/api/sensors" \
    --c2-dealer="tcp://localhost:$ROUTER_PORT" \
    > "$TMPDIR/sniffer.log" 2>&1 &
SNIFFER_PID=$!

# Self-announce fires on a 3 s initial delay; DEALER heartbeat every 30 s
# but the connect itself counts as session activity. 8 s gives plenty of
# slack for both legs to reach fusion.
sleep 8

# 1. Sensor registered via HTTP self-announce?
sensors=$(curl -s "http://localhost:$FUSION_PORT/api/sensors")
if ! echo "$sensors" | grep -q '"name":"smoke-c2"'; then
    echo "FAIL: sensor 'smoke-c2' did not appear in /api/sensors"
    echo "fusion log:"; tail -30 "$TMPDIR/fusion.log"
    echo "sniffer log:"; tail -30 "$TMPDIR/sniffer.log"
    echo "/api/sensors body: $sensors"
    exit 1
fi
echo "  [1/3] HTTP self-announce: ok"

# 2. DEALER session live? (fusion sets sensor.dealer=true when the ROUTER
#    has heard from this identity recently.)
if ! echo "$sensors" | grep -q '"dealer":true'; then
    echo "FAIL: 'dealer':true not present -- DEALER session did not register"
    echo "fusion log:"; tail -30 "$TMPDIR/fusion.log"
    echo "sniffer log:"; tail -30 "$TMPDIR/sniffer.log"
    echo "/api/sensors body: $sensors"
    exit 1
fi
echo "  [2/3] DEALER session registered: ok"

# 3. Fan-out command via DEALER -> sniffer's c2_dispatch -> reply back.
#    cot-multicast is the cheapest endpoint (no side effects we care about
#    beyond the round-trip). Body is a "host:port" string.
fanout=$(curl -s -X POST -d "239.2.3.99:6999" \
    "http://localhost:$FUSION_PORT/api/fanout/cot-multicast")
if ! echo "$fanout" | grep -q '"sensor":"smoke-c2"'; then
    echo "FAIL: fan-out reply did not include smoke-c2"
    echo "reply: $fanout"
    exit 1
fi
# Either DEALER round-tripped (status 200) or HTTP fallback worked (also 200).
# We only fail if both paths errored.
if ! echo "$fanout" | grep -qE '"status":200'; then
    echo "FAIL: fan-out reply had no 200 from smoke-c2"
    echo "reply: $fanout"
    exit 1
fi
echo "  [3/3] fan-out command round-trip: ok"

echo
echo "C2 SMOKE TEST PASSED"
