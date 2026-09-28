#!/bin/bash
# E2E test of the Linux code path, run inside Docker (works from macOS too).
# Uses the original upstream Linux setup: inside the container's network
# namespace 192.168.0.0/24 is free, so tun0 gets the upstream addresses.
#
# Requires: docker, with the daemon running.
set -eu
cd "$(dirname "$0")"

docker run --rm --device /dev/net/tun --cap-add NET_ADMIN \
  -v "$PWD":/src -w /src \
  -e CARGO_TARGET_DIR=/tmp/target \
  -v rust-tcp-cargo-registry:/usr/local/cargo/registry \
  rust:1-slim bash -eux -c '
    [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends iproute2 netcat-openbsd > /dev/null

    cargo build --release
    $CARGO_TARGET_DIR/release/trust 2>/tmp/server.log &
    pid=$!

    ip addr add 192.168.0.1/24 dev tun0
    ip link set up dev tun0
    sleep 1

    out=$(printf "ping\n" | nc -w 5 192.168.0.2 8000)
    echo "client received: $out"
    [ "$out" = "hello from rust-tcp!" ] || { echo "FAIL: greeting"; kill $pid; exit 1; }

    sleep 1
    grep -q "read 5b of data" /tmp/server.log || { echo "FAIL: server data"; kill $pid; exit 1; }

    # TIME-WAIT is 10s in this stack; afterwards the connection must be reclaimed
    sleep 12
    grep -q "reclaiming closed connection" /tmp/server.log \
      || { echo "FAIL: connection not reclaimed"; kill $pid; exit 1; }

    kill $pid 2>/dev/null || true
    echo "ALL LINUX TESTS PASSED"
  '
