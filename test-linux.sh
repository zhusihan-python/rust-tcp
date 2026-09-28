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
    apt-get install -y -qq --no-install-recommends iproute2 netcat-openbsd python3 > /dev/null

    # the library tests, plus the root-only interface test (we are root here)
    cargo test --release --quiet
    cargo test --release --quiet --test interface_drop -- --ignored --nocapture

    cargo build --release
    $CARGO_TARGET_DIR/release/trust >/tmp/server.out 2>/tmp/server.log &
    pid=$!

    ip addr add 192.168.0.1/24 dev tun0
    ip link set up dev tun0
    sleep 1

    # test 1: greeting round-trips through the userspace TCP stack
    out=$(printf "ping\n" | nc -w 5 192.168.0.2 8000)
    echo "client received: $out"
    [ "$out" = "hello from rust-tcp!" ] || { echo "FAIL: greeting"; kill $pid; exit 1; }

    sleep 1
    grep -q "read 5b of data" /tmp/server.log || { echo "FAIL: server data"; kill $pid; exit 1; }

    # test 2: after the 10s TIME-WAIT the connection must be reclaimed
    sleep 12
    grep -q "reclaiming closed connection" /tmp/server.log \
      || { echo "FAIL: connection not reclaimed"; kill $pid; exit 1; }

    # test 3: an aborted client (SO_LINGER 0 => RST) must fail the server
    # reads with an error instead of hanging or reporting clean EOF
    python3 - <<EOF
import socket, struct
s = socket.create_connection(("192.168.0.2", 8000), timeout=5)
s.sendall(b"ping\n")
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()
EOF
    sleep 1
    grep -q "got RST; aborting connection" /tmp/server.log \
      || { echo "FAIL: RST not handled"; kill $pid; exit 1; }
    grep -q "connection reset by peer" /tmp/server.log \
      || { echo "FAIL: read did not error on RST"; kill $pid; exit 1; }

    # test 4: with every connection idle, the stack must stay silent
    # (no periodic empty segments); n1 must be non-zero or the server
    # never traced any write at all, which would make 0 == 0 vacuous
    n1=$(grep -c "^write(" /tmp/server.out)
    [ "$n1" -gt 0 ] || { echo "FAIL: server produced no write() trace"; kill $pid; exit 1; }
    sleep 2
    n2=$(grep -c "^write(" /tmp/server.out)
    echo "idle write() calls: $n1 -> $n2"
    [ "$n1" -eq "$n2" ] || { echo "FAIL: transmitting while idle"; kill $pid; exit 1; }

    kill $pid 2>/dev/null || true
    echo "ALL LINUX TESTS PASSED"
  '
