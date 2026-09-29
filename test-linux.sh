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
    apt-get install -y -qq --no-install-recommends iproute2 iptables netcat-openbsd python3 python3-scapy > /dev/null
    # fail loudly if apt silently failed: a missing tool otherwise surfaces
    # later as phantom symptoms (e.g. SYNs that never reach the stack)
    for tool in ip tc iptables nc python3; do
      command -v $tool > /dev/null || { echo "FAIL: $tool missing after apt install"; exit 1; }
    done

    # the library tests, plus the root-only integration tests (we are root here)
    cargo test --release --quiet
    cargo test --release --quiet --test interface_drop --test blocking_write --test rst_semantics --test shutdown_read_semantics --test listener_drop_rst --test synrcvd_reset -- --ignored --nocapture

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
    # reads with an error instead of hanging or reporting clean EOF. No data
    # is sent: a reset legitimately discards received-but-unread bytes, so a
    # ping here would make the byte accounting of test 5 racy.
    python3 - <<EOF
import socket, struct
s = socket.create_connection(("192.168.0.2", 8000), timeout=5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()
EOF
    sleep 1
    grep -q "got RST; aborting connection" /tmp/server.log \
      || { echo "FAIL: RST not handled"; kill $pid; exit 1; }
    grep -q "connection reset by peer" /tmp/server.log \
      || { echo "FAIL: read did not error on RST"; kill $pid; exit 1; }

    # test 4: with a connection parked idle in the connection map (its
    # server-side reader is blocked, so it is never reclaimed) the stack
    # must stay silent — no periodic empty segments. n1 must be non-zero
    # or the server never traced any write at all.
    python3 - <<'EOF' &
import socket, time
s = socket.create_connection(("192.168.0.2", 8000), timeout=5)
time.sleep(8)
EOF
    idle=$!
    sleep 1
    n1=$(grep -c "^write(" /tmp/server.out)
    [ "$n1" -gt 0 ] || { echo "FAIL: server produced no write() trace"; kill $pid; exit 1; }
    sleep 2
    n2=$(grep -c "^write(" /tmp/server.out)
    echo "idle write() calls: $n1 -> $n2"
    [ "$n1" -eq "$n2" ] || { echo "FAIL: transmitting while idle"; kill $pid; exit 1; }
    wait $idle || true

    # test 5: on a lossy, reordering link, a multi-segment stream must
    # arrive complete and unduplicated: out-of-order segments must not
    # advance RCV.NXT past the gap (silent loss), and retransmissions must
    # not re-queue data. Byte-total accounting catches both (missing bytes
    # < expected, duplicated bytes > expected).
    if tc qdisc add dev tun0 root netem delay 3ms reorder 25% 50% loss 10% 2>/dev/null; then
      python3 - <<'EOF'
import socket
s = socket.create_connection(("192.168.0.2", 8000), timeout=180)
lines = ("B4LINE%06d" % i for i in range(80))
data = "".join(l + "A" * (100 - len(l) - 1) + "\n" for l in lines)  # 80 x 100 = 8000 bytes
s.sendall(data.encode())
s.shutdown(socket.SHUT_WR)
s.settimeout(180)
while s.recv(4096):
    pass
s.close()
EOF
      # the client drains the server FIN immediately and exits while its
      # data is still in flight; retransmissions under loss take seconds,
      # so poll for the transfer to complete instead of a fixed sleep
      got=0
      for _ in $(seq 1 45); do
        # 5 (test 1) + 8000 (test 5) bytes must have been read
        got=$(grep -o "read [0-9]*b of data" /tmp/server.log | grep -o "[0-9]*" | awk "{s+=\$1} END{print s+0}")
        [ "$got" -eq 8005 ] && break
        sleep 2
      done
      # duplicate ACKs during the data phase prove out-of-order/duplicate
      # segments actually arrived and were handled (otherwise vacuous)
      dupacks=$(grep "^write(" /tmp/server.out | grep -o "ack: [0-9]*" | awk "\$2 < 8002" | uniq -d | wc -l)
      echo "lossy transfer: $got/8005 bytes, $dupacks duplicate-ACK points"
      [ "$got" -eq 8005 ] || { echo "FAIL: lossy transfer corrupted"; kill $pid; exit 1; }
      [ "$dupacks" -ge 1 ] || { echo "FAIL: no duplicate/OOO handling exercised"; kill $pid; exit 1; }
      tc qdisc del dev tun0 root
    else
      echo "NOTE: netem unavailable in this kernel; skipped loss test"
    fi

    # test 6: a transfer much larger than the receive window with a draining
    # reader must complete byte-exact — exercises window updates and the
    # blocking/backpressure behavior of the send queue
    if ! python3 - <<'EOF'
import socket
s = socket.create_connection(("192.168.0.2", 8000), timeout=60)
# ASCII payload: the demo server reader println!s it as utf-8, so binary
# data would (correctly) panic it and close the window
lines = ("B6LINE%06d" % i for i in range(1024))
data = "".join(l + "x" * (100 - len(l) - 1) + "\n" for l in lines)  # 102400 bytes
s.sendall(data.encode())
s.shutdown(socket.SHUT_WR)
s.settimeout(60)
while s.recv(4096):
    pass
s.close()
EOF
    then
      echo "FAIL: large transfer client"
      ss -tan 2>/dev/null | head -8
      tc qdisc show dev tun0 2>/dev/null
      tail -8 /tmp/server.log
      kill $pid
      exit 1
    fi
    got=0
    for _ in $(seq 1 30); do
      # 5 + 8000 + 102400 bytes total must have been read
      got=$(grep -o "read [0-9]*b of data" /tmp/server.log | grep -o "[0-9]*" | awk "{s+=\$1} END{print s+0}")
      [ "$got" -eq 110405 ] && break
      sleep 2
    done
    echo "large transfer: $got/110405 bytes"
    [ "$got" -eq 110405 ] || { echo "FAIL: large transfer incomplete"; tail -8 /tmp/server.log; kill $pid; exit 1; }

    # test 7 (SYN-RCVD reset form against a never-accepting listener) runs
    # as the root-only integration test synrcvd_reset above: the demo
    # server would race the connection out of SYN-RCVD before the probe

    kill $pid 2>/dev/null || true
    echo "ALL LINUX TESTS PASSED"

    kill $pid 2>/dev/null || true
    echo "ALL LINUX TESTS PASSED"
  '
