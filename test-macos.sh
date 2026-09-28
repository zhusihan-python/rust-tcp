#!/bin/bash
# End-to-end test for the macOS port: builds the stack, starts it under sudo,
# configures the utun interface it created, then checks that a real TCP
# connection from the kernel side works in both directions.
#
# Usage: ./test-macos.sh   (will prompt for sudo password)
set -u

fail() {
  echo "FAIL: $*" >&2
  sudo pkill -f 'target/release/trust' 2>/dev/null || true
  exit 1
}

cargo b --release || fail "build failed"

# authenticate before backgrounding: a password prompt from the backgrounded
# sudo would race the interface-detection loop below
sudo -v || fail "sudo authentication failed"

before=$(ifconfig -l)
sudo ./target/release/trust 2>server.log &

# find the utun interface the server just created
tun=""
for _ in $(seq 1 50); do
  after=$(ifconfig -l)
  for i in $after; do
    if [[ " $before " != *" $i "* && "$i" == utun* ]]; then
      tun=$i
      break
    fi
  done
  if [[ -n "$tun" ]]; then
    break
  fi
  sleep 0.1
done
[[ -n "$tun" ]] || fail "no new utun interface appeared (did sudo succeed?)"
echo "interface: $tun"

sudo ifconfig "$tun" 192.168.0.1 192.168.0.2 up || fail "ifconfig failed"

# test 1: kernel-side client receives the greeting sent by our userspace TCP
out=$(printf 'ping\n' | nc -w 5 192.168.0.2 8000)
if [[ "$out" == "hello from rust-tcp!" ]]; then
  echo "PASS: received greeting over userspace TCP"
else
  fail "expected greeting, got '$out'"
fi

# test 2: our userspace TCP received and logged the client's data
sleep 1
if grep -q "read 5b of data" server.log; then
  echo "PASS: server received 5 bytes of client data"
else
  fail "server never logged the client data; server.log tail: $(tail -5 server.log)"
fi

sudo pkill -f 'target/release/trust' 2>/dev/null || true
echo "ALL TESTS PASSED"
