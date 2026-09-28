#!/bin/bash
cargo b --release
ext=$?
if [[ $ext -ne 0 ]]; then
  exit $ext
fi

if [[ "$(uname)" == "Darwin" ]]; then
  # macOS: utun requires root (no setcap equivalent), and the interface is
  # created by the process itself, so detect it by diffing the interface list.
  before=$(ifconfig -l)
  sudo ./target/release/trust &
  pid=$!
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
  if [[ -z "$tun" ]]; then
    echo "could not find new utun interface" >&2
    kill $pid
    exit 1
  fi
  echo "using interface $tun"
  sudo ifconfig "$tun" 192.168.0.1 192.168.0.2 up
  trap "kill $pid" INT TERM
  wait $pid
else
  sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/trust
  $CARGO_TARGET_DIR/release/trust &
  pid=$!
  sudo ip addr add 192.168.0.1/24 dev tun0
  sudo ip link set up dev tun0
  trap "kill $pid" INT TERM
  wait $pid
fi
