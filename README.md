# rust-tcp: a userspace TCP stack

[![CI](https://github.com/zhusihan-python/rust-tcp/actions/workflows/ci.yml/badge.svg?branch=macos-utun)](https://github.com/zhusihan-python/rust-tcp/actions/workflows/ci.yml)

A toy-but-real TCP implementation written in userspace Rust: it owns a virtual
network interface (a TUN device on Linux, a `utun` interface on macOS), speaks
raw IPv4/TCP packets over it, and exposes the result through the standard
library's I/O traits — so an ordinary kernel-side program can open a real TCP
connection *to* the stack without either side knowing the other is unusual.

The demo server in `src/main.rs` is the whole user story:

```rust
let mut i = trust::Interface::new()?;      // creates the virtual interface
let mut listener = i.bind(8000)?;          // passive open, our own state machine
while let Ok(mut stream) = listener.accept() {
    stream.write(b"hello from rust-tcp!\n")?;   // our TCP, not the kernel's
    stream.shutdown(std::net::Shutdown::Write)?;
    // ... and reads whatever the peer sends back
}
```

`Interface`, `TcpListener`, and `TcpStream` implement (or behave like)
`std::io::Read` / `Write`, including blocking behavior: `read` parks until
data or an error arrives, `write` applies backpressure when the peer's
receive window closes.

## Origin

Fork of Jon Gjengset's [rust-tcp](https://github.com/jonhoo/rust-tcp)
(`trust` crate, originally a livestreamed exercise). This branch
(`macos-utun`) ports the stack from Linux-only to macOS and hardens the
connection state machine against RFC 793 review findings.

## Architecture

| File | Role |
|---|---|
| `src/lib.rs` | `Interface` / `TcpListener` / `TcpStream`. One packet loop owns the virtual NIC and demultiplexes incoming segments by the connection 4-tuple; reader/writer threads park on condvars and hand work to the loop. Connections live in a shared map behind `Mutex`/`Condvar`. |
| `src/tcp.rs` | The per-connection state machine: RFC 793 states (`SynRcvd`, `Estab`, `FinWait1/2`, `Closing`, `LastAck`, `TimeWait`, `CloseWait`, `Closed`), send/receive sequence spaces, retransmission timers, and the segment-processing rules of RFC 793 §3.4 (including RST generation). Unit tests cover the sequence-space arithmetic (half-domain wrapping comparisons) and state transitions. |
| `src/utun.rs` | Minimal macOS `utun` bindings: macOS has no `/dev/net/tun`; interfaces are created by connecting a `SYSPROTO_CONTROL` socket to the `com.apple.net.utun_control` kernel control, and every packet carries a 4-byte address-family header this wrapper strips/re-adds so the rest of the crate sees raw IP on both platforms. |
| Linux NIC access | Via the [`tun-tap`](https://crates.io/crates/tun-tap) crate (`/dev/net/tun`); on macOS the `utun` wrapper above takes the same slot behind a `cfg` switch. |

Notable behaviors, each pinned by a test (see below): TIME-WAIT reclamation,
RST aborts that surface as `ConnectionReset` rather than a clean EOF,
`shutdown(Write/Read/Both)` semantics, duplicate/out-of-order segment handling
with duplicate ACKs, retransmission on a ~1 s timeout, receive-window updates
gated by the SND.WL1/WL2 rules, and an over-window transfer completing
byte-exact under backpressure.

Deliberate simplifications: the initial sequence number is always 0, there is
no Nagle / slow-start / congestion control, and the TIME-WAIT (10 s) and
FIN-WAIT-2 (30 s) timers are shortened from the real 2·MSL so reclamation is
observable in tests. There is no `connect()` — the stack does passive opens
only.

## Running it

Requires a root-capable host (the stack must create a virtual network
interface).

```
cargo build --release
./run.sh          # starts the demo server; on macOS prompts for sudo,
                  # on Linux setcaps the binary
```

The server picks the benchmark range `198.18.0.0/15` (macOS utun; chosen so it
never collides with real LANs) or `192.168.0.0/24` (Linux TUN), and listens on
port 8000. Talk to it with anything — `nc`, a browser, `curl`:

```
$ printf 'ping\n' | nc 198.18.0.2 8000
hello from rust-tcp!
```

## Testing

```
cargo test                    # unit tests (no root needed)
./test-macos.sh               # end-to-end on macOS (prompts for sudo)
./test-linux.sh               # full end-to-end in Docker — runs on macOS hosts too
```

`test-linux.sh` is the primary suite and runs the Linux code path in a
`rust:1-slim` container regardless of the host OS. It covers:

1. greeting round-trip over the userspace TCP (kernel-side `nc` client);
2. server-side data receipt and TIME-WAIT reclamation;
3. `RST` abort (`SO_LINGER 0`) surfacing as an error on blocked reads;
4. transmit silence while a connection is idle (no keepalive-style noise);
5. an 8 KB transfer over a `netem` link with 10% loss, 3 ms delay and 50%
   reordering — byte-exact, no duplicates, duplicate-ACKs provably exercised;
6. a 100 KB transfer (≫ the 4 KB receive window) completing byte-exact
   through window updates and send-queue backpressure;
7. the root-only integration tests under `tests/` (run via
   `cargo test -- --ignored`), which drive the stack with raw scapy probes:
   SYN-RCVD bad-ACK reset form (RST `SEQ` = offending ACK, no ACK flag),
   listener-teardown deferred RST (client sees `ECONNRESET`, not a hang),
   RST semantics, `shutdown(Read)` EOF semantics, blocking writes, and
   interface drop.

GitHub Actions (`.github/workflows/ci.yml`) runs the unit tests and the full
`test-linux.sh` e2e suite on every push and pull request.

## Status

Passive open, full data transfer in both directions, flow control, graceful
and aborted close on all `shutdown` modes, and RFC 793 §3.4 RST generation are
implemented and covered by the suite above. Active open (`connect()`) is not.
