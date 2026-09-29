//! Contract test for listener teardown: connections that were established
//! at the TCP level but never accepted must be reset when the listener goes
//! away, so the peer sees ECONNRESET instead of hanging until timeout.
//!
//! Linux-only and needs root (creates tun0 and configures addresses).
//! Run inside the Docker test container:
//!
//!     cargo test --release --test listener_drop_rst -- --ignored --nocapture
#![cfg(target_os = "linux")]

use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

#[test]
#[ignore] // needs root + a tun device
fn dropping_listener_resets_pending_connections() {
    let mut iface = trust::Interface::new().expect("creating tun0 requires root");
    let listener = iface.bind(8004).expect("bind");
    for args in [
        vec!["addr", "add", "192.168.0.1/24", "dev", "tun0"],
        vec!["link", "set", "up", "dev", "tun0"],
    ] {
        let st = std::process::Command::new("ip")
            .args(&args)
            .status()
            .expect("running ip");
        assert!(st.success(), "ip {:?} failed", args);
    }

    // client connects (handshake completes server-side) and stays unread
    let client = std::thread::spawn(|| {
        let mut c =
            std::net::TcpStream::connect("192.168.0.2:8004").expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        c.write_all(b"hello?\n").expect("write");
        // no accept() will ever happen: the listener is about to be dropped,
        // and the stack must reset us instead of leaving us hanging
        let mut buf = [0u8; 16];
        match c.read(&mut buf) {
            Ok(_) => panic!("expected a reset, got data or clean EOF"),
            Err(e) => assert_eq!(e.kind(), ErrorKind::ConnectionReset, "got {:?}", e),
        }
    });

    // let the handshake and the write land, then abandon the listener
    std::thread::sleep(Duration::from_secs(1));
    drop(listener);

    client.join().expect("client thread");
}
