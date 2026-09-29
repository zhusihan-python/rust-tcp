//! Contract test for shutdown(Read) semantics: after the application shuts
//! down its read side, reads must keep returning EOF even while the peer
//! keeps sending (the peer cannot know the read side is closed); the data
//! is acknowledged and discarded, not delivered.
//!
//! Linux-only and needs root (creates tun0 and configures addresses).
//! Run inside the Docker test container:
//!
//!     cargo test --release --test shutdown_read_semantics -- --ignored --nocapture
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::time::Duration;

#[test]
#[ignore] // needs root + a tun device
fn reads_after_shutdown_read_stay_eof() {
    let mut iface = trust::Interface::new().expect("creating tun0 requires root");
    let mut listener = iface.bind(8003).expect("bind");
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

    let client = std::thread::spawn(|| {
        let mut c =
            std::net::TcpStream::connect("192.168.0.2:8003").expect("connect");
        c.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"before\n").expect("write before");
        std::thread::sleep(Duration::from_millis(1500));
        // the server has shut down its read side by now; this must still be
        // accepted and ACKed, but never delivered to the reader
        c.write_all(b"after\n").expect("write after");
        std::thread::sleep(Duration::from_millis(1500));
        c.shutdown(std::net::Shutdown::Write).expect("shutdown");
    });

    let mut stream = listener.accept().expect("accept");
    // give "before" a moment to land in the buffer, then half-close reads
    std::thread::sleep(Duration::from_millis(500));
    stream
        .shutdown(std::net::Shutdown::Read)
        .expect("shutdown read");

    let mut buf = [0u8; 16];
    // even with data in flight/arriving, reads must see plain EOF
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(750));
        match stream.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!(
                "read after shutdown(Read) returned data: {:?}",
                String::from_utf8_lossy(&buf[..n])
            ),
            Err(e) => panic!("read after shutdown(Read) errored: {}", e),
        }
    }

    client.join().expect("client thread");
}
