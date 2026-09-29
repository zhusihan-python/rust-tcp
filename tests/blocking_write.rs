//! Contract test for blocking writes and send-window updates: writing more
//! than the send queue (and more than the peer's small receive buffer)
//! must block in write()/flush() and still deliver every byte exactly.
//!
//! Linux-only and needs root (creates tun0 and configures addresses).
//! Run inside the Docker test container:
//!
//!     cargo test --release --test blocking_write -- --ignored --nocapture
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

#[test]
#[ignore] // needs root + a tun device
fn blocking_write_and_flush_deliver_exactly() {
    let mut iface = trust::Interface::new().expect("creating tun0 requires root");
    let mut listener = iface.bind(8002).expect("bind");
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

    const TOTAL: usize = 16 * 1024;
    let expected: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

    // kernel-side client with a deliberately small receive buffer, so the
    // sender can only finish if it honors window updates
    let expected_cl = expected.clone();
    let client = std::thread::spawn(move || {
        let mut c = std::net::TcpStream::connect("192.168.0.2:8002").expect("connect");
        let sz: libc::c_int = 4096;
        let r = unsafe {
            libc::setsockopt(
                c.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &sz as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(r, 0, "setsockopt SO_RCVBUF");
        c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let mut got = vec![0u8; expected_cl.len()];
        c.read_exact(&mut got).expect("read exactly");
        assert_eq!(got, expected_cl);
    });

    // 16KB through a 1024-byte send queue: write() must block repeatedly
    let mut stream = listener.accept().expect("accept");
    let mut written = 0;
    while written < TOTAL {
        let n = stream
            .write(&expected[written..])
            .expect("write blocks until there is room");
        written += n;
    }
    assert_eq!(written, TOTAL);
    stream.flush().expect("flush waits for all data to be ACKed");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");

    client.join().expect("client thread");
}
