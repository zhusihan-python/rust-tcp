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
use std::time::Duration;

#[test]
#[ignore] // needs root + a tun device
fn blocking_write_and_flush_deliver_exactly() {
    // watchdog: a failed client must not leave this test hanging on accept()
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(run()).unwrap();
    });
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(()) => {}
        Err(_) => panic!("blocking_write did not finish within 120s"),
    }
}

fn run() {
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

    // kernel-side client with a deliberately small receive buffer — set
    // BEFORE connect so even the SYN advertises a small window — that does
    // not read for a while: the sender must stall on the closed window and
    // can only finish if it honors the window updates on our ACKs
    let expected_cl = expected.clone();
    let client = std::thread::spawn(move || {
        use std::os::unix::io::FromRawFd;
        let fd = unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            assert!(fd >= 0, "socket");
            let sz: libc::c_int = 2048;
            let r = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &sz as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            assert_eq!(r, 0, "setsockopt SO_RCVBUF");
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 8002u16.to_be(),
                sin_addr: libc::in_addr {
                    // s_addr must hold the address bytes in network order in
                    // memory, i.e. from_le_bytes on little-endian hosts
                    s_addr: u32::from_le_bytes([192, 168, 0, 2]),
                },
                sin_zero: [0; 8],
            };
            let r = libc::connect(
                fd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            assert_eq!(r, 0, "connect");
            fd
        };
        let mut c = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        c.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
        // let the sender fill the small window and stall before we read
        std::thread::sleep(Duration::from_secs(3));
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
