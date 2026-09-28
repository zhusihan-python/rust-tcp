//! Contract test for RST semantics: a reset must surface as
//! ConnectionReset for as long as a TcpStream handle exists, NOT turn
//! into ConnectionAborted once the reclaimer sweeps the connection map.
//!
//! Linux-only and needs root (creates tun0 and configures addresses).
//! Run inside the Docker test container:
//!
//!     cargo test --release --test rst_semantics -- --ignored --nocapture
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::time::Duration;

#[test]
#[ignore] // needs root + a tun device
fn reset_survives_reclamation_delay() {
    let mut iface = trust::Interface::new().expect("creating tun0 requires root");
    let mut listener = iface.bind(8001).expect("bind");
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

    // kernel-side client: connects, reads the greeting, then aborts with RST
    let client = std::thread::spawn(|| {
        use std::os::unix::io::AsRawFd;
        let mut c =
            std::net::TcpStream::connect("192.168.0.2:8001").expect("client connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).expect("client reads greeting");
        assert_eq!(&buf[..n], b"hello from rust-tcp!\n");
        // SO_LINGER 0 => close() sends RST instead of FIN
        let ling = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let r = unsafe {
            libc::setsockopt(
                c.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &ling as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(r, 0, "setsockopt SO_LINGER");
        drop(c);
    });

    let mut stream = listener.accept().expect("accept");
    stream
        .write(b"hello from rust-tcp!\n")
        .expect("server writes greeting");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");

    client.join().expect("client thread");

    // hold the stream idle well past the 10ms reclaim window (and the
    // 10s TIME_WAIT): a read now must still report the reset precisely,
    // not "stream was terminated unexpectedly"
    std::thread::sleep(Duration::from_secs(15));
    let mut buf = [0u8; 16];
    match stream.read(&mut buf) {
        Ok(n) => panic!("expected ConnectionReset, got Ok({})", n),
        Err(e) => {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset,
                "expected ConnectionReset, got {:?} ({})",
                e.kind(),
                e
            );
        }
    }
}
