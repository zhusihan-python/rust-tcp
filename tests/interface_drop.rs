//! Tests that need to create a real TUN/utun interface, and therefore root.
//! They are ignored by default; run them with:
//!
//!     sudo cargo test --test interface_drop -- --ignored
//!
//! (or inside the Docker test container, where the test runs as root)

use std::time::Duration;

#[test]
#[ignore] // needs root to create the interface
fn interface_drop_terminates_packet_loop() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut iface = trust::Interface::new().expect("creating the interface requires root");
        let _listener = iface.bind(8000).expect("bind");
        drop(_listener);
        drop(iface);
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("dropping the Interface did not terminate the packet loop within 5s");
}
