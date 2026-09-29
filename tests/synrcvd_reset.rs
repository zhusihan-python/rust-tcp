//! Contract test for the SYN-RCVD reset form: an ACK that does not
//! acknowledge our SYN must be answered with a RST whose sequence number is
//! the offending ACK number and which carries no ACK flag (RFC 793 S3.4).
//!
//! The connection must still be pending (SYN-RCVD) when the bad ACK
//! arrives, so this test binds a listener and never accepts — the demo
//! server would race it into FIN-WAIT-1. The probe itself is a small scapy
//! script fed on stdin (no shell quoting); the kernel would answer our
//! SYN-ACK with its own RST (nothing listens on the client port) and kill
//! the connection under test, so those are dropped first. The userspace
//! stack writes below the OUTPUT chain and is unaffected.
//!
//! Linux-only, needs root AND scapy. Run inside the Docker test container:
//!
//!     cargo test --release --test synrcvd_reset -- --ignored --nocapture
#![cfg(target_os = "linux")]

use std::io::Write;
use std::time::Duration;

const PORT: u16 = 8005;
const CPORT: u16 = 42425;
const BAD_ACK: u32 = 424242;

fn probe() -> String {
    r#"
from scapy.all import IP, TCP, sr1, conf
conf.verb = 0
synack = sr1(IP(dst="192.168.0.2")/TCP(dport=__PORT__, sport=__CPORT__, flags="S", seq=1000, window=1024), timeout=5)
assert synack is not None and synack[TCP].flags == "SA", "no SYN-ACK: %s" % synack
rst = sr1(IP(dst="192.168.0.2")/TCP(dport=__PORT__, sport=__CPORT__, flags="A", seq=1001, ack=__BAD_ACK__), timeout=5)
assert rst is not None and "R" in rst[TCP].flags, "no RST for unacceptable ACK: %s" % rst
assert rst[TCP].seq == __BAD_ACK__, "RST seq %d must equal the offending ACK number" % rst[TCP].seq
assert "A" not in rst[TCP].flags, "RST must not carry the ACK flag"
print("SYN-RCVD reset form OK")
"#
    .replace("__PORT__", &PORT.to_string())
    .replace("__CPORT__", &CPORT.to_string())
    .replace("__BAD_ACK__", &BAD_ACK.to_string())
}

fn run(cmd: &str, args: &[&str]) {
    let st = std::process::Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("running {} failed: {}", cmd, e));
    assert!(st.success(), "{} {:?} failed", cmd, args);
}

#[test]
#[ignore] // needs root, a tun device and scapy
fn unacceptable_ack_in_syn_rcvd_gets_rfc793_reset() {
    let mut iface = trust::Interface::new().expect("creating tun0 requires root");
    let _listener = iface.bind(PORT).expect("bind");
    run("ip", &["addr", "add", "192.168.0.1/24", "dev", "tun0"]);
    run("ip", &["link", "set", "up", "dev", "tun0"]);
    run(
        "iptables",
        &[
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--sport",
            &CPORT.to_string(),
            "--tcp-flags",
            "RST",
            "RST",
            "-j",
            "DROP",
        ],
    );

    // let the stack settle, then probe: SYN -> SYN-ACK -> bad ACK -> RST
    std::thread::sleep(Duration::from_millis(500));
    let mut child = std::process::Command::new("python3")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("python3 (with scapy) is required");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(probe().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("waiting for python3");
    assert!(
        out.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    run(
        "iptables",
        &[
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--sport",
            &CPORT.to_string(),
            "--tcp-flags",
            "RST",
            "RST",
            "-j",
            "DROP",
        ],
    );
}
