//! Minimal macOS utun bindings.
//!
//! macOS has no /dev/net/tun. Virtual point-to-point IP interfaces (utun) are
//! created by connecting a PF_SYSTEM/SYSPROTO_CONTROL socket to the
//! "com.apple.net.utun_control" kernel control. Unlike Linux TUN opened with
//! IFF_NO_PI, every packet read from or written to such a socket is prefixed
//! with a 4-byte address-family header (network byte order) that cannot be
//! turned off. This wrapper strips and re-adds that header so that the rest of
//! this crate sees raw IP packets, just like the Linux code path.
//!
//! Layout constants mirror <sys/kern_control.h> and <sys/socket.h>, which the
//! libc crate does not expose portably across versions.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

/// AF_SYSTEM from <sys/socket.h> on Darwin.
const AF_SYSTEM: libc::c_int = 32;
/// SYSPROTO_CONTROL: protocol used to talk to kernel controls.
const SYSPROTO_CONTROL: libc::c_int = 2;
/// AF_SYS_CONTROL: address of a specific kernel control within AF_SYSTEM.
const AF_SYS_CONTROL: u16 = 2;
/// _IOWR('N', 3, struct ctl_info): look up a kernel control's dynamic id by name.
const CTLIOCGINFO: libc::c_ulong = 0xC064_4E03;
/// Name of the utun kernel control.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

/// struct ctl_info from <sys/kern_control.h>.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

/// struct sockaddr_ctl from <sys/kern_control.h>.
///
/// Modern SDKs pad this to 32 bytes with `sc_reserved[5]`; the kernel rejects
/// connects whose `sc_len` does not equal `sizeof(struct sockaddr_ctl)`, so the
/// padding field must be present.
#[repr(C)]
struct SockAddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

/// A utun interface. Plays the same role as `tun_tap::Iface` on Linux.
pub struct Iface {
    fd: libc::c_int,
    /// scratch space for prepending the 4-byte header on send.
    out: [u8; 1504],
}

impl Iface {
    /// Create a utun interface, taking the first free unit from utun9 upwards.
    pub fn new() -> io::Result<Self> {
        unsafe {
            let fd = libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // the control id is assigned dynamically at boot, so look it up by name
            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0; 96],
            };
            info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
            if libc::ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }

            // connecting to control unit N+1 creates utunN; try units until one is free
            for unit in 9u32.. {
                let addr = SockAddrCtl {
                    sc_len: std::mem::size_of::<SockAddrCtl>() as u8,
                    sc_family: AF_SYSTEM as u8,
                    ss_sysaddr: AF_SYS_CONTROL,
                    sc_id: info.ctl_id,
                    sc_unit: unit + 1,
                    sc_reserved: [0; 5],
                };
                if libc::connect(
                    fd,
                    &addr as *const SockAddrCtl as *const libc::sockaddr,
                    std::mem::size_of::<SockAddrCtl>() as libc::socklen_t,
                ) == 0
                {
                    eprintln!("created utun interface utun{}", unit);
                    return Ok(Iface { fd, out: [0; 1504] });
                }
                let e = io::Error::last_os_error();
                // no point trying other units if we are not allowed to create one at all
                if e.kind() == io::ErrorKind::PermissionDenied || unit == 24 {
                    libc::close(fd);
                    return Err(e);
                }
            }
            unreachable!()
        }
    }

    /// Read one IP packet, with the 4-byte protocol header removed.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            // one SOCK_DGRAM read = 4-byte header + exactly one IP packet
            let n = libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short read from utun",
                ));
            }
            buf.copy_within(4..n, 0);
            Ok(n - 4)
        }
    }

    /// Write one IP packet, with the 4-byte protocol header added back.
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() + 4 > self.out.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for utun",
            ));
        }
        // XNU's utun_ctl_send() ntohl()-swaps these four bytes, and
        // utun_output() htonl()-swaps them on the way out: the ABI is
        // network byte order, not host byte order
        self.out[..4].copy_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        self.out[4..4 + buf.len()].copy_from_slice(buf);
        let n = unsafe {
            libc::write(
                self.fd,
                self.out.as_ptr() as *const libc::c_void,
                4 + buf.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            // report payload bytes handed to the kernel, header excluded
            Ok(n as usize - 4)
        }
    }
}

impl AsRawFd for Iface {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Iface {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
