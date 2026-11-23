use std::mem;
use std::os::raw::{c_int, c_ulong, c_void};

use super::{Fd, IFNAMSIZ, IfName, OsFailure, close, err, errno, safe_read_partial, safe_write, set_errno};
use crate::TUN_WRITE_TIMEOUT_MS;

const TUNSETIFF: c_ulong = 0x4004_54ca;
const SIOCSIFMTU: c_ulong = 0x8922;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

/// `struct ifreq`: the interface name followed by a union of which only the flags and MTU
/// members are used.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &[u8]) -> Self {
        let mut req = IfReq { name: [0; IFNAMSIZ], data: [0; 24] };
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len()).min(IFNAMSIZ - 1);
        req.name[..end].copy_from_slice(&name[..end]);
        req
    }
}

fn ioctl(fd: Fd, request: c_ulong, req: &mut IfReq) -> c_int {
    // SAFETY: `req` is a valid `ifreq`-sized buffer for the requests used here.
    unsafe { libc::ioctl(fd, request as _, std::ptr::from_mut(req).cast::<c_void>()) }
}

/// Opens `/dev/net/tun` and attaches a raw (no packet information) TUN interface.
pub fn tun_create(wanted: Option<&[u8]>) -> Result<(Fd, IfName), OsFailure> {
    // SAFETY: the path is NUL-terminated.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd == -1 {
        err(b"tun module not present. See https://sk.tl/2RdReigK\n");
        return Err(OsFailure);
    }
    let mut req = IfReq::new(wanted.unwrap_or(b""));
    req.data[..2].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    if ioctl(fd, TUNSETIFF, &mut req) != 0 {
        let e = errno();
        close(fd);
        set_errno(e);
        return Err(OsFailure);
    }
    let mut name = [0u8; IFNAMSIZ];
    let end = req.name.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ).min(IFNAMSIZ - 1);
    name[..end].copy_from_slice(&req.name[..end]);
    Ok((fd, name))
}

/// Sets the interface MTU through a throwaway datagram socket; 0 on success, -1 with `errno`
/// set otherwise.
pub fn tun_set_mtu(name: &IfName, mtu: i32) -> i32 {
    // SAFETY: plain integer arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd == -1 {
        return -1;
    }
    let mut req = IfReq::new(name);
    req.data[..mem::size_of::<c_int>()].copy_from_slice(&mtu.to_ne_bytes());
    if ioctl(fd, SIOCSIFMTU, &mut req) != 0 {
        close(fd);
        return -1;
    }
    close(fd)
}

pub fn tun_read(fd: Fd, buf: &mut [u8]) -> isize {
    safe_read_partial(fd, buf)
}

pub fn tun_write(fd: Fd, data: &[u8]) -> isize {
    safe_write(fd, data, TUN_WRITE_TIMEOUT_MS)
}
