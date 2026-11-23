//! TUN backends for the BSD family. macOS shares the framing, read, write and MTU code and only
//! differs in how the device is created.

#[cfg(not(target_os = "macos"))]
use std::ffi::CString;
use std::mem;
use std::os::raw::{c_int, c_ulong, c_void};

use super::{Fd, IFNAMSIZ, IfName, c_prefix, close};
#[cfg(not(target_os = "macos"))]
use super::OsFailure;
#[cfg(any(target_os = "macos", target_os = "openbsd"))]
use super::set_errno;
#[cfg(not(any(target_os = "macos", target_os = "openbsd")))]
use super::{safe_read_partial, safe_write};
#[cfg(not(any(target_os = "macos", target_os = "openbsd")))]
use crate::TUN_WRITE_TIMEOUT_MS;

/// `_IOW('i', 52, struct ifreq)` with the 32-byte `struct ifreq` of every BSD and macOS.
const SIOCSIFMTU: c_ulong = 0x8020_6934;

/// `struct ifreq`: the interface name followed by a union of which only the MTU member is used.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    data: [u8; 16],
}

const _: () = assert!(mem::size_of::<IfReq>() == 32);

/// The part of `wanted` before any NUL, or `None` when C would treat it as unset (`NULL` or an
/// empty string).
pub(super) fn wanted_name(wanted: Option<&[u8]>) -> Option<&[u8]> {
    wanted.map(c_prefix).filter(|name| !name.is_empty())
}

/// `snprintf(if_name, IFNAMSIZ, "%s", name)`.
fn if_name_from(name: &[u8]) -> IfName {
    let mut out = [0u8; IFNAMSIZ];
    let end = c_prefix(name).len().min(IFNAMSIZ - 1);
    out[..end].copy_from_slice(&name[..end]);
    out
}

/// Sets the interface MTU through a throwaway datagram socket; 0 on success, -1 with `errno`
/// set otherwise.
pub fn tun_set_mtu(name: &IfName, mtu: i32) -> i32 {
    // SAFETY: plain integer arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd == -1 {
        return -1;
    }
    let mut req = IfReq { name: if_name_from(name), data: [0; 16] };
    req.data[..mem::size_of::<c_int>()].copy_from_slice(&mtu.to_ne_bytes());
    // SAFETY: `req` is a live, correctly sized `ifreq` for this request.
    if unsafe { libc::ioctl(fd, SIOCSIFMTU as _, std::ptr::from_mut(&mut req).cast::<c_void>()) } != 0 {
        close(fd);
        return -1;
    }
    close(fd)
}

/// The `/dev/<name>` path truncated to the 64-byte buffer C formats it into.
#[cfg(not(target_os = "macos"))]
fn device_path(name: &[u8]) -> CString {
    let mut path = b"/dev/".to_vec();
    path.extend_from_slice(c_prefix(name));
    path.truncate(63);
    CString::new(path).unwrap_or_default()
}

/// Opens `/dev/tunN`, trying `tun0` to `tun31` when no name is wanted.
#[cfg(not(target_os = "macos"))]
pub fn tun_create(wanted: Option<&[u8]>) -> Result<(Fd, IfName), OsFailure> {
    let open = |name: &[u8]| -> Fd {
        let path = device_path(name);
        // SAFETY: `path` is NUL-terminated.
        unsafe { libc::open(path.as_ptr(), libc::O_RDWR) }
    };
    match wanted_name(wanted) {
        None => {
            for id in 0..32u32 {
                let name = format!("tun{id}");
                let fd = open(name.as_bytes());
                if fd != -1 {
                    return Ok((fd, if_name_from(name.as_bytes())));
                }
            }
            Err(OsFailure)
        }
        Some(name) => {
            let fd = open(name);
            if fd == -1 { Err(OsFailure) } else { Ok((fd, if_name_from(name))) }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "openbsd", test))]
mod frame {
    pub const FAMILY_LEN: usize = 4;
    const MIN_PACKET_WRITE: usize = 20;

    /// The 4-byte address family header that precedes a packet written to the device.
    #[derive(Debug, PartialEq, Eq)]
    pub enum FrameOut {
        TooShort,
        UnknownVersion,
        Family([u8; FAMILY_LEN]),
    }

    /// Chooses the header for an outbound packet from its IP version nibble: `htonl(AF_INET)` or
    /// `htonl(AF_INET6)`.
    pub fn frame_out(packet: &[u8]) -> FrameOut {
        if packet.len() < MIN_PACKET_WRITE {
            return FrameOut::TooShort;
        }
        match packet[0] >> 4 {
            4 => FrameOut::Family((libc::AF_INET as u32).to_be_bytes()),
            6 => FrameOut::Family((libc::AF_INET6 as u32).to_be_bytes()),
            _ => FrameOut::UnknownVersion,
        }
    }

    /// Maps a `readv` result over header plus payload to the payload length: errors and end of file
    /// are -1, a header alone is 0.
    pub fn frame_in(readv_result: isize) -> isize {
        if readv_result <= 0 {
            return -1;
        }
        if readv_result <= FAMILY_LEN as isize {
            return 0;
        }
        readv_result - FAMILY_LEN as isize
    }

    /// Maps a `writev` result over header plus payload to the payload length.
    pub fn frame_written(writev_result: isize) -> isize {
        if writev_result <= 0 {
            return writev_result;
        }
        if writev_result <= FAMILY_LEN as isize {
            return 0;
        }
        writev_result - FAMILY_LEN as isize
    }
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
use frame::{FAMILY_LEN, FrameOut, frame_in, frame_out, frame_written};

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
pub fn tun_read(fd: Fd, buf: &mut [u8]) -> isize {
    let mut family = [0u8; FAMILY_LEN];
    let iov = [
        libc::iovec { iov_base: family.as_mut_ptr().cast(), iov_len: FAMILY_LEN },
        libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() },
    ];
    // SAFETY: both iovecs describe writable buffers that outlive the call.
    frame_in(unsafe { libc::readv(fd, iov.as_ptr(), 2) })
}

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
pub fn tun_write(fd: Fd, data: &[u8]) -> isize {
    let mut family = match frame_out(data) {
        FrameOut::TooShort => return 0,
        FrameOut::UnknownVersion => {
            set_errno(libc::EINVAL);
            return -1;
        }
        FrameOut::Family(family) => family,
    };
    let iov = [
        libc::iovec { iov_base: family.as_mut_ptr().cast(), iov_len: FAMILY_LEN },
        libc::iovec { iov_base: data.as_ptr().cast_mut().cast(), iov_len: data.len() },
    ];
    // SAFETY: both iovecs describe buffers that outlive the call and are only read.
    frame_written(unsafe { libc::writev(fd, iov.as_ptr(), 2) })
}

#[cfg(not(any(target_os = "macos", target_os = "openbsd")))]
pub fn tun_read(fd: Fd, buf: &mut [u8]) -> isize {
    safe_read_partial(fd, buf)
}

#[cfg(not(any(target_os = "macos", target_os = "openbsd")))]
pub fn tun_write(fd: Fd, data: &[u8]) -> isize {
    safe_write(fd, data, TUN_WRITE_TIMEOUT_MS)
}

/// Restricts the process to the promises the tunnel needs once the device is configured.
#[cfg(target_os = "openbsd")]
pub fn pledge_runtime() {
    // SAFETY: both arguments are NUL-terminated or null.
    unsafe { libc::pledge(c"stdio proc exec dns inet pf error".as_ptr(), std::ptr::null()) };
}

#[cfg(test)]
mod tests {
    use super::frame::{FrameOut, frame_in, frame_out, frame_written};
    use super::*;

    #[test]
    fn short_writes_are_dropped_without_a_header() {
        assert_eq!(frame_out(&[]), FrameOut::TooShort);
        assert_eq!(frame_out(&[0x45; 19]), FrameOut::TooShort);
        assert_eq!(frame_out(&[0x45; 20]), FrameOut::Family((libc::AF_INET as u32).to_be_bytes()));
    }

    #[test]
    fn the_ip_version_nibble_selects_the_family() {
        let mut packet = [0u8; 40];
        packet[0] = 0x4f;
        assert_eq!(frame_out(&packet), FrameOut::Family((libc::AF_INET as u32).to_be_bytes()));
        packet[0] = 0x60;
        assert_eq!(frame_out(&packet), FrameOut::Family((libc::AF_INET6 as u32).to_be_bytes()));
        for first in [0x00, 0x30, 0x50, 0x70, 0xf5] {
            packet[0] = first;
            assert_eq!(frame_out(&packet), FrameOut::UnknownVersion, "first byte {first:#x}");
        }
    }

    #[test]
    fn the_header_is_network_order() {
        let FrameOut::Family(header) = frame_out(&[0x45; 20]) else { panic!("no header") };
        assert_eq!(header, [0, 0, 0, libc::AF_INET as u8]);
    }

    #[test]
    fn read_results_map_to_payload_lengths() {
        assert_eq!(frame_in(-1), -1);
        assert_eq!(frame_in(0), -1);
        assert_eq!(frame_in(1), 0);
        assert_eq!(frame_in(4), 0);
        assert_eq!(frame_in(5), 1);
        assert_eq!(frame_in(24), 20);
    }

    #[test]
    fn write_results_map_to_payload_lengths() {
        assert_eq!(frame_written(-1), -1);
        assert_eq!(frame_written(0), 0);
        assert_eq!(frame_written(3), 0);
        assert_eq!(frame_written(4), 0);
        assert_eq!(frame_written(24), 20);
    }

    #[test]
    fn names_are_truncated_like_snprintf() {
        assert_eq!(wanted_name(None), None);
        assert_eq!(wanted_name(Some(b"")), None);
        assert_eq!(wanted_name(Some(b"\0tun1")), None);
        assert_eq!(wanted_name(Some(b"tun1\0x")), Some(b"tun1".as_slice()));
        let long = if_name_from(b"abcdefghijklmnopqrstuvwxyz");
        assert_eq!(&long[..15], b"abcdefghijklmno");
        assert_eq!(long[15], 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn device_paths_fit_the_c_buffer() {
        assert_eq!(device_path(b"tun3").as_bytes(), b"/dev/tun3");
        assert_eq!(device_path(&[b'x'; 100]).as_bytes().len(), 63);
    }

    #[cfg(any(target_os = "macos", target_os = "openbsd"))]
    mod socketpair {
        use super::*;
        use crate::os::{errno, set_errno};

        fn pair() -> (Fd, Fd) {
            let mut fds = [0 as c_int; 2];
            // SAFETY: `fds` is a valid two-element out array.
            let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0);
            (fds[0], fds[1])
        }

        fn send(fd: Fd, bytes: &[u8]) {
            // SAFETY: the pointer and length describe the slice.
            let n = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), 0) };
            assert_eq!(n, bytes.len() as isize);
        }

        fn recv_datagram(fd: Fd) -> Vec<u8> {
            let mut buf = [0u8; 2048];
            // SAFETY: the pointer and length describe the buffer; `MSG_DONTWAIT` keeps a bug from hanging.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            assert!(n >= 0, "no datagram queued");
            buf[..n as usize].to_vec()
        }

        fn nothing_queued(fd: Fd) -> bool {
            let mut buf = [0u8; 8];
            // SAFETY: the pointer and length describe the buffer.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            n < 0 && errno() == libc::EAGAIN
        }

        fn packet(first: u8, len: usize) -> Vec<u8> {
            let mut p: Vec<u8> = (0..len).map(|i| i as u8).collect();
            p[0] = first;
            p
        }

        #[test]
        fn write_prepends_the_family_and_reports_the_payload() {
            let (tun, peer) = pair();
            let v4 = packet(0x45, 60);
            assert_eq!(tun_write(tun, &v4), 60);
            let sent = recv_datagram(peer);
            assert_eq!(&sent[..4], &(libc::AF_INET as u32).to_be_bytes());
            assert_eq!(&sent[4..], v4.as_slice());

            let v6 = packet(0x60, 40);
            assert_eq!(tun_write(tun, &v6), 40);
            let sent = recv_datagram(peer);
            assert_eq!(&sent[..4], &(libc::AF_INET6 as u32).to_be_bytes());
            assert_eq!(&sent[4..], v6.as_slice());
            close(tun);
            close(peer);
        }

        #[test]
        fn short_or_unknown_writes_touch_nothing() {
            let (tun, peer) = pair();
            assert_eq!(tun_write(tun, &packet(0x45, 19)), 0);
            assert_eq!(tun_write(tun, &[]), 0);
            assert!(nothing_queued(peer));
            set_errno(0);
            assert_eq!(tun_write(tun, &packet(0x95, 40)), -1);
            assert_eq!(errno(), libc::EINVAL);
            assert!(nothing_queued(peer));
            close(tun);
            close(peer);
        }

        #[test]
        fn write_to_a_closed_descriptor_fails() {
            let (tun, peer) = pair();
            close(peer);
            close(tun);
            assert_eq!(tun_write(tun, &packet(0x45, 40)), -1);
        }

        #[test]
        fn read_strips_the_header() {
            let (tun, peer) = pair();
            let body = packet(0x45, 60);
            let mut datagram = (libc::AF_INET as u32).to_be_bytes().to_vec();
            datagram.extend_from_slice(&body);
            send(peer, &datagram);
            let mut buf = [0u8; 2048];
            assert_eq!(tun_read(tun, &mut buf), 60);
            assert_eq!(&buf[..60], body.as_slice());
            close(tun);
            close(peer);
        }

        #[test]
        fn header_only_reads_return_zero() {
            let (tun, peer) = pair();
            send(peer, &(libc::AF_INET as u32).to_be_bytes());
            send(peer, &[1, 2]);
            let mut buf = [0u8; 64];
            assert_eq!(tun_read(tun, &mut buf), 0);
            assert_eq!(tun_read(tun, &mut buf), 0);
            close(tun);
            close(peer);
        }

        #[test]
        fn empty_datagrams_and_errors_return_minus_one() {
            let (tun, peer) = pair();
            send(peer, &[]);
            let mut buf = [0u8; 64];
            assert_eq!(tun_read(tun, &mut buf), -1);
            close(tun);
            close(peer);
            assert_eq!(tun_read(tun, &mut buf), -1);
        }

        #[test]
        fn reads_into_a_small_buffer_are_truncated_to_it() {
            let (tun, peer) = pair();
            let mut datagram = (libc::AF_INET6 as u32).to_be_bytes().to_vec();
            datagram.extend_from_slice(&packet(0x60, 40));
            send(peer, &datagram);
            let mut buf = [0u8; 10];
            assert_eq!(tun_read(tun, &mut buf), 10);
            assert_eq!(buf[0], 0x60);
            close(tun);
            close(peer);
        }
    }
}
