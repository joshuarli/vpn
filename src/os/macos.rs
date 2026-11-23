use std::ffi::CString;
use std::mem;
use std::os::raw::{c_char, c_uint, c_void};

use super::{Fd, IFNAMSIZ, IfName, OsFailure, c_prefix, close, errno, set_errno};
pub use super::bsd::{tun_read, tun_set_mtu, tun_write};
use super::bsd::wanted_name;

const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

/// Reads the unit number the way C does, with `sscanf(name, "utun%u", &id)`.
fn utun_id(name: &[u8]) -> Option<u32> {
    let name = CString::new(c_prefix(name)).ok()?;
    let mut id: c_uint = 0;
    // SAFETY: the subject and format are NUL-terminated and `id` is a live `unsigned int`.
    let matched = unsafe { libc::sscanf(name.as_ptr(), c"utun%u".as_ptr(), &mut id as *mut c_uint) };
    (matched == 1).then_some(id)
}

fn tun_create_by_id(id: u32) -> Result<(Fd, IfName), OsFailure> {
    // SAFETY: plain integer arguments.
    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd == -1 {
        return Err(OsFailure);
    }
    // SAFETY: all-zero bytes are a valid `ctl_info`.
    let mut info: libc::ctl_info = unsafe { mem::zeroed() };
    for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *dst = *src as c_char;
    }
    // SAFETY: `info` is a live `ctl_info`, the type `CTLIOCGINFO` reads and fills.
    if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, std::ptr::from_mut(&mut info).cast::<c_void>()) } != 0 {
        let e = errno();
        close(fd);
        set_errno(e);
        return Err(OsFailure);
    }
    // SAFETY: all-zero bytes are a valid `sockaddr_ctl`.
    let mut sc: libc::sockaddr_ctl = unsafe { mem::zeroed() };
    sc.sc_id = info.ctl_id;
    sc.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
    sc.sc_family = libc::AF_SYSTEM as u8;
    sc.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    sc.sc_unit = id.wrapping_add(1);
    // SAFETY: `sc` is a live `sockaddr_ctl` and the length passed is its size.
    let connected = unsafe {
        libc::connect(
            fd,
            std::ptr::from_ref(&sc).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if connected != 0 {
        let e = errno();
        close(fd);
        set_errno(e);
        return Err(OsFailure);
    }
    let mut name = [0u8; IFNAMSIZ];
    let text = format!("utun{id}");
    name[..text.len()].copy_from_slice(text.as_bytes());
    Ok((fd, name))
}

/// Attaches a utun device: the first free `utun0` to `utun31`, or the one named.
pub fn tun_create(wanted: Option<&[u8]>) -> Result<(Fd, IfName), OsFailure> {
    match wanted_name(wanted) {
        None => {
            for id in 0..32 {
                if let Ok(created) = tun_create_by_id(id) {
                    return Ok(created);
                }
            }
            Err(OsFailure)
        }
        Some(name) => match utun_id(name) {
            Some(id) => tun_create_by_id(id),
            None => {
                set_errno(libc::EINVAL);
                Err(OsFailure)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_parsed_with_scanf_rules() {
        assert_eq!(utun_id(b"utun7"), Some(7));
        assert_eq!(utun_id(b"utun12abc"), Some(12));
        assert_eq!(utun_id(b"utun"), None);
        assert_eq!(utun_id(b"tun0"), None);
        assert_eq!(utun_id(b"utun3\0utun9"), Some(3));
    }

    #[test]
    fn a_name_that_is_not_utun_is_invalid() {
        set_errno(0);
        assert_eq!(tun_create(Some(b"tun0")), Err(OsFailure));
        assert_eq!(errno(), libc::EINVAL);
    }
}
