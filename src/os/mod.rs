use std::ffi::{CStr, CString};
use std::fmt::{self, Write as _};
use std::mem;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::{self, CommandRunner, Os, RunError};
use crate::reorder::Timespec;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{tun_create, tun_read, tun_set_mtu, tun_write};

#[cfg(any(target_os = "macos", target_os = "openbsd", target_os = "freebsd", target_os = "netbsd", target_os = "dragonfly"))]
mod bsd;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{tun_create, tun_read, tun_set_mtu, tun_write};
#[cfg(any(target_os = "openbsd", target_os = "freebsd", target_os = "netbsd", target_os = "dragonfly"))]
pub use bsd::{tun_create, tun_read, tun_set_mtu, tun_write};
#[cfg(target_os = "openbsd")]
pub use bsd::pledge_runtime;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub use unsupported::{tun_create, tun_read, tun_set_mtu, tun_write};

pub const IFNAMSIZ: usize = 16;
pub const NI_MAXHOST: usize = 1025;
pub const SOCKET_BUFFER_BYTES: c_int = 4 * 1024 * 1024;

/// A failed OS operation; the cause is left in `errno`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsFailure;

pub type Fd = c_int;
/// Interface name as a NUL-terminated byte array, like the C `char[IFNAMSIZ]`.
pub type IfName = [u8; IFNAMSIZ];

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
mod unsupported {
    use super::{Fd, IfName, OsFailure};

    pub fn tun_create(_wanted: Option<&[u8]>) -> Result<(Fd, IfName), OsFailure> {
        super::err(b"twice: TUN devices are not supported on this operating system in this build\n");
        super::set_errno(libc::ENOSYS);
        Err(OsFailure)
    }

    pub fn tun_set_mtu(_name: &IfName, _mtu: i32) -> i32 {
        super::set_errno(libc::ENOSYS);
        -1
    }

    pub fn tun_read(_fd: Fd, _buf: &mut [u8]) -> isize {
        super::set_errno(libc::ENOSYS);
        -1
    }

    pub fn tun_write(_fd: Fd, _data: &[u8]) -> isize {
        super::set_errno(libc::ENOSYS);
        -1
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
mod stdio {
    // SAFETY: these are the C library's standard stream pointers, initialised before `main` and
    // never written by this program.
    unsafe extern "C" {
        #[cfg_attr(target_vendor = "apple", link_name = "__stdoutp")]
        safe static stdout: *mut libc::FILE;
        #[cfg_attr(target_vendor = "apple", link_name = "__stderrp")]
        safe static stderr: *mut libc::FILE;
    }

    pub fn out_stream() -> *mut libc::FILE {
        stdout
    }

    pub fn err_stream() -> *mut libc::FILE {
        stderr
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
mod stdio {
    use std::sync::atomic::{AtomicPtr, Ordering};

    fn stream(fd: libc::c_int, slot: &AtomicPtr<libc::FILE>) -> *mut libc::FILE {
        let current = slot.load(Ordering::Relaxed);
        if !current.is_null() {
            return current;
        }
        // SAFETY: the mode string is NUL-terminated and `fd` is a standard descriptor.
        let opened = unsafe { libc::fdopen(fd, c"w".as_ptr()) };
        slot.store(opened, Ordering::Relaxed);
        opened
    }

    pub fn out_stream() -> *mut libc::FILE {
        static SLOT: AtomicPtr<libc::FILE> = AtomicPtr::new(std::ptr::null_mut());
        stream(1, &SLOT)
    }

    pub fn err_stream() -> *mut libc::FILE {
        static SLOT: AtomicPtr<libc::FILE> = AtomicPtr::new(std::ptr::null_mut());
        let s = stream(2, &SLOT);
        // SAFETY: `s` is a valid stream; stderr is unbuffered as in the C program.
        unsafe { libc::setvbuf(s, std::ptr::null_mut(), libc::_IONBF, 0) };
        s
    }
}

fn write_stream(stream: *mut libc::FILE, bytes: &[u8]) {
    if bytes.is_empty() || stream.is_null() {
        return;
    }
    // SAFETY: `stream` is a valid open stdio stream and `bytes` is readable for its length.
    unsafe { libc::fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stream) };
}

/// Writes to stdout through stdio, which is line buffered on a terminal and fully buffered
/// otherwise, and flushed by `exit`.
pub fn out(bytes: &[u8]) {
    write_stream(stdio::out_stream(), bytes);
}

pub fn out_flush() {
    // SAFETY: the stream is a valid open stdio stream.
    unsafe { libc::fflush(stdio::out_stream()) };
}

pub fn err(bytes: &[u8]) {
    write_stream(stdio::err_stream(), bytes);
}

struct StackBuf {
    buf: [u8; 512],
    len: usize,
}

impl fmt::Write for StackBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let take = s.len().min(room);
        self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

/// Writes a short diagnostic to stderr without allocating.
pub fn err_display(message: &dyn fmt::Display) {
    let mut buf = StackBuf { buf: [0; 512], len: 0 };
    let _ = write!(buf, "{message}");
    err(&buf.buf[..buf.len]);
}

pub fn perror(prefix: &CStr) {
    // SAFETY: `prefix` is NUL-terminated.
    unsafe { libc::perror(prefix.as_ptr()) };
}

pub fn exit(code: i32) -> ! {
    // SAFETY: `exit` flushes stdio and terminates the process.
    unsafe { libc::exit(code) }
}

/// Restores the default SIGPIPE action that the Rust runtime replaces with "ignore", so child
/// processes and write errors behave as under the C program.
pub fn reset_sigpipe() {
    // SAFETY: installing the default disposition is always valid.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn set_errno(value: i32) {
    // SAFETY: the C library returns a valid thread-local errno location.
    unsafe { *errno_location() = value };
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "dragonfly"))]
unsafe fn errno_location() -> *mut c_int {
    // SAFETY: no preconditions.
    unsafe { libc::__errno_location() }
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
unsafe fn errno_location() -> *mut c_int {
    // SAFETY: no preconditions.
    unsafe { libc::__error() }
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
unsafe fn errno_location() -> *mut c_int {
    // SAFETY: no preconditions.
    unsafe { libc::__errno() }
}

pub fn strerror(errnum: i32) -> Vec<u8> {
    // SAFETY: `strerror` returns a valid NUL-terminated string that is copied before any other call.
    unsafe { CStr::from_ptr(libc::strerror(errnum)).to_bytes().to_vec() }
}

pub fn gai_strerror(code: i32) -> Vec<u8> {
    // SAFETY: `gai_strerror` returns a valid static NUL-terminated string.
    unsafe { CStr::from_ptr(libc::gai_strerror(code)).to_bytes().to_vec() }
}

static EXIT_SIGNAL: AtomicBool = AtomicBool::new(false);

pub fn exit_signal_received() -> bool {
    EXIT_SIGNAL.load(Ordering::SeqCst)
}

extern "C" fn on_exit_signal(sig: c_int) {
    // SAFETY: `signal` is async-signal-safe.
    unsafe { libc::signal(sig, libc::SIG_DFL) };
    EXIT_SIGNAL.store(true, Ordering::SeqCst);
}

/// First SIGINT or SIGTERM asks for a clean exit and puts the default action back.
pub fn install_exit_handlers() {
    let handler = on_exit_signal as extern "C" fn(c_int) as libc::sighandler_t;
    // SAFETY: the handler only calls `signal` and stores to an atomic.
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

pub fn monotonic() -> Timespec {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    #[allow(clippy::unnecessary_cast)] // timespec field widths differ across targets
    Timespec::new(ts.tv_sec as i64, ts.tv_nsec as i64)
}

pub fn sleep(seconds: u32) {
    // SAFETY: no preconditions.
    unsafe { libc::sleep(seconds) };
}

pub fn close(fd: Fd) -> i32 {
    // SAFETY: closing a descriptor has no memory-safety preconditions.
    unsafe { libc::close(fd) }
}

pub fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> i32 {
    // SAFETY: the pointer and length describe the slice.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) }
}

pub fn set_nonblocking(fd: Fd) {
    // SAFETY: `fcntl` with these commands takes only integers.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// `read` that retries `EINTR` until an exit signal arrives.
pub fn safe_read_partial(fd: Fd, buf: &mut [u8]) -> isize {
    loop {
        // SAFETY: the pointer and length describe the slice.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 && errno() == libc::EINTR && !exit_signal_received() {
            continue;
        }
        return n;
    }
}

/// Writes all of `data`, waiting up to `timeout_ms` when the descriptor would block.
pub fn safe_write(fd: Fd, data: &[u8], timeout_ms: i32) -> isize {
    let mut done = 0usize;
    while done < data.len() {
        let rest = &data[done..];
        // SAFETY: the pointer and length describe the slice.
        let written = unsafe { libc::write(fd, rest.as_ptr().cast(), rest.len()) };
        if written < 0 {
            let e = errno();
            if e == libc::EAGAIN {
                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                if poll(std::slice::from_mut(&mut pfd), timeout_ms) <= 0 {
                    return -1;
                }
            } else if e != libc::EINTR || exit_signal_received() {
                return -1;
            }
            continue;
        }
        done += written as usize;
    }
    done as isize
}

/// A socket address and its length, as the kernel filled it in.
#[derive(Clone, Copy)]
pub struct SockAddr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl SockAddr {
    /// No address.
    pub fn empty() -> Self {
        // SAFETY: `sockaddr_storage` is plain data for which all-zero bytes are valid.
        SockAddr { storage: unsafe { mem::zeroed() }, len: 0 }
    }

    /// A buffer ready to receive any address.
    pub fn for_receive() -> Self {
        let mut a = SockAddr::empty();
        a.len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        a
    }

    fn as_ptr(&self) -> *const libc::sockaddr {
        ptr::from_ref(&self.storage).cast()
    }
}

pub fn recv(fd: Fd, buf: &mut [u8]) -> isize {
    // SAFETY: the pointer and length describe the slice.
    unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) }
}

pub fn recv_from(fd: Fd, buf: &mut [u8], from: &mut SockAddr) -> isize {
    from.len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: the buffer and the address storage are valid for the lengths passed.
    unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            ptr::from_mut(&mut from.storage).cast(),
            &mut from.len,
        )
    }
}

pub fn send_to(fd: Fd, buf: &[u8], to: &SockAddr) -> isize {
    // SAFETY: the buffer and the address are valid for the lengths passed.
    unsafe { libc::sendto(fd, buf.as_ptr().cast(), buf.len(), 0, to.as_ptr(), to.len) }
}

fn iovecs(parts: &[&[u8]; 3]) -> [libc::iovec; 3] {
    parts.map(|p| libc::iovec { iov_base: p.as_ptr().cast_mut().cast(), iov_len: p.len() })
}

/// `writev` of three parts to a connected socket.
pub fn writev3(fd: Fd, parts: &[&[u8]; 3]) -> isize {
    let iov = iovecs(parts);
    // SAFETY: `iov` points at three buffers that outlive the call and are only read.
    unsafe { libc::writev(fd, iov.as_ptr(), 3) }
}

/// `sendmsg` of three parts to `to`.
pub fn sendmsg3(fd: Fd, to: &SockAddr, parts: &[&[u8]; 3]) -> isize {
    let mut iov = iovecs(parts);
    // SAFETY: all-zero bytes are a valid `msghdr`.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = to.as_ptr().cast_mut().cast();
    msg.msg_namelen = to.len;
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = 3;
    // SAFETY: the message describes live buffers that are only read.
    unsafe { libc::sendmsg(fd, &msg, 0) }
}

fn setsockopt_int(fd: Fd, level: c_int, name: c_int, value: c_int) {
    // SAFETY: the option value points at a live `c_int` of the length passed.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            ptr::from_ref(&value).cast::<c_void>(),
            mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
}

fn setsockopt_int_checked(fd: Fd, level: c_int, name: c_int, value: c_int) -> bool {
    // SAFETY: the option value points at a live `c_int` of the length passed.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            ptr::from_ref(&value).cast::<c_void>(),
            mem::size_of::<c_int>() as libc::socklen_t,
        ) == 0
    }
}

fn lookup(node: Option<&CStr>, service: Option<&CStr>, flags: c_int) -> (c_int, *mut libc::addrinfo) {
    lookup_family(node, service, flags, libc::AF_UNSPEC)
}

fn lookup_family(
    node: Option<&CStr>,
    service: Option<&CStr>,
    flags: c_int,
    family: c_int,
) -> (c_int, *mut libc::addrinfo) {
    // SAFETY: all-zero bytes are a valid `addrinfo` hint.
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_flags = flags;
    hints.ai_family = family;
    hints.ai_socktype = libc::SOCK_DGRAM;
    let mut res: *mut libc::addrinfo = ptr::null_mut();
    // SAFETY: the strings are NUL-terminated or null and the out pointer is valid.
    let eai = unsafe {
        libc::getaddrinfo(
            node.map_or(ptr::null(), CStr::as_ptr),
            service.map_or(ptr::null(), CStr::as_ptr),
            &hints,
            &mut res,
        )
    };
    (eai, res)
}

fn is_inet(res: *mut libc::addrinfo) -> bool {
    // SAFETY: `res` came from a successful `getaddrinfo`, so it is a valid list head.
    let family = unsafe { (*res).ai_family };
    family == libc::AF_INET || family == libc::AF_INET6
}

fn free_lookup(res: *mut libc::addrinfo) {
    // SAFETY: `res` came from `getaddrinfo` and is not used afterwards.
    unsafe { libc::freeaddrinfo(res) };
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// Opens and binds the server socket, printing `Listening on UDP` before the bind. Returns -1
/// with `errno` set on failure.
pub fn udp_server_socket(address: Option<&CStr>, port: &CStr) -> Fd {
    let family = if cfg!(any(target_os = "openbsd", target_os = "dragonfly")) && address.is_none() {
        libc::AF_INET
    } else {
        libc::AF_UNSPEC
    };
    let (eai, res) = lookup_family(address, Some(port), libc::AI_PASSIVE, family);
    if eai != 0 || !is_inet(res) {
        err(&join(&[b"Unable to create the UDP server socket: [".as_slice(), &gai_strerror(eai), b"]\n"]));
        set_errno(libc::EINVAL);
        return -1;
    }
    // SAFETY: `res` is a valid list head from `getaddrinfo`.
    let ai = unsafe { &*res };
    // SAFETY: plain integer arguments.
    let fd = unsafe { libc::socket(ai.ai_family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd == -1 || !setsockopt_int_checked(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1) {
        let e = errno();
        if fd != -1 {
            close(fd);
        }
        free_lookup(res);
        set_errno(e);
        return -1;
    }
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, SOCKET_BUFFER_BYTES);
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, SOCKET_BUFFER_BYTES);
    setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0);
    out(&join(&[
        b"Listening on UDP ".as_slice(),
        address.map_or(b"*".as_slice(), CStr::to_bytes),
        b":",
        port.to_bytes(),
        b"\n",
    ]));
    // SAFETY: the address and length come from `getaddrinfo`.
    let bound = unsafe { libc::bind(fd, ai.ai_addr, ai.ai_addrlen) };
    free_lookup(res);
    if bound != 0 {
        return -1;
    }
    fd
}

/// Opens a socket connected to the server, printing `Connecting to UDP` first. Returns -1 with
/// `errno` set on failure.
pub fn udp_client_socket(address: &CStr, port: &CStr) -> Fd {
    out(&join(&[b"Connecting to UDP ".as_slice(), address.to_bytes(), b":", port.to_bytes(), b"...\n"]));
    let (eai, res) = lookup(Some(address), Some(port), 0);
    if eai != 0 || !is_inet(res) {
        err(&join(&[b"Unable to create the UDP client socket: [".as_slice(), &gai_strerror(eai), b"]\n"]));
        set_errno(libc::EINVAL);
        return -1;
    }
    // SAFETY: `res` is a valid list head from `getaddrinfo`.
    let ai = unsafe { &*res };
    // SAFETY: plain integer arguments.
    let fd = unsafe { libc::socket(ai.ai_family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    // SAFETY: the address and length come from `getaddrinfo`.
    if fd == -1 || unsafe { libc::connect(fd, ai.ai_addr, ai.ai_addrlen) } != 0 {
        free_lookup(res);
        let e = errno();
        if fd != -1 {
            close(fd);
        }
        set_errno(e);
        return -1;
    }
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, SOCKET_BUFFER_BYTES);
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, SOCKET_BUFFER_BYTES);
    free_lookup(res);
    fd
}

fn c_prefix(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())]
}

/// The numeric host text of `addr`, empty when it cannot be rendered.
pub fn numeric_host(addr: &SockAddr) -> Vec<u8> {
    let mut host = vec![0u8; NI_MAXHOST];
    // SAFETY: the address and the host buffer are valid for the lengths passed.
    unsafe {
        libc::getnameinfo(
            addr.as_ptr(),
            addr.len,
            host.as_mut_ptr().cast::<c_char>(),
            NI_MAXHOST as _,
            ptr::null_mut(),
            0,
            libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        )
    };
    c_prefix(&host).to_vec()
}

/// Resolves a name to numeric text in a 64-byte buffer. On failure prints the C diagnostic and
/// returns `Err`.
pub fn resolve_ip(name: &CStr) -> Result<Vec<u8>, OsFailure> {
    let mut ip = [0u8; 64];
    let (mut eai, res) = lookup(Some(name), None, 0);
    if eai == 0 && is_inet(res) {
        // SAFETY: `res` is a valid list head and `ip` is valid for the length passed.
        eai = unsafe {
            libc::getnameinfo(
                (*res).ai_addr,
                (*res).ai_addrlen,
                ip.as_mut_ptr().cast::<c_char>(),
                ip.len() as _,
                ptr::null_mut(),
                0,
                libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
            )
        };
        if eai == 0 {
            free_lookup(res);
            return Ok(c_prefix(&ip).to_vec());
        }
    }
    err(&join(&[b"Unable to resolve [".as_slice(), name.to_bytes(), b"]: [", &gai_strerror(eai), b"]\n"]));
    if !res.is_null() {
        free_lookup(res);
    }
    Err(OsFailure)
}

/// Fills `buf` from `/dev/urandom`.
pub fn random_bytes(buf: &mut [u8]) -> bool {
    // SAFETY: the path is NUL-terminated.
    let fd = unsafe { libc::open(c"/dev/urandom".as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return false;
    }
    let mut total = 0usize;
    while total < buf.len() {
        let rest = &mut buf[total..];
        // SAFETY: the pointer and length describe the slice.
        let n = unsafe { libc::read(fd, rest.as_mut_ptr().cast(), rest.len()) };
        if n <= 0 {
            close(fd);
            return false;
        }
        total += n as usize;
    }
    close(fd);
    true
}

pub enum KeyRead {
    OpenFailed,
    Short,
    Loaded([u8; 32]),
}

/// Reads the first 32 bytes of a key file with stdio.
pub fn read_key_file(path: &CStr) -> KeyRead {
    // SAFETY: both strings are NUL-terminated.
    let fp = unsafe { libc::fopen(path.as_ptr(), c"rb".as_ptr()) };
    if fp.is_null() {
        return KeyRead::OpenFailed;
    }
    let mut key = [0u8; 32];
    // SAFETY: `key` is valid for 32 bytes and `fp` is an open stream.
    let n = unsafe { libc::fread(key.as_mut_ptr().cast(), 1, key.len(), fp) };
    // SAFETY: `fp` is an open stream that is not used afterwards.
    unsafe { libc::fclose(fp) };
    if n == key.len() { KeyRead::Loaded(key) } else { KeyRead::Short }
}

pub fn path_exists(path: &CStr) -> bool {
    // SAFETY: `path` is NUL-terminated.
    unsafe { libc::access(path.as_ptr(), libc::F_OK) == 0 }
}

pub enum CreateOutcome {
    CreateFailed,
    WriteFailed,
    Done,
}

/// `fopen(path, "wb")` and `fwrite`; a short write closes and removes the file.
pub fn write_new_file(path: &CStr, data: &[u8]) -> CreateOutcome {
    // SAFETY: both strings are NUL-terminated.
    let fp = unsafe { libc::fopen(path.as_ptr(), c"wb".as_ptr()) };
    if fp.is_null() {
        return CreateOutcome::CreateFailed;
    }
    // SAFETY: `data` is valid for its length and `fp` is an open stream.
    let written = unsafe { libc::fwrite(data.as_ptr().cast(), 1, data.len(), fp) };
    if written != data.len() {
        // SAFETY: `fp` is an open stream that is not used afterwards; `path` is NUL-terminated.
        unsafe {
            libc::fclose(fp);
            libc::unlink(path.as_ptr());
        }
        return CreateOutcome::WriteFailed;
    }
    // SAFETY: `fp` is an open stream that is not used afterwards.
    unsafe { libc::fclose(fp) };
    CreateOutcome::Done
}

pub fn chmod_private(path: &CStr) -> bool {
    // SAFETY: `path` is NUL-terminated.
    unsafe { libc::chmod(path.as_ptr(), 0o600) == 0 }
}

/// Runs argv with `fork`, `execvp` and `waitpid`.
pub struct Shell;

impl CommandRunner for Shell {
    fn run(&mut self, argv: &[Vec<u8>], silent: bool) -> Result<(), RunError> {
        set_errno(libc::ENOSPC);
        let owned: Vec<CString> =
            argv.iter().map(|a| CString::new(c_prefix(a)).unwrap_or_default()).collect();
        let mut ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(ptr::null());
        // SAFETY: the child below only calls async-signal-safe functions on data prepared before
        // the fork.
        let child = unsafe { libc::fork() };
        if child == -1 {
            return Err(RunError::Errno(errno()));
        }
        if child == 0 {
            // SAFETY: only descriptor calls, `execvp` on a NULL-terminated argv, and `_exit`.
            unsafe {
                if silent {
                    libc::dup2(libc::dup2(libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY), 2), 1);
                }
                libc::execvp(ptrs[0], ptrs.as_ptr());
                libc::_exit(1)
            }
        }
        let mut status: c_int = 0;
        // SAFETY: `status` is a valid out pointer.
        if unsafe { libc::waitpid(child, &mut status, 0) } == -1 {
            return Err(RunError::Errno(errno()));
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(RunError::Failed);
        }
        Ok(())
    }
}

/// First line of a shell pipeline's output, at most 63 bytes, with the trailing newline removed.
fn read_from_shell_command(command: &str) -> Option<Vec<u8>> {
    let command_c = CString::new(command).ok()?;
    // SAFETY: both strings are NUL-terminated.
    let fp = unsafe { libc::popen(command_c.as_ptr(), c"r".as_ptr()) };
    if fp.is_null() {
        return None;
    }
    let mut buf = [0u8; config::GATEWAY_BUFFER];
    // SAFETY: `buf` is valid for the length passed and `fp` is an open stream.
    let got = unsafe { libc::fgets(buf.as_mut_ptr().cast(), buf.len() as c_int, fp) };
    if got.is_null() {
        // SAFETY: `fp` came from `popen` and is not used afterwards.
        unsafe { libc::pclose(fp) };
        err(&config::command_failed_stderr(command));
        return None;
    }
    let mut line = c_prefix(&buf);
    if let Some(nl) = line.iter().rposition(|&b| b == b'\n') {
        line = &line[..nl];
    }
    let line = line.to_vec();
    // SAFETY: `fp` came from `popen` and is not used afterwards.
    unsafe { libc::pclose(fp) };
    if line.is_empty() { None } else { Some(line) }
}

pub fn default_gateway() -> Option<Vec<u8>> {
    read_from_shell_command(config::default_gateway_command(Os::host())?)
}

pub fn default_ext_if_name() -> Option<Vec<u8>> {
    read_from_shell_command(config::default_ext_if_command(Os::host())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_buffer_truncates_instead_of_growing() {
        let mut b = StackBuf { buf: [0; 512], len: 0 };
        write!(b, "{}", "x".repeat(600)).unwrap();
        assert_eq!(b.len, 512);
    }

    #[test]
    fn c_prefix_stops_at_the_first_nul() {
        assert_eq!(c_prefix(b"ab\0cd"), b"ab");
        assert_eq!(c_prefix(b"abcd"), b"abcd");
    }

    #[test]
    fn shell_runner_reports_exit_status() {
        let mut shell = Shell;
        assert_eq!(shell.run(&[b"true".to_vec()], true), Ok(()));
        assert_eq!(shell.run(&[b"false".to_vec()], true), Err(RunError::Failed));
    }

    #[test]
    fn gateway_command_output_is_trimmed_to_a_line() {
        assert_eq!(read_from_shell_command("printf '10.0.0.1\\nrest'"), Some(b"10.0.0.1".to_vec()));
        assert_eq!(read_from_shell_command("printf '\\n'"), None);
        assert_eq!(read_from_shell_command("true"), None);
    }
}
