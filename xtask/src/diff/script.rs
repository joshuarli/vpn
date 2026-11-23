use super::case::{Header, Input, Kind};
use crate::util::Result;

const ERRNOS: &[(&str, i32)] = &[
    ("EPERM", 1),
    ("ENOENT", 2),
    ("EINTR", 4),
    ("EIO", 5),
    ("EBADF", 9),
    ("EAGAIN", 11),
    ("EWOULDBLOCK", 11),
    ("ENOMEM", 12),
    ("EACCES", 13),
    ("EEXIST", 17),
    ("ENODEV", 19),
    ("EINVAL", 22),
    ("EMFILE", 24),
    ("ENOTTY", 25),
    ("ENOSPC", 28),
    ("EPIPE", 32),
    ("EPROTO", 71),
    ("EMSGSIZE", 90),
    ("EDESTADDRREQ", 89),
    ("EADDRINUSE", 98),
    ("ENETDOWN", 100),
    ("ENETUNREACH", 101),
    ("ENOBUFS", 105),
    ("ENOTCONN", 107),
    ("ECONNREFUSED", 111),
    ("EHOSTUNREACH", 113),
    ("EAI_NONAME", -2),
    ("EAI_AGAIN", -3),
    ("EAI_FAIL", -4),
    ("EAI_FAMILY", -6),
    ("EAI_SERVICE", -8),
    ("EAI_MEMORY", -10),
    ("EAI_SYSTEM", -11),
    ("EAI_OVERFLOW", -12),
];

const SIGNALS: &[(&str, u32)] =
    &[("SIGHUP", 1), ("SIGINT", 2), ("SIGQUIT", 3), ("SIGUSR1", 10), ("SIGUSR2", 12), ("SIGTERM", 15)];

const REVENTS: &[(&str, u32)] = &[("POLLIN", 1), ("POLLERR", 8), ("POLLHUP", 16), ("POLLNVAL", 32)];

const DEFAULT_TAIL_MS: u64 = 3000;
const HANG_SLACK_MS: u64 = 600_000;

fn hexs(s: &str) -> String {
    if s.is_empty() {
        return "-".to_owned();
    }
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn opt_hex(s: &str) -> String {
    if s.is_empty() { "-".to_owned() } else { s.to_owned() }
}

fn check_hex(what: &str, s: &str) -> Result<()> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{what}: not an even-length hex string: {s:?}"));
    }
    Ok(())
}

pub fn errno_value(name: &str) -> Result<i32> {
    if let Ok(n) = name.parse::<i32>() {
        return Ok(n);
    }
    ERRNOS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("unknown errno name {name}"))
}

pub fn signal_number(name: &str) -> Result<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Ok(n);
    }
    SIGNALS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("unknown signal {name}"))
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    check_hex("hex", s)?;
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn encode_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn effective_end(header: &Header, inputs: &[Input]) -> u64 {
    header.end_ms.unwrap_or_else(|| inputs.iter().map(|i| i.t_ms).max().unwrap_or(0) + DEFAULT_TAIL_MS)
}

pub fn compile(header: &Header, inputs: &[Input], verbose: bool) -> Result<String> {
    let mut out = String::new();
    out.push_str(&format!("seed {}\n", header.seed));
    if let Some(p) = &header.urandom_prefix {
        check_hex("urandom_prefix", p)?;
        out.push_str(&format!("urandom_prefix {}\n", opt_hex(p)));
    }
    match &header.key {
        Some(k) => {
            if k.len() != 64 {
                return Err(format!("key must be 64 hex characters, got {}", k.len()));
            }
            check_hex("key", k)?;
            out.push_str(&format!("key {k}\n"));
        }
        None => out.push_str("key -\n"),
    }
    if let Some(n) = &header.tun_name {
        out.push_str(&format!("tun_name {}\n", hexs(n)));
    }
    if let Some(p) = &header.passive {
        out.push_str(&format!("passive {}\n", hexs(p)));
    }
    out.push_str(&format!("verbose {}\n", u8::from(verbose || header.calls)));
    for (name, value) in &header.dns {
        out.push_str(&format!("dns {} {}\n", hexs(name), hexs(value)));
    }
    for e in &header.errors {
        let fd = e.fd.as_deref().unwrap_or("-");
        if !matches!(fd, "-" | "tun" | "udp" | "urandom") {
            return Err(format!("error rule fd must be tun|udp|urandom, got {fd}"));
        }
        let errno = match &e.errno {
            Some(n) => errno_value(n)?,
            None => 0,
        };
        if errno == 0 && e.short.is_none() {
            return Err(format!("error rule for {} needs errno or short", e.call));
        }
        out.push_str(&format!(
            "err {} {} {} {} {} {} {}\n",
            e.call,
            fd,
            e.path.as_deref().map_or("-".to_owned(), hexs),
            e.nth.max(1),
            e.count,
            errno,
            e.short.unwrap_or(-1)
        ));
    }
    let defaults = [
        ("popen", Some("print $3"), 0, 0, "192.0.2.1\n"),
        ("popen", Some("print $5"), 0, 0, "eth0\n"),
        ("any", None, 0, 0, ""),
    ];
    for r in &header.cmds {
        if !matches!(r.kind.as_str(), "popen" | "exec" | "system" | "any") {
            return Err(format!("cmd rule kind must be popen|exec|system|any, got {}", r.kind));
        }
        out.push_str(&format!(
            "rule {} {} {} {} {} {}:{}\n",
            r.kind,
            r.pattern.as_deref().map_or("-".to_owned(), hexs),
            r.from.max(1),
            r.to,
            r.status,
            r.signal,
            hexs(&r.stdout)
        ));
    }
    for (kind, pat, status, sig, stdout) in defaults {
        out.push_str(&format!(
            "rule {kind} {} 1 0 {status} {sig}:{}\n",
            pat.map_or("-".to_owned(), hexs),
            hexs(stdout)
        ));
    }
    let mut lines: Vec<(u64, String)> = Vec::new();
    for i in inputs {
        let body = match &i.kind {
            Kind::UdpIn(u) => {
                check_hex("udp_in.random", &u.random)?;
                if u.random.len() != 16 {
                    return Err(format!("udp_in.random must be 16 hex characters: {}", u.random));
                }
                check_hex("udp_in.payload", &u.payload)?;
                let (mode, n, payload) = match u.auth.split_once(':') {
                    None if u.auth == "valid" || u.auth == "bad_tag" => (u.auth.as_str(), 0, u.payload.clone()),
                    Some(("truncate", n)) => ("truncate", n.parse::<i64>().map_err(|e| e.to_string())?, u.payload.clone()),
                    Some(("flip", n)) => ("flip", n.parse::<i64>().map_err(|e| e.to_string())?, u.payload.clone()),
                    Some(("raw", h)) => {
                        check_hex("udp_in.auth raw", h)?;
                        ("raw", 0, h.to_owned())
                    }
                    _ => return Err(format!("unknown udp_in.auth {}", u.auth)),
                };
                format!(
                    "udp_in {} {} {} {} {} {}",
                    hexs(&u.from),
                    u.random,
                    u.counter,
                    mode,
                    n,
                    opt_hex(&payload)
                )
            }
            Kind::TunIn(h) => {
                check_hex("tun_in", h)?;
                format!("tun_in {}", opt_hex(h))
            }
            Kind::Signal(s) => format!("signal {}", signal_number(s)?),
            Kind::PollErr { fd, revents } => {
                let mut bits = 0;
                for r in revents {
                    bits |= REVENTS
                        .iter()
                        .find(|(n, _)| n == r)
                        .map(|(_, v)| *v)
                        .ok_or_else(|| format!("unknown revents flag {r}"))?;
                }
                if !matches!(fd.as_str(), "tun" | "udp") {
                    return Err(format!("poll_err fd must be tun|udp, got {fd}"));
                }
                format!("poll_err {fd} {bits}")
            }
        };
        lines.push((i.t_ms, format!("ev {} {}\n", i.t_ms, body)));
    }
    let end = effective_end(header, inputs);
    let end_signal = header.end_signal.as_deref().unwrap_or("SIGTERM");
    let hang = if end_signal == "none" {
        end + HANG_SLACK_MS
    } else {
        lines.push((end, format!("ev {end} signal {}\n", signal_number(end_signal)?)));
        end + HANG_SLACK_MS
    };
    out.push_str(&format!("hang_ms {hang}\n"));
    lines.sort_by_key(|(t, _)| *t);
    for (_, l) in lines {
        out.push_str(&l);
    }
    Ok(out)
}
