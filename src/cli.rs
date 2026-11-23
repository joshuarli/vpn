use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::config;
use crate::mtu::{DEFAULT_MTU, MAX_ARG_MTU, MIN_ARG_MTU};

pub const DEFAULT_CLIENT_IP: &str = "192.168.192.1";
pub const DEFAULT_SERVER_IP: &str = "192.168.192.254";
pub const DEFAULT_PORT: &str = "41194";
pub const DEFAULT_KEY_FILE: &str = "vpn.key";

pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 254;
/// What `return -1` from `main` becomes as a process status.
pub const EXIT_SETUP_FAILED: i32 = 255;

/// Bytes the C program writes to stdout for its usage text, including the newline `puts` adds.
pub const USAGE: &str = concat!(
    "twice ",
    "0.1.0",
    " usage:\n",
    "\n",
    "twice genkey [keyfile]\t# Generate encryption key (default: vpn.key)\n",
    "\n",
    "twice\t\"server\"\n\t<vpn server ip or name>|\"auto\"\n\t<vpn ",
    "server port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun ",
    "ip>|\"auto\"\n\t<remote tun ip>\"auto\"\n\t<external ip>|\"auto\"",
    "\n\n",
    "twice\t\"client\"\n\t<vpn server ip or name>\n\t<vpn server ",
    "port>|\"auto\"\n\t<tun interface>|\"auto\"\n\t<local tun ",
    "ip>|\"auto\"\n\t<remote tun ip>|\"auto\"\n\t<gateway ip>|\"auto\"\n\n",
    "Options:\n",
    "\t-k, --key <file>\tPath to 256-bit key file for encryption\n",
    "\t-m, --mtu <mtu>\t\tSet TUN interface MTU (default: 1420)\n",
    "\t-d, --discover-mtu\tAutomatically discover optimal MTU (client only)\n\n",
    "Example:\n\n[server]\n",
    "\tsudo ./twice server auto\t# listen on UDP port 41194\n",
    "\tsudo ./twice -k vpn.key server auto\t# with encryption\n",
    "\tsudo ./twice -m 1380 server auto\t# with custom MTU\n\n[client]\n",
    "\tsudo ./twice client 34.216.127.34\n",
    "\tsudo ./twice -k vpn.key client 34.216.127.34\t# with encryption\n",
    "\tsudo ./twice -d client 34.216.127.34\t# with MTU discovery\n",
    "\tsudo ./twice --mtu 1380 client 34.216.127.34\n\n",
    "Generate encryption key:\n",
    "\t./twice genkey\t\t# creates vpn.key\n",
    "\t./twice genkey mykey.key\t# creates mykey.key\n",
    "\n"
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    GenKey { path: OsString },
    Run(Box<Run>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub key_file: Option<OsString>,
    pub mtu: Mtu,
    pub mode: Mode,
    pub port: OsString,
    pub tun_name: Option<OsString>,
    pub local_tun_ip: OsString,
    pub remote_tun_ip: OsString,
    /// Explicit external gateway; `None` means detect it.
    pub gateway: Option<OsString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mtu {
    Fixed(i32),
    /// Start from `initial`, then let the client probe the path.
    Discover { initial: i32 },
}

impl Mtu {
    pub fn initial(self) -> i32 {
        match self {
            Mtu::Fixed(v) | Mtu::Discover { initial: v } => v,
        }
    }

    pub fn discovers(self) -> bool {
        matches!(self, Mtu::Discover { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `bind` is the listen address; `None` listens on the wildcard address.
    Server { bind: Option<OsString> },
    Client { server: OsString },
}

impl Mode {
    pub fn is_server(&self) -> bool {
        matches!(self, Mode::Server { .. })
    }

    pub fn role(&self) -> config::Role {
        match self {
            Mode::Server { .. } => config::Role::Server,
            Mode::Client { .. } => config::Role::Client,
        }
    }

    /// The name or address in the `server_ip_or_name` slot; absent only for a wildcard server.
    pub fn server_ip_or_name(&self) -> Option<&OsStr> {
        match self {
            Mode::Server { bind } => bind.as_deref(),
            Mode::Client { server } => Some(server),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliError {
    /// Usage text on stdout, exit 254.
    Usage,
    /// `Unknown option: ...` on stderr, then usage text on stdout, exit 254.
    UnknownOption(OsString),
    KeyOptionNeedsPath,
    MtuOptionNeedsValue,
    InvalidMtu(i32),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage | CliError::UnknownOption(_) => EXIT_USAGE,
            _ => EXIT_FAILURE,
        }
    }

    pub fn stdout(&self) -> &'static str {
        match self {
            CliError::Usage | CliError::UnknownOption(_) => USAGE,
            _ => "",
        }
    }

    pub fn stderr(&self) -> Vec<u8> {
        match self {
            CliError::Usage => Vec::new(),
            CliError::UnknownOption(o) => [b"Unknown option: ", o.as_bytes(), b"\n"].concat(),
            CliError::KeyOptionNeedsPath => b"Key option requires a file path\n".to_vec(),
            CliError::MtuOptionNeedsValue => b"MTU option requires a value\n".to_vec(),
            CliError::InvalidMtu(v) => {
                format!("Invalid MTU value: {v} (must be between {MIN_ARG_MTU} and {MAX_ARG_MTU})\n")
                    .into_bytes()
            }
        }
    }
}

/// C `atoi` on a 64-bit glibc target: `strtol` in base 10 saturating at the `long` limits, then
/// truncated to the low 32 bits.
pub fn atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (9..=13).contains(&s[i])) {
        i += 1;
    }
    let mut negative = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        negative = s[i] == b'-';
        i += 1;
    }
    let mut acc: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        let d = (s[i] - b'0') as u64;
        match acc.checked_mul(10).and_then(|v| v.checked_add(d)) {
            Some(v) => acc = v,
            None => overflow = true,
        }
        i += 1;
    }
    let value: i64 = if negative {
        if overflow || acc > 1u64 << 63 { i64::MIN } else { (acc as i64).wrapping_neg() }
    } else if overflow || acc > i64::MAX as u64 {
        i64::MAX
    } else {
        acc as i64
    };
    value as i32
}

/// Parses a full `argv` (program name first) the way `main` does before any side effect.
pub fn parse<S: AsRef<OsStr>>(argv: &[S]) -> Result<Command, CliError> {
    let argc = argv.len();
    let arg = |i: usize| -> &[u8] { argv[i].as_ref().as_bytes() };

    if argc < 2 {
        return Err(CliError::Usage);
    }

    if arg(1) == b"genkey" || arg(1) == b"generate-key" {
        let path = if argc > 2 { argv[2].as_ref().to_os_string() } else { OsString::from(DEFAULT_KEY_FILE) };
        return Ok(Command::GenKey { path });
    }

    let mut key_file = None;
    let mut tun_mtu = DEFAULT_MTU;
    let mut discover = false;
    let mut start = 1;

    while start < argc && arg(start).first() == Some(&b'-') {
        match arg(start) {
            b"-k" | b"--key" => {
                if start + 1 >= argc {
                    return Err(CliError::KeyOptionNeedsPath);
                }
                key_file = Some(argv[start + 1].as_ref().to_os_string());
                start += 2;
            }
            b"-m" | b"--mtu" => {
                if start + 1 >= argc {
                    return Err(CliError::MtuOptionNeedsValue);
                }
                tun_mtu = atoi(arg(start + 1));
                if !(MIN_ARG_MTU..=MAX_ARG_MTU).contains(&tun_mtu) {
                    return Err(CliError::InvalidMtu(tun_mtu));
                }
                discover = false;
                start += 2;
            }
            b"-d" | b"--discover-mtu" => {
                discover = true;
                start += 1;
            }
            _ => return Err(CliError::UnknownOption(argv[start].as_ref().to_os_string())),
        }
    }

    if argc - start < 1 {
        return Err(CliError::Usage);
    }

    let is_server = arg(start) == b"server";

    let positional = |offset: usize| -> Option<OsString> {
        if argc <= start + offset || arg(start + offset) == b"auto" {
            None
        } else {
            Some(argv[start + offset].as_ref().to_os_string())
        }
    };
    let or_default = |v: Option<OsString>, d: &str| v.unwrap_or_else(|| OsString::from(d));

    let server_ip_or_name = positional(1);
    let mode = if is_server {
        Mode::Server { bind: server_ip_or_name }
    } else {
        match server_ip_or_name {
            Some(server) => Mode::Client { server },
            None => return Err(CliError::Usage),
        }
    };
    let port = or_default(positional(2), DEFAULT_PORT);
    let tun_name = positional(3);
    let (own_default, peer_default) = if is_server {
        (DEFAULT_SERVER_IP, DEFAULT_CLIENT_IP)
    } else {
        (DEFAULT_CLIENT_IP, DEFAULT_SERVER_IP)
    };
    let local_tun_ip = or_default(positional(4), own_default);
    let remote_tun_ip = or_default(positional(5), peer_default);
    let gateway = positional(6);

    Ok(Command::Run(Box::new(Run {
        key_file,
        mtu: if discover { Mtu::Discover { initial: tun_mtu } } else { Mtu::Fixed(tun_mtu) },
        mode,
        port,
        tun_name,
        local_tun_ip,
        remote_tun_ip,
        gateway,
    })))
}

pub fn genkey_exists_stderr(path: &OsStr) -> Vec<u8> {
    [
        b"Error: Key file '".as_slice(),
        path.as_bytes(),
        b"' already exists\nPlease specify a different filename or remove the existing file\n",
    ]
    .concat()
}

pub fn genkey_create_failed_stderr(path: &OsStr) -> Vec<u8> {
    [b"Error: Failed to create key file '".as_slice(), path.as_bytes(), b"'\n"].concat()
}

pub const GENKEY_RANDOM_FAILED_STDERR: &str = "Error: Failed to generate random key\n";
pub const GENKEY_WRITE_FAILED_STDERR: &str = "Error: Failed to write key file\n";
pub const GENKEY_CHMOD_FAILED_STDERR: &str = "Warning: Failed to set restrictive permissions on key file\n";

pub fn genkey_success_stdout(path: &OsStr) -> Vec<u8> {
    let p = path.as_bytes();
    [
        b"Successfully generated 256-bit key file: ".as_slice(),
        p,
        b"\n\nUsage:\n  Server: sudo ./twice -k ",
        p,
        b" server auto\n  Client: sudo ./twice -k ",
        p,
        b" client <server-ip>\n\nImportant: Copy this key file securely to both server and client\n",
    ]
    .concat()
}

pub const KEY_FILE_TOO_SHORT_STDERR: &str = "Key file must contain exactly 32 bytes\n";

pub fn key_open_failed_stderr(path: &OsStr) -> Vec<u8> {
    [b"Failed to open key file: ".as_slice(), path.as_bytes(), b"\n"].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, CliError> {
        let mut v = vec!["twice"];
        v.extend_from_slice(args);
        parse(&v)
    }

    fn run(args: &[&str]) -> Run {
        match p(args).unwrap() {
            Command::Run(r) => *r,
            other => panic!("{other:?}"),
        }
    }

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn usage_text_is_byte_exact_with_puts_newline() {
        let expected = [
            "twice 0.1.0 usage:",
            "",
            "twice genkey [keyfile]\t# Generate encryption key (default: vpn.key)",
            "",
            "twice\t\"server\"",
            "\t<vpn server ip or name>|\"auto\"",
            "\t<vpn server port>|\"auto\"",
            "\t<tun interface>|\"auto\"",
            "\t<local tun ip>|\"auto\"",
            "\t<remote tun ip>\"auto\"",
            "\t<external ip>|\"auto\"",
            "",
            "twice\t\"client\"",
            "\t<vpn server ip or name>",
            "\t<vpn server port>|\"auto\"",
            "\t<tun interface>|\"auto\"",
            "\t<local tun ip>|\"auto\"",
            "\t<remote tun ip>|\"auto\"",
            "\t<gateway ip>|\"auto\"",
            "",
            "Options:",
            "\t-k, --key <file>\tPath to 256-bit key file for encryption",
            "\t-m, --mtu <mtu>\t\tSet TUN interface MTU (default: 1420)",
            "\t-d, --discover-mtu\tAutomatically discover optimal MTU (client only)",
            "",
            "Example:",
            "",
            "[server]",
            "\tsudo ./twice server auto\t# listen on UDP port 41194",
            "\tsudo ./twice -k vpn.key server auto\t# with encryption",
            "\tsudo ./twice -m 1380 server auto\t# with custom MTU",
            "",
            "[client]",
            "\tsudo ./twice client 34.216.127.34",
            "\tsudo ./twice -k vpn.key client 34.216.127.34\t# with encryption",
            "\tsudo ./twice -d client 34.216.127.34\t# with MTU discovery",
            "\tsudo ./twice --mtu 1380 client 34.216.127.34",
            "",
            "Generate encryption key:",
            "\t./twice genkey\t\t# creates vpn.key",
            "\t./twice genkey mykey.key\t# creates mykey.key",
            "",
            "",
        ]
        .join("\n");
        assert_eq!(USAGE, expected);
        assert_eq!(USAGE.len(), 1108);
        assert!(USAGE.contains(&format!("twice {} usage:", crate::VERSION_STRING)));
    }

    #[test]
    fn no_arguments_prints_usage_with_status_254() {
        let e = parse::<&str>(&["twice"]).unwrap_err();
        assert_eq!(e, CliError::Usage);
        assert_eq!((e.exit_code(), e.stdout(), e.stderr()), (254, USAGE, vec![]));
    }

    #[test]
    fn genkey_and_alias_are_recognized_only_as_first_argument() {
        assert_eq!(p(&["genkey"]).unwrap(), Command::GenKey { path: os("vpn.key") });
        assert_eq!(p(&["generate-key", "a.key", "extra"]).unwrap(), Command::GenKey { path: os("a.key") });
        assert_eq!(p(&["-d", "genkey"]).unwrap_err(), CliError::Usage);
        assert_eq!(run(&["client", "genkey"]).mode, Mode::Client { server: os("genkey") });
    }

    #[test]
    fn defaults_for_client_and_server() {
        let c = run(&["client", "example.net"]);
        assert_eq!(c.mode, Mode::Client { server: os("example.net") });
        assert_eq!(c.port, os("41194"));
        assert_eq!(c.tun_name, None);
        assert_eq!(c.local_tun_ip, os("192.168.192.1"));
        assert_eq!(c.remote_tun_ip, os("192.168.192.254"));
        assert_eq!(c.gateway, None);
        assert_eq!(c.mtu, Mtu::Fixed(1420));
        assert_eq!(c.key_file, None);

        let s = run(&["server"]);
        assert_eq!(s.mode, Mode::Server { bind: None });
        assert_eq!(s.local_tun_ip, os("192.168.192.254"));
        assert_eq!(s.remote_tun_ip, os("192.168.192.1"));
        assert_eq!(run(&["server", "auto"]), s);
    }

    #[test]
    fn auto_is_a_placeholder_in_every_positional_slot() {
        let r = run(&["client", "h", "auto", "auto", "auto", "auto", "auto"]);
        assert_eq!(r, run(&["client", "h"]));
        let r = run(&["server", "0.0.0.0", "5000", "tun7", "10.0.0.1", "10.0.0.2", "192.0.2.1"]);
        assert_eq!(r.mode, Mode::Server { bind: Some(os("0.0.0.0")) });
        assert_eq!(r.port, os("5000"));
        assert_eq!(r.tun_name, Some(os("tun7")));
        assert_eq!(r.local_tun_ip, os("10.0.0.1"));
        assert_eq!(r.remote_tun_ip, os("10.0.0.2"));
        assert_eq!(r.gateway, Some(os("192.0.2.1")));
    }

    #[test]
    fn auto_match_is_exact_and_case_sensitive() {
        assert_eq!(run(&["client", "h", "AUTO"]).port, os("AUTO"));
        assert_eq!(run(&["client", "h", "auto "]).port, os("auto "));
        assert_eq!(run(&["client", "h", ""]).port, os(""));
    }

    #[test]
    fn extra_positionals_are_ignored() {
        let r = run(&["client", "h", "1", "2", "3", "4", "5", "6", "7"]);
        assert_eq!(r.gateway, Some(os("5")));
    }

    #[test]
    fn client_without_server_is_usage_error() {
        assert_eq!(p(&["client"]).unwrap_err(), CliError::Usage);
        assert_eq!(p(&["client", "auto"]).unwrap_err(), CliError::Usage);
        assert_eq!(p(&["anything"]).unwrap_err(), CliError::Usage);
    }

    #[test]
    fn anything_other_than_exact_server_is_a_client() {
        for m in ["Server", "servers", "SERVER", "client", "x", ""] {
            assert!(!run(&[m, "h"]).mode.is_server(), "{m:?}");
        }
        assert!(run(&["server"]).mode.is_server());
    }

    #[test]
    fn options_must_precede_the_mode() {
        let r = run(&["-k", "vpn.key", "-m", "1380", "client", "h"]);
        assert_eq!(r.key_file, Some(os("vpn.key")));
        assert_eq!(r.mtu, Mtu::Fixed(1380));
        let r = run(&["--key", "k", "--mtu", "1380", "--discover-mtu", "server"]);
        assert_eq!(r.mtu, Mtu::Discover { initial: 1380 });
        assert_eq!(r.key_file, Some(os("k")));
        let r = run(&["client", "h", "auto", "auto", "auto", "auto", "auto"]);
        assert_eq!(r.key_file, None);
        assert_eq!(run(&["client", "h", "-k", "x"]).port, os("-k"));
    }

    #[test]
    fn mtu_and_discovery_flags_apply_in_order() {
        assert_eq!(run(&["-d", "client", "h"]).mtu, Mtu::Discover { initial: 1420 });
        assert_eq!(run(&["-m", "1380", "-d", "client", "h"]).mtu, Mtu::Discover { initial: 1380 });
        assert_eq!(run(&["-d", "-m", "1380", "client", "h"]).mtu, Mtu::Fixed(1380));
        assert_eq!(run(&["-d", "-m", "1380", "-d", "client", "h"]).mtu, Mtu::Discover { initial: 1380 });
        assert_eq!(run(&["-d", "-d", "client", "h"]).mtu, Mtu::Discover { initial: 1420 });
        assert!(run(&["-d", "client", "h"]).mtu.discovers());
        assert_eq!(run(&["-d", "-m", "9000", "-m", "68", "client", "h"]).mtu, Mtu::Fixed(68));
    }

    #[test]
    fn mtu_range_is_68_to_9000_inclusive() {
        assert_eq!(run(&["-m", "68", "server"]).mtu, Mtu::Fixed(68));
        assert_eq!(run(&["-m", "9000", "server"]).mtu, Mtu::Fixed(9000));
        assert_eq!(p(&["-m", "67", "server"]).unwrap_err(), CliError::InvalidMtu(67));
        assert_eq!(p(&["-m", "9001", "server"]).unwrap_err(), CliError::InvalidMtu(9001));
        let e = p(&["-m", "0", "server"]).unwrap_err();
        assert_eq!(e.stderr(), b"Invalid MTU value: 0 (must be between 68 and 9000)\n");
        assert_eq!((e.exit_code(), e.stdout()), (1, ""));
    }

    #[test]
    fn mtu_value_uses_atoi_leniency() {
        assert_eq!(run(&["-m", " 1380abc", "server"]).mtu, Mtu::Fixed(1380));
        assert_eq!(run(&["-m", "+1380", "server"]).mtu, Mtu::Fixed(1380));
        assert_eq!(run(&["-m", "\t\n 0099", "server"]).mtu, Mtu::Fixed(99));
        assert_eq!(p(&["-m", "-1380", "server"]).unwrap_err(), CliError::InvalidMtu(-1380));
        assert_eq!(p(&["-m", "abc", "server"]).unwrap_err(), CliError::InvalidMtu(0));
        assert_eq!(p(&["-m", "", "server"]).unwrap_err(), CliError::InvalidMtu(0));
        assert_eq!(p(&["-m", "1e3", "server"]).unwrap_err(), CliError::InvalidMtu(1));
        assert_eq!(p(&["-m", "0x500", "server"]).unwrap_err(), CliError::InvalidMtu(0));
        assert_eq!(p(&["-m", "1 380", "server"]).unwrap_err(), CliError::InvalidMtu(1));
    }

    #[test]
    fn atoi_truncates_wrapped_long_to_int_like_glibc() {
        assert_eq!(atoi(b"4294968716"), 1420);
        assert_eq!(atoi(b"2147483648"), i32::MIN);
        assert_eq!(atoi(b"-2147483649"), i32::MAX);
        assert_eq!(atoi(b"99999999999"), 1215752191);
        assert_eq!(atoi(b"9223372036854775807"), -1);
        assert_eq!(atoi(b"9223372036854775808"), -1);
        assert_eq!(atoi(b"99999999999999999999999"), -1);
        assert_eq!(atoi(b"-9223372036854775808"), 0);
        assert_eq!(atoi(b"-99999999999999999999999"), 0);
        assert_eq!(atoi(b"-"), 0);
        assert_eq!(atoi(b"+-5"), 0);
        assert_eq!(atoi(b"\x0b\x0c\r 7"), 7);
        assert_eq!(atoi(b"\xa07"), 0);
    }

    #[test]
    fn wrapped_mtu_is_accepted_when_low_bits_are_in_range() {
        assert_eq!(run(&["-m", "4294968716", "server"]).mtu, Mtu::Fixed(1420));
        assert_eq!(p(&["-m", "9223372036854775807", "server"]).unwrap_err(), CliError::InvalidMtu(-1));
    }

    #[test]
    fn option_missing_its_argument_exits_1() {
        let e = p(&["-k"]).unwrap_err();
        assert_eq!(e, CliError::KeyOptionNeedsPath);
        assert_eq!((e.exit_code(), e.stderr(), e.stdout()), (1, b"Key option requires a file path\n".to_vec(), ""));
        let e = p(&["-m"]).unwrap_err();
        assert_eq!(e.stderr(), b"MTU option requires a value\n");
        assert_eq!(e.exit_code(), 1);
        assert_eq!(p(&["-d", "-k"]).unwrap_err(), CliError::KeyOptionNeedsPath);
        assert_eq!(p(&["--mtu"]).unwrap_err(), CliError::MtuOptionNeedsValue);
    }

    #[test]
    fn option_argument_is_consumed_even_if_it_looks_like_an_option() {
        let r = run(&["-k", "-d", "client", "h"]);
        assert_eq!(r.key_file, Some(os("-d")));
        assert!(!r.mtu.discovers());
        assert_eq!(p(&["-k", "x"]).unwrap_err(), CliError::Usage);
    }

    #[test]
    fn unknown_option_reports_then_prints_usage_with_status_254() {
        for bad in ["-", "-q", "--key=x", "-kx", "--", "-D"] {
            let e = p(&[bad, "client", "h"]).unwrap_err();
            assert_eq!(e, CliError::UnknownOption(os(bad)));
            assert_eq!(e.stderr(), format!("Unknown option: {bad}\n").into_bytes());
            assert_eq!((e.exit_code(), e.stdout()), (254, USAGE));
        }
    }

    #[test]
    fn leading_non_dash_argument_ends_option_parsing() {
        let r = run(&["", "h"]);
        assert_eq!(r.mode, Mode::Client { server: os("h") });
        assert_eq!(run(&[" -d", "h"]).mode, Mode::Client { server: os("h") });
        assert_eq!(run(&["server", "-d"]).mode, Mode::Server { bind: Some(os("-d")) });
    }

    #[test]
    fn only_options_without_mode_is_usage() {
        assert_eq!(p(&["-d"]).unwrap_err(), CliError::Usage);
        assert_eq!(p(&["-k", "a", "-m", "1500"]).unwrap_err(), CliError::Usage);
    }

    #[test]
    fn invalid_mtu_is_reported_before_missing_mode() {
        assert_eq!(p(&["-m", "5"]).unwrap_err(), CliError::InvalidMtu(5));
    }

    #[test]
    fn non_utf8_arguments_are_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let weird = OsString::from_vec(vec![b'h', 0xff, b'x']);
        let argv = [os("twice"), os("client"), weird.clone()];
        match parse(&argv).unwrap() {
            Command::Run(r) => assert_eq!(r.mode, Mode::Client { server: weird }),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn mode_exposes_role_and_server_slot() {
        let c = run(&["client", "h"]).mode;
        assert_eq!(c.role(), config::Role::Client);
        assert_eq!(c.server_ip_or_name(), Some(OsStr::new("h")));
        let s = run(&["server"]).mode;
        assert_eq!(s.role(), config::Role::Server);
        assert_eq!(s.server_ip_or_name(), None);
    }

    #[test]
    fn genkey_messages_are_exact() {
        let k = OsStr::new("my.key");
        assert_eq!(
            genkey_success_stdout(k),
            b"Successfully generated 256-bit key file: my.key\n\nUsage:\n  Server: sudo ./twice -k my.key server auto\n  Client: sudo ./twice -k my.key client <server-ip>\n\nImportant: Copy this key file securely to both server and client\n"
        );
        assert_eq!(
            genkey_exists_stderr(k),
            b"Error: Key file 'my.key' already exists\nPlease specify a different filename or remove the existing file\n"
        );
        assert_eq!(genkey_create_failed_stderr(k), b"Error: Failed to create key file 'my.key'\n");
        assert_eq!(key_open_failed_stderr(k), b"Failed to open key file: my.key\n");
    }
}
