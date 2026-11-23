use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    OpenBsd,
    FreeBsd,
    NetBsd,
    DragonFly,
    /// Any other system: no routing tables, no gateway discovery commands.
    Other,
}

impl Os {
    pub const fn host() -> Os {
        if cfg!(target_os = "linux") {
            Os::Linux
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "openbsd") {
            Os::OpenBsd
        } else if cfg!(target_os = "freebsd") {
            Os::FreeBsd
        } else if cfg!(target_os = "netbsd") {
            Os::NetBsd
        } else if cfg!(target_os = "dragonfly") {
            Os::DragonFly
        } else {
            Os::Other
        }
    }

    const fn is_bsd_family(self) -> bool {
        matches!(self, Os::MacOs | Os::OpenBsd | Os::FreeBsd | Os::NetBsd | Os::DragonFly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Whether the client installs routes that send all traffic through the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultRoutes {
    Enabled,
    Suppressed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cmds {
    pub set: &'static [&'static str],
    pub unset: &'static [&'static str],
}

const LINUX_SERVER_SET: &[&str] = &[
    "sysctl net.ipv4.ip_forward=1",
    "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
    "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",
    "ip link set dev $IF_NAME up",
    "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
    "iptables -t nat -A POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j MASQUERADE",
    "iptables -t filter -A FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT",
    "iptables -t filter -A FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",
];

const LINUX_SERVER_UNSET: &[&str] = &[
    "iptables -t nat -D POSTROUTING -o $EXT_IF_NAME -s $REMOTE_TUN_IP -j MASQUERADE",
    "iptables -t filter -D FORWARD -i $EXT_IF_NAME -o $IF_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT",
    "iptables -t filter -D FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT",
    "iptables -t raw -D PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
];

const BSD_SERVER_SET: &[&str] = &[
    "sysctl -w net.inet.ip.forwarding=1",
    "ifconfig $IF_NAME $LOCAL_TUN_IP $REMOTE_TUN_IP up",
    "ifconfig $IF_NAME inet6 $LOCAL_TUN_IP6 $REMOTE_TUN_IP6 prefixlen 128 up",
];

const BSD_SERVER_UNSET: &[&str] = &[];

const BSD_CLIENT_SET_ROUTED: &[&str] = &[
    "ifconfig $IF_NAME $LOCAL_TUN_IP $REMOTE_TUN_IP up",
    "ifconfig $IF_NAME inet6 $LOCAL_TUN_IP6 $REMOTE_TUN_IP6 prefixlen 128 up",
    "route add $EXT_IP $EXT_GW_IP",
    "route add 0/1 $REMOTE_TUN_IP",
    "route add 128/1 $REMOTE_TUN_IP",
    "route add -inet6 -blackhole 0000::/1 $REMOTE_TUN_IP6",
    "route add -inet6 -blackhole 8000::/1 $REMOTE_TUN_IP6",
];

const BSD_CLIENT_SET_PLAIN: &[&str] = &[
    "ifconfig $IF_NAME $LOCAL_TUN_IP $REMOTE_TUN_IP up",
    "ifconfig $IF_NAME inet6 $LOCAL_TUN_IP6 $REMOTE_TUN_IP6 prefixlen 128 up",
];

const BSD_CLIENT_UNSET_ROUTED: &[&str] = &[
    "route delete $EXT_IP",
    "route delete 0/1",
    "route delete 128/1",
    "route delete -inet6 0000::/1",
    "route delete -inet6 8000::/1",
];

const BSD_CLIENT_UNSET_PLAIN: &[&str] = &[];

const LINUX_CLIENT_SET_ROUTED: &[&str] = &[
    "ip link set dev $IF_NAME up",
    "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
    "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
    "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",
    "ip route add default dev $IF_NAME table 42069",
    "ip -6 route add default dev $IF_NAME table 42069",
    "ip rule add not fwmark 42069 table 42069",
    "ip -6 rule add not fwmark 42069 table 42069",
    "ip rule add table main suppress_prefixlength 0",
    "ip -6 rule add table main suppress_prefixlength 0",
];

const LINUX_CLIENT_SET_PLAIN: &[&str] = &[
    "ip link set dev $IF_NAME up",
    "iptables -t raw -I PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
    "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
    "ip -6 addr add $LOCAL_TUN_IP6 peer $REMOTE_TUN_IP6/96 dev $IF_NAME",
];

const LINUX_CLIENT_UNSET_ROUTED: &[&str] = &[
    "ip rule delete table 42069",
    "ip -6 rule delete table 42069",
    "ip rule delete table main suppress_prefixlength 0",
    "ip -6 rule delete table main suppress_prefixlength 0",
    "iptables -t raw -D PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
];

const LINUX_CLIENT_UNSET_PLAIN: &[&str] = &[
    "iptables -t raw -D PREROUTING ! -i $IF_NAME -d $LOCAL_TUN_IP -m addrtype ! --src-type LOCAL -j DROP",
];

/// Command templates for the OS and role; `None` where the C program has no table.
pub fn firewall_rules_cmds(os: Os, role: Role, routes: DefaultRoutes) -> Option<Cmds> {
    let routed = routes == DefaultRoutes::Enabled;
    match (role, os) {
        (Role::Server, Os::Linux) => {
            Some(Cmds { set: LINUX_SERVER_SET, unset: LINUX_SERVER_UNSET })
        }
        (Role::Server, os) if os.is_bsd_family() => {
            Some(Cmds { set: BSD_SERVER_SET, unset: BSD_SERVER_UNSET })
        }
        (Role::Client, Os::Linux) => Some(if routed {
            Cmds { set: LINUX_CLIENT_SET_ROUTED, unset: LINUX_CLIENT_UNSET_ROUTED }
        } else {
            Cmds { set: LINUX_CLIENT_SET_PLAIN, unset: LINUX_CLIENT_UNSET_PLAIN }
        }),
        (Role::Client, os) if os.is_bsd_family() => Some(if routed {
            Cmds { set: BSD_CLIENT_SET_ROUTED, unset: BSD_CLIENT_UNSET_ROUTED }
        } else {
            Cmds { set: BSD_CLIENT_SET_PLAIN, unset: BSD_CLIENT_UNSET_PLAIN }
        }),
        _ => None,
    }
}

pub const UNSUPPORTED_OS_MESSAGE: &str =
    "Routing commands for that operating system have not been added yet.\n";

/// Shell pipeline run through `popen` (so `sh -c`) whose first output line is the default
/// gateway address.
pub const fn default_gateway_command(os: Os) -> Option<&'static str> {
    if os.is_bsd_family() {
        Some("route -n get default 2>/dev/null|awk '/gateway:/{print $2;exit}'")
    } else if matches!(os, Os::Linux) {
        Some("ip route show default 2>/dev/null|awk '/default/{print $3}'")
    } else {
        None
    }
}

/// Shell pipeline whose first output line is the default external interface name.
pub const fn default_ext_if_command(os: Os) -> Option<&'static str> {
    if os.is_bsd_family() {
        Some("route -n get default 2>/dev/null|awk '/interface:/{print $2;exit}'")
    } else if matches!(os, Os::Linux) {
        Some("ip route show default 2>/dev/null|awk '/default/{print $5}'")
    } else {
        None
    }
}

pub const GATEWAY_BUFFER: usize = 64;
pub const IP6_BUFFER: usize = 40;

/// What `fgets(buf, 64, fp)` followed by newline stripping yields from a command's output:
/// `Err` when nothing could be read (the C program logs `Command [..] failed]`), `Ok(None)` for
/// an empty first line.
pub fn parse_command_output(output: &[u8]) -> Result<Option<Vec<u8>>, NoOutput> {
    if output.is_empty() {
        return Err(NoOutput);
    }
    let limit = (GATEWAY_BUFFER - 1).min(output.len());
    let mut end = limit;
    if let Some(nl) = output[..limit].iter().position(|&b| b == b'\n') {
        end = nl + 1;
    }
    let mut line = &output[..end];
    if let Some(nl) = line.iter().rposition(|&b| b == b'\n') {
        line = &line[..nl];
    }
    if let Some(nul) = line.iter().position(|&b| b == 0) {
        line = &line[..nul];
    }
    Ok(if line.is_empty() { None } else { Some(line.to_vec()) })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoOutput;

pub fn command_failed_stderr(command: &str) -> Vec<u8> {
    format!("Command [{command}] failed]\n").into_bytes()
}

/// Copy as `snprintf(dst, size, "%s", src)` would: at most `size - 1` bytes, and nothing after a
/// NUL.
pub fn truncate_c_string(src: &[u8], size: usize) -> Vec<u8> {
    let end = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    src[..end.min(size.saturating_sub(1))].to_vec()
}

/// `64:ff9b::` followed by the IPv4 text, cut to the 39 bytes of the C buffer.
pub fn tun6_address(ip: &[u8]) -> Vec<u8> {
    let mut v = b"64:ff9b::".to_vec();
    let tail = &ip[..ip.iter().position(|&b| b == 0).unwrap_or(ip.len())];
    v.extend_from_slice(tail);
    v.truncate(IP6_BUFFER - 1);
    v
}

/// Values for the `$NAME` placeholders. A value is used as-is; callers apply the C buffer limits
/// with `truncate_c_string` (gateway 64, interface name `IFNAMSIZ`) where C stores them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Substitutions {
    pub local_tun_ip: Vec<u8>,
    pub remote_tun_ip: Vec<u8>,
    pub local_tun_ip6: Vec<u8>,
    pub remote_tun_ip6: Vec<u8>,
    pub ext_ip: Vec<u8>,
    pub ext_port: Vec<u8>,
    /// Unset only on a client, where no template uses it; a server cannot start without it.
    pub ext_if_name: Vec<u8>,
    pub ext_gw_ip: Vec<u8>,
    pub if_name: Vec<u8>,
}

impl Substitutions {
    /// Derives the IPv6 addresses from the tunnel IPv4 addresses and applies the 63-byte limit
    /// of the gateway buffer.
    pub fn new(
        local_tun_ip: &[u8],
        remote_tun_ip: &[u8],
        ext_ip: &[u8],
        ext_port: &[u8],
        ext_if_name: &[u8],
        ext_gw_ip: &[u8],
        if_name: &[u8],
    ) -> Substitutions {
        Substitutions {
            local_tun_ip: local_tun_ip.to_vec(),
            remote_tun_ip: remote_tun_ip.to_vec(),
            local_tun_ip6: tun6_address(local_tun_ip),
            remote_tun_ip6: tun6_address(remote_tun_ip),
            ext_ip: ext_ip.to_vec(),
            ext_port: ext_port.to_vec(),
            ext_if_name: ext_if_name.to_vec(),
            ext_gw_ip: truncate_c_string(ext_gw_ip, GATEWAY_BUFFER),
            if_name: if_name.to_vec(),
        }
    }

    /// Placeholder table in C lookup order. Order matters: `$LOCAL_TUN_IP6` must be tried
    /// before its prefix `$LOCAL_TUN_IP`.
    pub fn pairs(&self) -> [(&'static [u8], &[u8]); 9] {
        [
            (b"$LOCAL_TUN_IP6", &self.local_tun_ip6),
            (b"$REMOTE_TUN_IP6", &self.remote_tun_ip6),
            (b"$LOCAL_TUN_IP", &self.local_tun_ip),
            (b"$REMOTE_TUN_IP", &self.remote_tun_ip),
            (b"$EXT_IP", &self.ext_ip),
            (b"$EXT_PORT", &self.ext_port),
            (b"$EXT_IF_NAME", &self.ext_if_name),
            (b"$EXT_GW_IP", &self.ext_gw_ip),
            (b"$IF_NAME", &self.if_name),
        ]
    }

    pub fn render(&self, template: &str) -> Result<Vec<Vec<u8>>, SplitError> {
        split_command(&self.pairs(), template.as_bytes())
    }
}

pub const MAX_ARGS: usize = 64;
pub const CMDBUF_LEN: usize = 4096;

/// The command did not fit the 64-argument or 4096-byte limits of the C splitter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitError;

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("command too long")
    }
}

const fn is_c_space(c: u8) -> bool {
    c == b' ' || (c >= 9 && c <= 13)
}

/// Splits a template on ASCII whitespace into argv, substituting placeholders as `shell_cmd`
/// does: there is no quoting, a substituted value is never re-scanned or split, and the
/// earliest matching placeholder in `substs` wins at each position. An argument that is only an
/// empty substitution stays as an empty argument.
pub fn split_command(substs: &[(&[u8], &[u8])], template: &[u8]) -> Result<Vec<Vec<u8>>, SplitError> {
    let mut cmdbuf: Vec<u8> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    let mut is_space = true;
    let mut i = 0;

    while i < template.len() {
        let c = template[i];
        if is_c_space(c) {
            if !is_space {
                if cmdbuf.len() >= CMDBUF_LEN {
                    return Err(SplitError);
                }
                cmdbuf.push(0);
            }
            is_space = true;
            i += 1;
            continue;
        }
        if is_space {
            if starts.len() >= MAX_ARGS {
                return Err(SplitError);
            }
            starts.push(cmdbuf.len());
        }
        is_space = false;
        let hit = substs.iter().find(|(pat, _)| template[i..].starts_with(pat));
        match hit {
            Some((pat, value)) => {
                let value = &value[..value.iter().position(|&b| b == 0).unwrap_or(value.len())];
                if CMDBUF_LEN - cmdbuf.len() <= value.len() {
                    return Err(SplitError);
                }
                cmdbuf.extend_from_slice(value);
                i += pat.len();
            }
            None => {
                if cmdbuf.len() >= CMDBUF_LEN {
                    return Err(SplitError);
                }
                cmdbuf.push(c);
                i += 1;
            }
        }
    }
    if !is_space {
        if cmdbuf.len() >= CMDBUF_LEN {
            return Err(SplitError);
        }
        cmdbuf.push(0);
    }
    if starts.len() >= MAX_ARGS || starts.is_empty() {
        return Err(SplitError);
    }
    Ok(starts
        .iter()
        .map(|&s| {
            let end = cmdbuf[s..].iter().position(|&b| b == 0).map_or(cmdbuf.len(), |n| s + n);
            cmdbuf[s..end].to_vec()
        })
        .collect())
}

/// Why a command did not succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    /// Non-zero or abnormal exit. C leaves `errno` as `ENOSPC` here, so its message reads
    /// `No space left on device`.
    Failed,
    /// `fork` or `waitpid` failed with this `errno`.
    Errno(i32),
}

impl RunError {
    pub fn errno(self) -> i32 {
        match self {
            RunError::Failed => libc::ENOSPC,
            RunError::Errno(e) => e,
        }
    }
}

pub trait CommandRunner {
    /// Runs `argv[0]` found through `PATH`, waits for it, and with `silent` redirects its stdout
    /// and stderr to `/dev/null`.
    fn run(&mut self, argv: &[Vec<u8>], silent: bool) -> Result<(), RunError>;
}

/// The `firewall_rules_set` state: -1 before anything ran, then 0 or 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallState {
    Unknown,
    Cleared,
    Applied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallOutcome {
    /// The state already equals the request: nothing ran.
    AlreadyInState,
    /// No table for this OS and role: log `UNSUPPORTED_OS_MESSAGE`; the state is unchanged.
    Unsupported,
    Done,
    /// A command could not be built or run; the remaining commands were skipped and the state is
    /// unchanged. Log `unable_to_run_stderr(template, strerror(errno))`.
    Failed { template: &'static str, errno: i32 },
}

pub fn unable_to_run_stderr(template: &str, error_text: &[u8]) -> Vec<u8> {
    [b"Unable to run [".as_slice(), template.as_bytes(), b"]: [", error_text, b"]\n"].concat()
}

#[derive(Clone, Copy, Debug)]
pub struct Plan {
    pub os: Os,
    pub role: Role,
    pub routes: DefaultRoutes,
}

impl FirewallState {
    /// One `firewall_rules(context, set, silent)` call: `apply` true sets rules, false removes them.
    pub fn transition<R: CommandRunner>(
        &mut self,
        plan: Plan,
        apply: bool,
        silent: bool,
        substs: &Substitutions,
        runner: &mut R,
    ) -> FirewallOutcome {
        let target = if apply { FirewallState::Applied } else { FirewallState::Cleared };
        if *self == target {
            return FirewallOutcome::AlreadyInState;
        }
        let Some(cmds) = firewall_rules_cmds(plan.os, plan.role, plan.routes) else {
            return FirewallOutcome::Unsupported;
        };
        let list = if apply { cmds.set } else { cmds.unset };
        for &template in list {
            let argv = match substs.render(template) {
                Ok(argv) => argv,
                Err(SplitError) => {
                    return FirewallOutcome::Failed { template, errno: libc::ENOSPC };
                }
            };
            if let Err(e) = runner.run(&argv, silent) {
                return FirewallOutcome::Failed { template, errno: e.errno() };
            }
        }
        *self = target;
        FirewallOutcome::Done
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayChange {
    pub message: Vec<u8>,
    /// New value for the stored gateway, cut to the 63 bytes of the C buffer.
    pub new_gateway: Vec<u8>,
}

/// Client reconnect check: when no gateway was given on the command line and a detected gateway
/// differs from the stored one, log `message`, clear the rules, store `new_gateway`, set the
/// rules again. Only applies when default routes are enabled.
pub fn gateway_change(
    explicit_gateway: bool,
    stored: &[u8],
    detected: Option<&[u8]>,
    routes: DefaultRoutes,
) -> Option<GatewayChange> {
    if routes == DefaultRoutes::Suppressed || explicit_gateway {
        return None;
    }
    let detected = detected?;
    if detected == stored {
        return None;
    }
    Some(GatewayChange {
        message: [b"Gateway changed from [".as_slice(), stored, b"] to [", detected, b"]\n"].concat(),
        new_gateway: truncate_c_string(detected, GATEWAY_BUFFER),
    })
}

/// Printed after a successful server setup on OpenBSD only.
pub fn openbsd_pf_notice(remote_tun_ip: &[u8]) -> Vec<u8> {
    [
        b"\nAdd the following rule to /etc/pf.conf:\npass out from ".as_slice(),
        remote_tun_ip,
        b" nat-to egress\n\n",
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OS: [Os; 6] =
        [Os::Linux, Os::MacOs, Os::OpenBsd, Os::FreeBsd, Os::NetBsd, Os::DragonFly];

    fn subs() -> Substitutions {
        Substitutions::new(
            b"10.0.0.1",
            b"10.0.0.2",
            b"203.0.113.9",
            b"41194",
            b"eth0",
            b"192.0.2.1",
            b"tun0",
        )
    }

    fn strs(v: Vec<Vec<u8>>) -> Vec<String> {
        v.into_iter().map(|a| String::from_utf8(a).unwrap()).collect()
    }

    fn rendered(list: &[&str]) -> Vec<String> {
        let s = subs();
        list.iter().map(|t| strs(s.render(t).unwrap()).join(" ")).collect()
    }

    fn cmds(os: Os, role: Role, routes: DefaultRoutes) -> Cmds {
        firewall_rules_cmds(os, role, routes).unwrap()
    }

    #[test]
    fn linux_server_set_and_unset_in_order() {
        let c = cmds(Os::Linux, Role::Server, DefaultRoutes::Enabled);
        assert_eq!(
            rendered(c.set),
            [
                "sysctl net.ipv4.ip_forward=1",
                "ip addr add 10.0.0.1 peer 10.0.0.2 dev tun0",
                "ip -6 addr add 64:ff9b::10.0.0.1 peer 64:ff9b::10.0.0.2/96 dev tun0",
                "ip link set dev tun0 up",
                "iptables -t raw -I PREROUTING ! -i tun0 -d 10.0.0.1 -m addrtype ! --src-type LOCAL -j DROP",
                "iptables -t nat -A POSTROUTING -o eth0 -s 10.0.0.2 -j MASQUERADE",
                "iptables -t filter -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
                "iptables -t filter -A FORWARD -i tun0 -o eth0 -j ACCEPT",
            ]
        );
        assert_eq!(
            rendered(c.unset),
            [
                "iptables -t nat -D POSTROUTING -o eth0 -s 10.0.0.2 -j MASQUERADE",
                "iptables -t filter -D FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
                "iptables -t filter -D FORWARD -i tun0 -o eth0 -j ACCEPT",
                "iptables -t raw -D PREROUTING ! -i tun0 -d 10.0.0.1 -m addrtype ! --src-type LOCAL -j DROP",
            ]
        );
    }

    #[test]
    fn linux_server_ignores_default_route_suppression() {
        assert_eq!(
            cmds(Os::Linux, Role::Server, DefaultRoutes::Suppressed),
            cmds(Os::Linux, Role::Server, DefaultRoutes::Enabled)
        );
    }

    #[test]
    fn linux_client_with_default_routes() {
        let c = cmds(Os::Linux, Role::Client, DefaultRoutes::Enabled);
        assert_eq!(
            rendered(c.set),
            [
                "ip link set dev tun0 up",
                "iptables -t raw -I PREROUTING ! -i tun0 -d 10.0.0.1 -m addrtype ! --src-type LOCAL -j DROP",
                "ip addr add 10.0.0.1 peer 10.0.0.2 dev tun0",
                "ip -6 addr add 64:ff9b::10.0.0.1 peer 64:ff9b::10.0.0.2/96 dev tun0",
                "ip route add default dev tun0 table 42069",
                "ip -6 route add default dev tun0 table 42069",
                "ip rule add not fwmark 42069 table 42069",
                "ip -6 rule add not fwmark 42069 table 42069",
                "ip rule add table main suppress_prefixlength 0",
                "ip -6 rule add table main suppress_prefixlength 0",
            ]
        );
        assert_eq!(
            rendered(c.unset),
            [
                "ip rule delete table 42069",
                "ip -6 rule delete table 42069",
                "ip rule delete table main suppress_prefixlength 0",
                "ip -6 rule delete table main suppress_prefixlength 0",
                "iptables -t raw -D PREROUTING ! -i tun0 -d 10.0.0.1 -m addrtype ! --src-type LOCAL -j DROP",
            ]
        );
    }

    #[test]
    fn linux_client_without_default_routes() {
        let c = cmds(Os::Linux, Role::Client, DefaultRoutes::Suppressed);
        assert_eq!(
            rendered(c.set),
            [
                "ip link set dev tun0 up",
                "iptables -t raw -I PREROUTING ! -i tun0 -d 10.0.0.1 -m addrtype ! --src-type LOCAL -j DROP",
                "ip addr add 10.0.0.1 peer 10.0.0.2 dev tun0",
                "ip -6 addr add 64:ff9b::10.0.0.1 peer 64:ff9b::10.0.0.2/96 dev tun0",
            ]
        );
        assert_eq!(
            rendered(c.unset),
            ["iptables -t raw -D PREROUTING ! -i tun0 -d 10.0.0.1 -m addrtype ! --src-type LOCAL -j DROP"]
        );
    }

    #[test]
    fn bsd_family_server_tables_are_identical_with_empty_teardown() {
        for os in [Os::MacOs, Os::OpenBsd, Os::FreeBsd, Os::NetBsd, Os::DragonFly] {
            for routes in [DefaultRoutes::Enabled, DefaultRoutes::Suppressed] {
                let c = cmds(os, Role::Server, routes);
                assert_eq!(
                    rendered(c.set),
                    [
                        "sysctl -w net.inet.ip.forwarding=1",
                        "ifconfig tun0 10.0.0.1 10.0.0.2 up",
                        "ifconfig tun0 inet6 64:ff9b::10.0.0.1 64:ff9b::10.0.0.2 prefixlen 128 up",
                    ],
                    "{os:?}"
                );
                assert!(c.unset.is_empty(), "{os:?}");
            }
        }
    }

    #[test]
    fn bsd_family_client_with_default_routes() {
        for os in [Os::MacOs, Os::OpenBsd, Os::FreeBsd, Os::NetBsd, Os::DragonFly] {
            let c = cmds(os, Role::Client, DefaultRoutes::Enabled);
            assert_eq!(
                rendered(c.set),
                [
                    "ifconfig tun0 10.0.0.1 10.0.0.2 up",
                    "ifconfig tun0 inet6 64:ff9b::10.0.0.1 64:ff9b::10.0.0.2 prefixlen 128 up",
                    "route add 203.0.113.9 192.0.2.1",
                    "route add 0/1 10.0.0.2",
                    "route add 128/1 10.0.0.2",
                    "route add -inet6 -blackhole 0000::/1 64:ff9b::10.0.0.2",
                    "route add -inet6 -blackhole 8000::/1 64:ff9b::10.0.0.2",
                ],
                "{os:?}"
            );
            assert_eq!(
                rendered(c.unset),
                [
                    "route delete 203.0.113.9",
                    "route delete 0/1",
                    "route delete 128/1",
                    "route delete -inet6 0000::/1",
                    "route delete -inet6 8000::/1",
                ],
                "{os:?}"
            );
        }
    }

    #[test]
    fn bsd_family_client_without_default_routes_only_configures_the_interface() {
        for os in [Os::MacOs, Os::OpenBsd, Os::FreeBsd, Os::NetBsd, Os::DragonFly] {
            let c = cmds(os, Role::Client, DefaultRoutes::Suppressed);
            assert_eq!(
                rendered(c.set),
                [
                    "ifconfig tun0 10.0.0.1 10.0.0.2 up",
                    "ifconfig tun0 inet6 64:ff9b::10.0.0.1 64:ff9b::10.0.0.2 prefixlen 128 up",
                ],
                "{os:?}"
            );
            assert!(c.unset.is_empty(), "{os:?}");
        }
    }

    #[test]
    fn unknown_os_has_no_tables_for_either_role() {
        for role in [Role::Client, Role::Server] {
            assert_eq!(firewall_rules_cmds(Os::Other, role, DefaultRoutes::Enabled), None);
        }
    }

    #[test]
    fn every_template_renders_to_a_nonempty_argv_for_every_os_and_role() {
        let s = subs();
        for os in ALL_OS {
            for role in [Role::Client, Role::Server] {
                for routes in [DefaultRoutes::Enabled, DefaultRoutes::Suppressed] {
                    let c = cmds(os, role, routes);
                    for t in c.set.iter().chain(c.unset) {
                        let argv = s.render(t).unwrap();
                        assert!(!argv.is_empty());
                        assert!(!rendered(&[t])[0].contains('$'), "{t}");
                    }
                }
            }
        }
    }

    #[test]
    fn argv_splits_on_whitespace_without_shell_quoting_or_glob_handling() {
        let a = strs(subs().render("ip route add default dev $IF_NAME table 42069").unwrap());
        assert_eq!(a, ["ip", "route", "add", "default", "dev", "tun0", "table", "42069"]);
        let a = strs(subs().render("  echo\t'a b'  \"c\"\n").unwrap());
        assert_eq!(a, ["echo", "'a", "b'", "\"c\""]);
    }

    #[test]
    fn longer_placeholder_names_win_over_their_prefixes() {
        let a = strs(subs().render("x $LOCAL_TUN_IP6 $LOCAL_TUN_IP $REMOTE_TUN_IP6/96 $EXT_IF_NAME $EXT_IP").unwrap());
        assert_eq!(
            a,
            ["x", "64:ff9b::10.0.0.1", "10.0.0.1", "64:ff9b::10.0.0.2/96", "eth0", "203.0.113.9"]
        );
    }

    #[test]
    fn placeholders_substitute_mid_token_and_unknown_dollars_stay() {
        let a = strs(subs().render("a$IF_NAME-b $UNKNOWN $$IF_NAME $EXT_PORT").unwrap());
        assert_eq!(a, ["atun0-b", "$UNKNOWN", "$tun0", "41194"]);
    }

    #[test]
    fn substituted_values_are_not_split_or_rescanned() {
        let mut s = subs();
        s.if_name = b"a b $EXT_IP".to_vec();
        let a = strs(s.render("ifconfig $IF_NAME up").unwrap());
        assert_eq!(a, ["ifconfig", "a b $EXT_IP", "up"]);
    }

    #[test]
    fn empty_substitution_yields_an_empty_argument() {
        let mut s = subs();
        s.ext_gw_ip = Vec::new();
        let a = s.render("route add $EXT_IP $EXT_GW_IP").unwrap();
        assert_eq!(a.len(), 4);
        assert_eq!(a[3], b"");
        let a = s.render("a $EXT_GW_IP").unwrap();
        assert_eq!(a, [b"a".to_vec(), Vec::new()]);
    }

    #[test]
    fn blank_template_is_an_error() {
        assert_eq!(subs().render(""), Err(SplitError));
        assert_eq!(subs().render(" \t\n"), Err(SplitError));
    }

    #[test]
    fn at_most_63_arguments_are_allowed() {
        let ok = vec!["a"; 63].join(" ");
        assert_eq!(subs().render(&ok).unwrap().len(), 63);
        let bad = vec!["a"; 64].join(" ");
        assert_eq!(subs().render(&bad), Err(SplitError));
        let bad = vec!["a"; 65].join(" ");
        assert_eq!(subs().render(&bad), Err(SplitError));
    }

    #[test]
    fn command_buffer_limit_counts_terminators() {
        let fits = "a".repeat(4095);
        assert_eq!(subs().render(&fits).unwrap()[0].len(), 4095);
        let over = "a".repeat(4096);
        assert_eq!(subs().render(&over), Err(SplitError));
        let two = format!("{} {}", "a".repeat(2047), "b".repeat(2047));
        assert_eq!(subs().render(&two).unwrap().len(), 2);
        let two = format!("{} {}", "a".repeat(2047), "b".repeat(2048));
        assert_eq!(subs().render(&two), Err(SplitError));
    }

    #[test]
    fn substitution_needs_room_for_one_more_byte() {
        let mut s = subs();
        s.if_name = vec![b'x'; 4095];
        assert_eq!(s.render("$IF_NAME").unwrap()[0].len(), 4095);
        s.if_name = vec![b'x'; 4096];
        assert_eq!(s.render("$IF_NAME"), Err(SplitError));
        s.if_name = vec![b'x'; 4090];
        assert_eq!(s.render("$IF_NAME").unwrap().len(), 1);
        assert_eq!(s.render("aaaaaa $IF_NAME"), Err(SplitError));
        assert!(s.render("aaaa $IF_NAME").is_ok());
    }

    #[test]
    fn ipv6_addresses_are_cut_to_39_bytes() {
        assert_eq!(tun6_address(b"192.168.192.1"), b"64:ff9b::192.168.192.1");
        let long = vec![b'1'; 60];
        let v = tun6_address(&long);
        assert_eq!(v.len(), 39);
        assert!(v.starts_with(b"64:ff9b::1"));
    }

    #[test]
    fn gateway_value_is_cut_to_63_bytes() {
        let long = vec![b'9'; 100];
        let s = Substitutions::new(b"a", b"b", b"c", b"d", b"e", &long, b"f");
        assert_eq!(s.ext_gw_ip.len(), 63);
        assert_eq!(truncate_c_string(b"abc", 4), b"abc");
        assert_eq!(truncate_c_string(b"abcd", 4), b"abc");
        assert_eq!(truncate_c_string(b"ab\0cd", 16), b"ab");
        assert_eq!(truncate_c_string(b"abc", 0), b"");
    }

    #[derive(Default)]
    struct Recorder {
        ran: Vec<(String, bool)>,
        fail_on: Option<usize>,
        error: Option<RunError>,
    }

    impl CommandRunner for Recorder {
        fn run(&mut self, argv: &[Vec<u8>], silent: bool) -> Result<(), RunError> {
            let line = strs(argv.to_vec()).join(" ");
            self.ran.push((line, silent));
            if Some(self.ran.len() - 1) == self.fail_on {
                return Err(self.error.unwrap_or(RunError::Failed));
            }
            Ok(())
        }
    }

    fn plan(os: Os, role: Role, routes: DefaultRoutes) -> Plan {
        Plan { os, role, routes }
    }

    #[test]
    fn applying_runs_every_command_in_order_and_records_the_state() {
        let mut st = FirewallState::Unknown;
        let mut r = Recorder::default();
        let out = st.transition(plan(Os::FreeBsd, Role::Client, DefaultRoutes::Enabled), true, false, &subs(), &mut r);
        assert_eq!(out, FirewallOutcome::Done);
        assert_eq!(st, FirewallState::Applied);
        assert_eq!(r.ran.len(), 7);
        assert_eq!(r.ran[2].0, "route add 203.0.113.9 192.0.2.1");
        assert!(r.ran.iter().all(|(_, silent)| !silent));
    }

    #[test]
    fn repeating_the_current_state_runs_nothing() {
        let mut st = FirewallState::Applied;
        let mut r = Recorder::default();
        let p = plan(Os::Linux, Role::Server, DefaultRoutes::Enabled);
        assert_eq!(st.transition(p, true, false, &subs(), &mut r), FirewallOutcome::AlreadyInState);
        assert!(r.ran.is_empty());
        assert_eq!(st.transition(p, false, false, &subs(), &mut r), FirewallOutcome::Done);
        assert_eq!(st, FirewallState::Cleared);
        assert_eq!(r.ran.len(), 4);
        assert_eq!(st.transition(p, false, false, &subs(), &mut r), FirewallOutcome::AlreadyInState);
    }

    #[test]
    fn unknown_state_still_runs_teardown_once() {
        let mut st = FirewallState::Unknown;
        let mut r = Recorder::default();
        let p = plan(Os::MacOs, Role::Server, DefaultRoutes::Enabled);
        assert_eq!(st.transition(p, false, true, &subs(), &mut r), FirewallOutcome::Done);
        assert_eq!(st, FirewallState::Cleared);
        assert!(r.ran.is_empty());
    }

    #[test]
    fn first_failing_command_stops_the_sequence_and_keeps_the_state() {
        let mut st = FirewallState::Unknown;
        let mut r = Recorder { fail_on: Some(1), ..Default::default() };
        let out = st.transition(plan(Os::Linux, Role::Client, DefaultRoutes::Enabled), false, true, &subs(), &mut r);
        assert_eq!(
            out,
            FirewallOutcome::Failed { template: "ip -6 rule delete table 42069", errno: libc::ENOSPC }
        );
        assert_eq!(r.ran.len(), 2);
        assert!(r.ran.iter().all(|(_, silent)| *silent));
        assert_eq!(st, FirewallState::Unknown);
    }

    #[test]
    fn failure_carries_the_runner_errno() {
        let mut st = FirewallState::Unknown;
        let mut r = Recorder { fail_on: Some(0), error: Some(RunError::Errno(libc::EAGAIN)), ..Default::default() };
        let out = st.transition(plan(Os::Linux, Role::Server, DefaultRoutes::Enabled), true, false, &subs(), &mut r);
        assert_eq!(out, FirewallOutcome::Failed { template: "sysctl net.ipv4.ip_forward=1", errno: libc::EAGAIN });
        assert_eq!(RunError::Failed.errno(), libc::ENOSPC);
    }

    #[test]
    fn oversized_substitution_fails_with_enospc_before_running_anything_else() {
        let mut st = FirewallState::Unknown;
        let mut s = subs();
        s.if_name = vec![b'x'; 5000];
        let mut r = Recorder::default();
        let out = st.transition(plan(Os::Linux, Role::Server, DefaultRoutes::Enabled), true, false, &s, &mut r);
        assert_eq!(
            out,
            FirewallOutcome::Failed {
                template: "ip addr add $LOCAL_TUN_IP peer $REMOTE_TUN_IP dev $IF_NAME",
                errno: libc::ENOSPC
            }
        );
        assert_eq!(r.ran.len(), 1);
    }

    #[test]
    fn unsupported_os_is_reported_without_changing_state() {
        let mut st = FirewallState::Unknown;
        let mut r = Recorder::default();
        let out = st.transition(plan(Os::Other, Role::Server, DefaultRoutes::Enabled), true, false, &subs(), &mut r);
        assert_eq!(out, FirewallOutcome::Unsupported);
        assert_eq!(st, FirewallState::Unknown);
        assert_eq!(
            UNSUPPORTED_OS_MESSAGE,
            "Routing commands for that operating system have not been added yet.\n"
        );
    }

    #[test]
    fn failure_message_shows_the_unsubstituted_template() {
        assert_eq!(
            unable_to_run_stderr("route delete $EXT_IP", b"No space left on device"),
            b"Unable to run [route delete $EXT_IP]: [No space left on device]\n"
        );
    }

    #[test]
    fn gateway_change_needs_detected_difference_and_no_explicit_gateway() {
        let routed = DefaultRoutes::Enabled;
        assert_eq!(gateway_change(false, b"1.1.1.1", Some(b"1.1.1.1"), routed), None);
        assert_eq!(gateway_change(false, b"1.1.1.1", None, routed), None);
        assert_eq!(gateway_change(true, b"1.1.1.1", Some(b"2.2.2.2"), routed), None);
        assert_eq!(gateway_change(false, b"1.1.1.1", Some(b"2.2.2.2"), DefaultRoutes::Suppressed), None);
        let c = gateway_change(false, b"1.1.1.1", Some(b"2.2.2.2"), routed).unwrap();
        assert_eq!(c.message, b"Gateway changed from [1.1.1.1] to [2.2.2.2]\n");
        assert_eq!(c.new_gateway, b"2.2.2.2");
        assert_eq!(gateway_change(false, b"", Some(b"2.2.2.2"), routed).unwrap().message, b"Gateway changed from [] to [2.2.2.2]\n");
    }

    #[test]
    fn discovery_commands_per_os() {
        assert_eq!(
            default_gateway_command(Os::Linux),
            Some("ip route show default 2>/dev/null|awk '/default/{print $3}'")
        );
        assert_eq!(
            default_ext_if_command(Os::Linux),
            Some("ip route show default 2>/dev/null|awk '/default/{print $5}'")
        );
        for os in [Os::MacOs, Os::OpenBsd, Os::FreeBsd, Os::NetBsd, Os::DragonFly] {
            assert_eq!(
                default_gateway_command(os),
                Some("route -n get default 2>/dev/null|awk '/gateway:/{print $2;exit}'")
            );
            assert_eq!(
                default_ext_if_command(os),
                Some("route -n get default 2>/dev/null|awk '/interface:/{print $2;exit}'")
            );
        }
        assert_eq!(default_gateway_command(Os::Other), None);
        assert_eq!(default_ext_if_command(Os::Other), None);
    }

    #[test]
    fn command_output_parsing_follows_fgets_and_newline_stripping() {
        assert_eq!(parse_command_output(b"192.0.2.1\n"), Ok(Some(b"192.0.2.1".to_vec())));
        assert_eq!(parse_command_output(b"192.0.2.1"), Ok(Some(b"192.0.2.1".to_vec())));
        assert_eq!(parse_command_output(b"a\nb\n"), Ok(Some(b"a".to_vec())));
        assert_eq!(parse_command_output(b"\nabc\n"), Ok(None));
        assert_eq!(parse_command_output(b""), Err(NoOutput));
        let long = vec![b'z'; 100];
        assert_eq!(parse_command_output(&long), Ok(Some(vec![b'z'; 63])));
        let mut line = vec![b'z'; 62];
        line.push(b'\n');
        assert_eq!(parse_command_output(&line), Ok(Some(vec![b'z'; 62])));
        let mut line = vec![b'z'; 63];
        line.push(b'\n');
        assert_eq!(parse_command_output(&line), Ok(Some(vec![b'z'; 63])));
        assert_eq!(command_failed_stderr("ip x"), b"Command [ip x] failed]\n");
    }

    #[test]
    fn openbsd_notice_text() {
        assert_eq!(
            openbsd_pf_notice(b"10.0.0.2"),
            b"\nAdd the following rule to /etc/pf.conf:\npass out from 10.0.0.2 nat-to egress\n\n"
        );
    }

    #[test]
    fn host_os_matches_the_build_target() {
        let os = Os::host();
        if cfg!(target_os = "linux") {
            assert_eq!(os, Os::Linux);
        }
        if cfg!(target_os = "macos") {
            assert_eq!(os, Os::MacOs);
        }
    }
}
