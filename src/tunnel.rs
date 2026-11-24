use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::cli::{self, Command, Run};
use crate::config::{
    self, DefaultRoutes, FirewallOutcome, FirewallState, Os, Plan, Substitutions,
};
use crate::crypto::{self, HiAeCipher, UnsupportedCpu};
use crate::mtu::{self, Discovery, Effect};
use crate::os::{self, Fd, IfName, KeyRead, OsFailure, Shell, SockAddr};
use crate::proto::{
    Accepted, ClientRx, Codec, ENCRYPTED_BANNER, HEADER_LEN, Header, KEY_LEN, MAX_DATAGRAM_LEN,
    MAX_PACKET_LEN, ProbeSender, Sender, ServerRx, TAG_LEN,
};
use crate::reorder::{Delivery, Diag, Outcome, Reorder, Sink, Timespec};
use crate::{EVENT_POLL_TIMEOUT_MS, RECONNECT_ATTEMPTS, reconnect_delay_secs};

const POLLFD_TUN: usize = 0;
const POLLFD_UDP: usize = 1;

fn c_string(bytes: &[u8]) -> CString {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    CString::new(&bytes[..end]).unwrap_or_default()
}

fn would_block(errno: i32) -> bool {
    errno == libc::EAGAIN || errno == libc::EWOULDBLOCK
}

/// Runs the program as `argv[0] args...` would and never returns.
pub fn main() -> ! {
    os::reset_sigpipe();
    let args: Vec<OsString> = std::env::args_os().collect();
    let code = match cli::parse(&args) {
        Err(e) => {
            os::err(&e.stderr());
            os::out(e.stdout().as_bytes());
            e.exit_code()
        }
        Ok(Command::GenKey { path }) => genkey(&path),
        Ok(Command::Run(run)) => start(*run),
    };
    os::exit(code)
}

fn genkey(path: &OsStr) -> i32 {
    let c_path = c_string(path.as_bytes());
    if os::path_exists(&c_path) {
        os::err(&cli::genkey_exists_stderr(path));
        return cli::EXIT_FAILURE;
    }
    let mut key = [0u8; KEY_LEN];
    if !os::random_bytes(&mut key) {
        os::err(cli::GENKEY_RANDOM_FAILED_STDERR.as_bytes());
        return cli::EXIT_FAILURE;
    }
    match os::write_new_file(&c_path, &key) {
        os::CreateOutcome::CreateFailed => {
            os::err(&cli::genkey_create_failed_stderr(path));
            return cli::EXIT_FAILURE;
        }
        os::CreateOutcome::WriteFailed => {
            os::err(cli::GENKEY_WRITE_FAILED_STDERR.as_bytes());
            return cli::EXIT_FAILURE;
        }
        os::CreateOutcome::Done => {}
    }
    if !os::chmod_private(&c_path) {
        os::err(cli::GENKEY_CHMOD_FAILED_STDERR.as_bytes());
    }
    crypto::wipe(&mut key);
    os::out(&cli::genkey_success_stdout(path));
    0
}

fn load_key(path: &OsStr) -> Result<[u8; KEY_LEN], i32> {
    match os::read_key_file(&c_string(path.as_bytes())) {
        KeyRead::OpenFailed => {
            os::err(&cli::key_open_failed_stderr(path));
            Err(cli::EXIT_FAILURE)
        }
        KeyRead::Short => {
            os::err(cli::KEY_FILE_TOO_SHORT_STDERR.as_bytes());
            Err(cli::EXIT_FAILURE)
        }
        KeyRead::Loaded(key) => {
            os::out(ENCRYPTED_BANNER.as_bytes());
            Ok(key)
        }
    }
}

struct Firewall {
    plan: Plan,
    state: FirewallState,
    subs: Substitutions,
    shell: Shell,
}

impl Firewall {
    /// `firewall_rules(set, silent)`: false when a command failed.
    fn apply(&mut self, set: bool, silent: bool) -> bool {
        match self.state.transition(self.plan, set, silent, &self.subs, &mut self.shell) {
            FirewallOutcome::AlreadyInState | FirewallOutcome::Done => true,
            FirewallOutcome::Unsupported => {
                os::err(config::UNSUPPORTED_OS_MESSAGE.as_bytes());
                true
            }
            FirewallOutcome::Failed { template, errno } => {
                os::set_errno(errno);
                os::err(&config::unable_to_run_stderr(template, &os::strerror(errno)));
                false
            }
        }
    }
}

fn start(run: Run) -> i32 {
    let is_server = run.mode.is_server();
    let explicit_gateway = run.gateway.is_some();

    let gateway = match &run.gateway {
        Some(g) => Some(g.as_bytes().to_vec()),
        None => os::default_gateway(),
    };
    let ext_gw_ip = config::truncate_c_string(gateway.as_deref().unwrap_or(b""), config::GATEWAY_BUFFER);
    if gateway.is_none() && !is_server {
        os::err(b"Unable to automatically determine the gateway IP\n");
        return cli::EXIT_FAILURE;
    }
    let ext_if_name = os::default_ext_if_name();
    if ext_if_name.is_none() && is_server {
        os::err(b"Unable to automatically determine the external interface\n");
        return cli::EXIT_FAILURE;
    }

    let mut key = match load_key(&run.key_file) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cipher = HiAeCipher::new(key);
    crypto::wipe(&mut key);
    let cipher = match cipher {
        Ok(c) => c,
        Err(UnsupportedCpu) => {
            os::err(UnsupportedCpu::message().as_bytes());
            return cli::EXIT_FAILURE;
        }
    };
    let codec = Codec::new(cipher);

    let mut packet_random = [0u8; 8];
    if !os::random_bytes(&mut packet_random) {
        os::perror(c"Failed to read from /dev/urandom");
        return cli::EXIT_FAILURE;
    }

    let wanted_name = run.tun_name.as_deref().map(OsStr::as_bytes);
    let Ok((tun_fd, if_name)) = os::tun_create(wanted_name) else {
        os::perror(c"tun device creation");
        return cli::EXIT_FAILURE;
    };
    let if_name_len = if_name.iter().position(|&b| b == 0).unwrap_or(if_name.len());
    os::out(&[b"Interface: [".as_slice(), &if_name[..if_name_len], b"]\n"].concat());

    let tun_mtu = run.mtu.initial();
    os::out(mtu::mtu_banner(tun_mtu).as_bytes());
    if os::tun_set_mtu(&if_name, mtu::effective_tun_mtu(tun_mtu)) != 0 {
        os::perror(c"mtu");
    }
    #[cfg(target_os = "openbsd")]
    os::pledge_runtime();

    let port = c_string(run.port.as_bytes());
    let mut firewall = Firewall {
        plan: Plan { os: Os::host(), role: run.mode.role(), routes: DefaultRoutes::Enabled },
        state: FirewallState::Unknown,
        subs: Substitutions::new(
            run.local_tun_ip.as_bytes(),
            run.remote_tun_ip.as_bytes(),
            b"",
            port.to_bytes(),
            ext_if_name.as_deref().unwrap_or(b""),
            &ext_gw_ip,
            &if_name[..if_name_len],
        ),
        shell: Shell,
    };

    let bind_or_server = run.mode.server_ip_or_name().map(|n| c_string(n.as_bytes()));
    let mut server_ip = CString::default();
    if let Some(name) = &bind_or_server {
        match os::resolve_ip(name) {
            Ok(ip) => {
                firewall.subs.ext_ip.clone_from(&ip);
                server_ip = c_string(&ip);
            }
            Err(OsFailure) => {
                firewall.apply(false, true);
                return cli::EXIT_FAILURE;
            }
        }
    }
    if is_server {
        if !firewall.apply(true, false) {
            return cli::EXIT_SETUP_FAILED;
        }
        #[cfg(target_os = "openbsd")]
        os::out(&config::openbsd_pf_notice(run.remote_tun_ip.as_bytes()));
    } else {
        firewall.apply(false, true);
    }

    os::install_exit_handlers();
    let mut tunnel = Tunnel::new(Setup {
        is_server,
        explicit_gateway,
        discover_mtu: run.mtu.discovers(),
        tun_fd,
        tun_mtu,
        if_name,
        bind_or_server,
        server_ip,
        port,
        firewall,
        codec,
        sender: Sender::new(u64::from_ne_bytes(packet_random)),
        probes: ProbeSender::new(u64::from_ne_bytes(packet_random)),
    });
    let ok = tunnel.doit();
    tunnel.firewall.apply(false, false);
    if !ok {
        return cli::EXIT_SETUP_FAILED;
    }
    os::out(b"Done.\n");
    0
}

struct Setup {
    is_server: bool,
    explicit_gateway: bool,
    discover_mtu: bool,
    tun_fd: Fd,
    tun_mtu: i32,
    if_name: IfName,
    bind_or_server: Option<CString>,
    server_ip: CString,
    port: CString,
    firewall: Firewall,
    codec: Codec<HiAeCipher>,
    sender: Sender,
    probes: ProbeSender,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

impl Flow {
    fn from_ok(ok: bool) -> Flow {
        if ok { Flow::Continue } else { Flow::Stop }
    }
}

struct TunSink {
    tun_fd: Fd,
}

impl Sink for TunSink {
    fn deliver(&mut self, kind: Delivery, packet: &[u8]) {
        if os::tun_write(self.tun_fd, packet) != packet.len() as isize {
            os::perror(match kind {
                Delivery::Immediate => c"tun_write",
                Delivery::Buffered => c"tun_write (buffered)",
            });
        }
    }

    fn diag(&mut self, diag: &Diag) {
        os::err_display(diag);
    }
}

fn parts(datagram: &[u8]) -> [&[u8]; 3] {
    let tag_at = datagram.len() - TAG_LEN;
    [&datagram[..HEADER_LEN], &datagram[HEADER_LEN..tag_at], &datagram[tag_at..]]
}

struct Tunnel {
    is_server: bool,
    explicit_gateway: bool,
    discover_mtu: bool,
    tun_fd: Fd,
    udp_fd: Fd,
    tun_mtu: i32,
    if_name: IfName,
    bind_or_server: Option<CString>,
    server_ip: CString,
    port: CString,
    firewall: Firewall,
    /// Server only: where to send, set by the last datagram the reorder stage accepted.
    client: Option<SockAddr>,
    sender: Sender,
    /// Lives as long as the process so probes stay unique across reconnects.
    probes: ProbeSender,
    codec: Codec<HiAeCipher>,
    reorder: Reorder,
    fds: [libc::pollfd; 2],
    tun_in: Box<[u8]>,
    rx: Box<[u8]>,
    tx: Box<[u8]>,
    scratch: Box<[u8]>,
}

impl Tunnel {
    fn new(setup: Setup) -> Tunnel {
        Tunnel {
            is_server: setup.is_server,
            explicit_gateway: setup.explicit_gateway,
            discover_mtu: setup.discover_mtu,
            tun_fd: setup.tun_fd,
            udp_fd: -1,
            tun_mtu: setup.tun_mtu,
            if_name: setup.if_name,
            bind_or_server: setup.bind_or_server,
            server_ip: setup.server_ip,
            port: setup.port,
            firewall: setup.firewall,
            client: None,
            sender: setup.sender,
            probes: setup.probes,
            codec: setup.codec,
            reorder: Reorder::new(os::monotonic()),
            fds: [
                libc::pollfd { fd: setup.tun_fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: 0, events: 0, revents: 0 },
            ],
            tun_in: vec![0u8; MAX_PACKET_LEN].into_boxed_slice(),
            rx: vec![0u8; MAX_DATAGRAM_LEN].into_boxed_slice(),
            tx: vec![0u8; MAX_DATAGRAM_LEN].into_boxed_slice(),
            scratch: vec![0u8; MAX_PACKET_LEN].into_boxed_slice(),
        }
    }

    fn doit(&mut self) -> bool {
        if self.is_server {
            self.udp_fd = os::udp_server_socket(self.bind_or_server.as_deref(), &self.port);
            if self.udp_fd == -1 {
                os::perror(c"Unable to set up UDP server");
                return false;
            }
            os::set_nonblocking(self.udp_fd);
            self.fds[POLLFD_UDP] =
                libc::pollfd { fd: self.udp_fd, events: libc::POLLIN, revents: 0 };
        }
        if !self.is_server && !self.reconnect() {
            let text = [
                b"Unable to connect to server: [".as_slice(),
                &os::strerror(os::errno()),
                b"]\n",
            ]
            .concat();
            os::err(&text);
            return false;
        }
        while self.event_loop() == Flow::Continue {}
        true
    }

    fn reconnect(&mut self) -> bool {
        self.client = None;
        if self.udp_fd != -1 {
            os::close(self.udp_fd);
            self.udp_fd = -1;
            self.fds[POLLFD_UDP] = libc::pollfd { fd: -1, events: 0, revents: 0 };
        }
        self.reorder.reset();
        if self.is_server {
            return true;
        }
        let mut attempt = 0u32;
        while !os::exit_signal_received() && attempt < RECONNECT_ATTEMPTS {
            os::out(b"Trying to reconnect\n");
            os::sleep(reconnect_delay_secs(attempt));
            if self.connect() {
                return true;
            }
            attempt += 1;
        }
        false
    }

    fn connect(&mut self) -> bool {
        if !self.explicit_gateway {
            let detected = os::default_gateway();
            if let Some(change) = config::gateway_change(
                false,
                &self.firewall.subs.ext_gw_ip,
                detected.as_deref(),
                DefaultRoutes::Enabled,
            ) {
                os::out(&change.message);
                self.firewall.apply(false, false);
                self.firewall.subs.ext_gw_ip = change.new_gateway;
                self.firewall.apply(true, false);
            }
        }
        self.udp_fd = os::udp_client_socket(&self.server_ip, &self.port);
        if self.udp_fd == -1 {
            os::perror(c"UDP client connection failed");
            return false;
        }
        os::set_nonblocking(self.udp_fd);
        self.firewall.apply(true, false);
        self.fds[POLLFD_UDP] = libc::pollfd { fd: self.udp_fd, events: libc::POLLIN, revents: 0 };
        os::out(b"Connected\n");

        if self.discover_mtu {
            let discovered = self.discover();
            if let Some(adopted) = mtu::adopt_discovered(self.tun_mtu, discovered) {
                self.tun_mtu = adopted.tun_mtu;
                os::out(adopted.message.as_bytes());
                if os::tun_set_mtu(&self.if_name, adopted.effective) != 0 {
                    os::perror(c"Failed to set discovered MTU");
                }
            }
        }
        true
    }

    fn discover(&mut self) -> i32 {
        let mut discovery = Discovery::new(self.is_server);
        // The probe in flight and its payload length; `AwaitReply` always follows `SendProbe`.
        let mut in_flight: Option<(Header, usize)> = None;
        loop {
            match discovery.step() {
                Effect::Print { text, flush } => {
                    os::out(text.as_bytes());
                    if flush {
                        os::out_flush();
                    }
                }
                Effect::SendProbe { data_len } => {
                    let probe = self.probes.next_header();
                    in_flight = Some((probe, data_len));
                    let n = self.codec.seal_probe(&probe, data_len, &mut self.tx);
                    let sent = os::writev3(self.udp_fd, &parts(&self.tx[..n]));
                    discovery.sent(sent >= 0);
                }
                Effect::AwaitReply { timeout_ms } => {
                    let valid = in_flight.is_some_and(|(probe, len)| {
                        self.await_probe_reply(timeout_ms, &probe, len)
                    });
                    discovery.replied(valid);
                }
                Effect::Done { tun_mtu } => return tun_mtu,
            }
        }
    }

    fn await_probe_reply(&mut self, timeout_ms: i32, probe: &Header, expected_len: usize) -> bool {
        let mut pfd = libc::pollfd { fd: self.udp_fd, events: libc::POLLIN, revents: 0 };
        if os::poll(std::slice::from_mut(&mut pfd), timeout_ms) <= 0 {
            return false;
        }
        let n = os::recv(self.udp_fd, &mut self.rx);
        if n < (HEADER_LEN + TAG_LEN) as isize {
            return false;
        }
        self.codec.is_probe_reply(&self.rx[..n as usize], probe, expected_len, &mut self.scratch)
    }

    fn event_loop(&mut self) -> Flow {
        if os::exit_signal_received() {
            return Flow::Stop;
        }
        let mut sink = TunSink { tun_fd: self.tun_fd };
        self.reorder.tick(os::monotonic(), os::monotonic, &mut sink);

        if os::poll(&mut self.fds, EVENT_POLL_TIMEOUT_MS) == -1 {
            return if os::errno() == libc::EINTR { Flow::Continue } else { Flow::Stop };
        }

        let tun_events = self.fds[POLLFD_TUN].revents;
        if tun_events & (libc::POLLERR | libc::POLLHUP) != 0 {
            os::out(b"HUP (tun)\n");
            return Flow::Stop;
        }
        if tun_events & libc::POLLIN != 0 {
            let len = os::tun_read(self.tun_fd, &mut self.tun_in);
            if len <= 0 {
                os::perror(c"tun_read");
                return Flow::Stop;
            }
            let len = len as usize;
            if mtu::exceeds_safe_size(len, self.tun_mtu) {
                os::err_display(&format_args!("{} ({len} bytes)\n", mtu::OVERSIZED_PACKET_PREFIX));
                return Flow::Continue;
            }
            if let (true, Some(client)) = (self.is_server, &self.client) {
                let header = self.sender.next_header();
                let n = self.codec.seal(&header, &self.tun_in[..len], &mut self.tx);
                if os::sendmsg3(self.udp_fd, client, &parts(&self.tx[..n])) < 0
                    && !would_block(os::errno())
                {
                    os::perror(c"Unable to send UDP packet to client");
                }
            } else if !self.is_server && self.udp_fd != -1 {
                let header = self.sender.next_header();
                let n = self.codec.seal(&header, &self.tun_in[..len], &mut self.tx);
                if os::writev3(self.udp_fd, &parts(&self.tx[..n])) < 0 && !would_block(os::errno())
                {
                    os::perror(c"Unable to send UDP packet to server");
                    return Flow::from_ok(self.reconnect());
                }
            }
        }

        let udp_events = self.fds[POLLFD_UDP].revents;
        if udp_events & (libc::POLLERR | libc::POLLHUP) != 0 && !self.is_server {
            os::out(b"UDP socket error\n");
            return Flow::from_ok(self.reconnect());
        }
        if udp_events & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            return if self.is_server { self.server_receive() } else { self.client_receive() };
        }
        Flow::Continue
    }

    fn server_receive(&mut self) -> Flow {
        let mut from = SockAddr::for_receive();
        let received = os::recv_from(self.udp_fd, &mut self.rx, &mut from);
        if received < HEADER_LEN as isize {
            if received < 0 && !would_block(os::errno()) {
                os::perror(c"UDP recvfrom failed");
            }
            return Flow::Continue;
        }
        let datagram = &self.rx[..received as usize];
        match self.codec.server_receive(datagram, &mut self.scratch) {
            ServerRx::Ignored => {}
            ServerRx::EchoProbe => {
                if os::send_to(self.udp_fd, datagram, &from) < 0 {
                    os::perror(c"Failed to echo MTU probe");
                }
            }
            ServerRx::Rejected(rejection) => os::err_display(&rejection),
            ServerRx::Accepted(accepted) => {
                let mut sink = TunSink { tun_fd: self.tun_fd };
                let now = os::monotonic();
                if accept_from_client(&mut self.client, &mut self.reorder, now, accepted, from, &mut sink) {
                    let host = os::numeric_host(&from);
                    os::out(&[b"Client connected from [".as_slice(), &host, b"]\n"].concat());
                }
            }
        }
        Flow::Continue
    }

    fn client_receive(&mut self) -> Flow {
        let received = os::recv(self.udp_fd, &mut self.rx);
        if received < HEADER_LEN as isize {
            if received < 0 && !would_block(os::errno()) {
                os::perror(c"UDP recv failed");
                return Flow::from_ok(self.reconnect());
            }
            return Flow::Continue;
        }
        let datagram = &self.rx[..received as usize];
        match self.codec.client_receive(datagram, &mut self.scratch) {
            ClientRx::Ignored => Flow::Continue,
            ClientRx::Reconnect(rejection) => {
                os::err_display(&rejection);
                Flow::from_ok(self.reconnect())
            }
            ClientRx::Accepted(Accepted { header, payload }) => {
                let mut sink = TunSink { tun_fd: self.tun_fd };
                self.reorder.process(os::monotonic(), header.random, header.counter, payload, &mut sink);
                Flow::Continue
            }
        }
    }
}

/// Server handling of one authenticated datagram from `from`. The reorder stage decides first; only
/// a datagram it did not drop as a duplicate or stale packet moves the peer to `from`, so a replay
/// from another address cannot redirect the tunnel. Returns true when this datagram established
/// the peer.
fn accept_from_client<A, S: Sink>(
    peer: &mut Option<A>,
    reorder: &mut Reorder,
    now: Timespec,
    accepted: Accepted<'_>,
    from: A,
    sink: &mut S,
) -> bool {
    let outcome =
        reorder.process(now, accepted.header.random, accepted.header.counter, accepted.payload, sink);
    if outcome == Outcome::Dropped {
        return false;
    }
    peer.replace(from).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Header;

    #[derive(Default)]
    struct Delivered(Vec<Vec<u8>>);

    impl Sink for Delivered {
        fn deliver(&mut self, _: Delivery, packet: &[u8]) {
            self.0.push(packet.to_vec());
        }
        fn diag(&mut self, _: &Diag) {}
    }

    fn data(random: u64, counter: u64, payload: &[u8]) -> Accepted<'_> {
        Accepted { header: Header { random, counter }, payload }
    }

    #[test]
    fn a_replayed_duplicate_from_another_address_does_not_move_the_peer() {
        let mut reorder = Reorder::new(Timespec::default());
        let mut sink = Delivered::default();
        let mut peer = None;
        let now = Timespec::default();
        assert!(accept_from_client(&mut peer, &mut reorder, now, data(5, 1, b"a"), "client", &mut sink));
        assert!(!accept_from_client(&mut peer, &mut reorder, now, data(5, 1, b"a"), "attacker", &mut sink));
        assert_eq!(peer, Some("client"));
        assert!(!accept_from_client(&mut peer, &mut reorder, now, data(5, 2, b"b"), "roamed", &mut sink));
        assert_eq!(peer, Some("roamed"));
        assert_eq!(sink.0, [b"a".to_vec(), b"b".to_vec()]);
    }
}
