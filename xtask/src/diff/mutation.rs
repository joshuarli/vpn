use super::case::{self, Case};
use super::run::{self, Impl, Job};
use super::{compare, norm};
use crate::container::{self, CONTAINER_REPO};
use crate::util::{self, Result};
use std::path::{Path, PathBuf};

struct Mutant {
    id: &'static str,
    area: &'static str,
    file: &'static str,
    find: &'static str,
    replace: &'static str,
}

const fn m(id: &'static str, area: &'static str, file: &'static str, find: &'static str, replace: &'static str) -> Mutant {
    Mutant { id, area, file, find, replace }
}

const MUTANTS: &[Mutant] = &[
    m("wire-counter-big-endian", "wire", "src/proto.rs", "out[8..].copy_from_slice(&self.counter.to_le_bytes());", "out[8..].copy_from_slice(&self.counter.to_be_bytes());"),
    m("wire-counter-starts-at-one", "wire", "src/proto.rs", "Sender { random, counter: 0 }", "Sender { random, counter: 1 }"),
    m("wire-tag-compare-prefix-only", "no-key", "src/proto.rs", "a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0", "a[..8] == b[..8]"),
    m("key-short-file-accepted", "key-file", "src/os/mod.rs", "if n == key.len() { KeyRead::Loaded(key) } else { KeyRead::Short }", "if n + 1 >= key.len() { KeyRead::Loaded(key) } else { KeyRead::Short }"),
    m("opt-mtu-min-69", "options", "src/mtu.rs", "pub const MIN_ARG_MTU: i32 = 68;", "pub const MIN_ARG_MTU: i32 = 69;"),
    m("opt-mtu-max-9001", "options", "src/mtu.rs", "pub const MAX_ARG_MTU: i32 = 9000;", "pub const MAX_ARG_MTU: i32 = 9001;"),
    m("opt-mtu-keeps-discovery", "options", "src/cli.rs", "                discover = false;\n                start += 2;", "                start += 2;"),
    m("opt-atoi-clamps", "options", "src/cli.rs", "    value as i32\n}", "    value.clamp(i32::MIN as i64, i32::MAX as i64) as i32\n}"),
    m("mode-server-prefix-match", "mode", "src/cli.rs", "let is_server = arg(start) == b\"server\";", "let is_server = arg(start).starts_with(b\"server\");"),
    m("genkey-alias-removed", "genkey", "src/cli.rs", "arg(1) == b\"genkey\" || arg(1) == b\"generate-key\"", "arg(1) == b\"genkey\""),
    m("genkey-overwrites-existing", "genkey", "src/tunnel.rs", "if os::path_exists(&c_path) {", "if false && os::path_exists(&c_path) {"),
    m("genkey-mode-0644", "genkey", "src/os/mod.rs", "libc::chmod(path.as_ptr(), 0o600) == 0", "libc::chmod(path.as_ptr(), 0o644) == 0"),
    m("exit-setup-failure-1", "exit-status", "src/cli.rs", "pub const EXIT_SETUP_FAILED: i32 = 255;", "pub const EXIT_SETUP_FAILED: i32 = 1;"),
    m("exit-usage-253", "exit-status", "src/cli.rs", "pub const EXIT_USAGE: i32 = 254;", "pub const EXIT_USAGE: i32 = 253;"),
    m("exit-early-failure-2", "exit-status", "src/cli.rs", "pub const EXIT_FAILURE: i32 = 1;", "pub const EXIT_FAILURE: i32 = 2;"),
    m("exit-loop-failure-not-done", "exit-status", "src/tunnel.rs", "while self.event_loop() == Flow::Continue {}\n        true", "while self.event_loop() == Flow::Continue {}\n        false"),
    m("exit-done-line-missing", "exit-status", "src/tunnel.rs", "os::out(b\"Done.\\n\");", ""),
    m("signal-handler-not-reset", "signals", "src/os/mod.rs", "    unsafe { libc::signal(sig, libc::SIG_DFL) };\n", ""),
    m("signal-sigterm-unhandled", "signals", "src/os/mod.rs", "        libc::signal(libc::SIGTERM, handler);\n", ""),
    m("reorder-window-1023", "reorder", "src/reorder.rs", "pub const WINDOW_SIZE: usize = 1024;", "pub const WINDOW_SIZE: usize = 1023;"),
    m("reorder-window-1025", "reorder", "src/reorder.rs", "pub const WINDOW_SIZE: usize = 1024;", "pub const WINDOW_SIZE: usize = 1025;"),
    m("reorder-jump-boundary-strict", "reorder", "src/reorder.rs", "if counter >= self.expected_counter.wrapping_add(WINDOW_SIZE as u64) {", "if counter > self.expected_counter.wrapping_add(WINDOW_SIZE as u64) {"),
    m("reorder-old-counter-inclusive", "reorder", "src/reorder.rs", "if counter < self.expected_counter {\n            self.stats.duplicated += 1;", "if counter <= self.expected_counter {\n            self.stats.duplicated += 1;"),
    m("reorder-jump-drops-packet", "reorder", "src/reorder.rs", "            sink.deliver(Delivery::Immediate, data);\n            return Outcome::Delivered;\n        }\n\n        self.buffer(", "            return Outcome::Delivered;\n        }\n\n        self.buffer("),
    m("reorder-jump-expects-same", "reorder", "src/reorder.rs", "self.expected_counter = counter.wrapping_add(1);\n            self.highest_processed = counter;\n            sink.deliver", "self.expected_counter = counter;\n            self.highest_processed = counter;\n            sink.deliver"),
    m("reorder-first-packet-baseline-one", "reorder", "src/reorder.rs", "            self.random_initialized = true;\n            self.expected_counter = counter;\n            self.window_base = counter;\n        }\n\n        if random != self.random_value {", "            self.random_initialized = true;\n            self.expected_counter = 1;\n            self.window_base = counter;\n        }\n\n        if random != self.random_value {"),
    m("timeout-at-least-2000", "timeout", "src/reorder.rs", "if now_ms.wrapping_sub(slot.timestamp.millis()) > TIMEOUT_MS {", "if now_ms.wrapping_sub(slot.timestamp.millis()) >= TIMEOUT_MS {"),
    m("timeout-1950", "timeout", "src/reorder.rs", "pub const TIMEOUT_MS: u64 = 2000;", "pub const TIMEOUT_MS: u64 = 1950;"),
    m("timeout-check-every-wakeup", "timeout", "src/reorder.rs", "now.since(self.last_check) >= CHECK_INTERVAL_MS", "now.since(self.last_check) >= 1"),
    m("timeout-check-interval-gt-50", "timeout", "src/reorder.rs", "now.since(self.last_check) >= CHECK_INTERVAL_MS", "now.since(self.last_check) > CHECK_INTERVAL_MS"),
    m("timeout-interval-60", "timeout", "src/reorder.rs", "pub const CHECK_INTERVAL_MS: u64 = 50;", "pub const CHECK_INTERVAL_MS: u64 = 60;"),
    m("timeout-skips-to-first-slot", "timeout", "src/reorder.rs", "if !have_min || slot.counter < min_counter {", "if !have_min {"),
    m("timeout-skip-needs-min-gap", "timeout", "src/reorder.rs", "if have_old && have_min && min_counter > self.expected_counter {", "if have_old && have_min && min_counter > self.expected_counter + 1 {"),
    m("epoch-change-ignored", "peer-epoch", "src/reorder.rs", "if random != self.random_value {", "if random != self.random_value && false {"),
    m("counter-wrap-window-saturates", "counter-wrap", "src/reorder.rs", "self.expected_counter.wrapping_add(WINDOW_SIZE as u64)", "self.expected_counter.saturating_add(WINDOW_SIZE as u64)"),
    m("counter-wrap-delivery-saturates", "counter-wrap", "src/reorder.rs", "self.expected_counter = self.expected_counter.wrapping_add(1);\n            self.highest_processed = counter;", "self.expected_counter = self.expected_counter.saturating_add(1);\n            self.highest_processed = counter;"),
    m("counter-wrap-signed-comparison", "counter-wrap", "src/reorder.rs", "if counter < self.expected_counter {\n            self.stats.duplicated += 1;", "if (counter as i64) < (self.expected_counter as i64) {\n            self.stats.duplicated += 1;"),
    m("oversize-inclusive", "oversize", "src/mtu.rs", "packet_len > (tun_mtu as isize as usize).wrapping_add(DATAGRAM_OVERHEAD)", "packet_len >= (tun_mtu as isize as usize).wrapping_add(DATAGRAM_OVERHEAD)"),
    m("oversize-overhead-46", "oversize", "src/mtu.rs", "const DATAGRAM_OVERHEAD: usize = 46 + TAG_LEN;", "const DATAGRAM_OVERHEAD: usize = 46;"),
    m("server-short-threshold-17", "server-input", "src/proto.rs", "if datagram.len() < HEADER_LEN {\n            return ServerRx::Ignored;", "if datagram.len() <= HEADER_LEN {\n            return ServerRx::Ignored;"),
    m("server-probe-echo-needs-tag", "server-input", "src/proto.rs", "if Header::from_bytes(&head).is_probe() {\n            return ServerRx::EchoProbe;", "if Header::from_bytes(&head).is_probe() && datagram.len() >= HEADER_LEN + TAG_LEN {\n            return ServerRx::EchoProbe;"),
    m("server-probe-not-echoed", "server-input", "src/proto.rs", "return ServerRx::EchoProbe;", "return ServerRx::Ignored;"),
    m("server-probe-magic-either-field", "server-input", "src/proto.rs", "self.random == PROBE_MAGIC && self.counter == PROBE_MAGIC", "self.random == PROBE_MAGIC || self.counter == PROBE_MAGIC"),
    m("server-peer-address-set-once", "server-input", "src/tunnel.rs", "self.client_addr = from;\n                if !self.client_connected {", "if !self.client_connected {\n                    self.client_addr = from;"),
    m("server-pollerr-reconnects", "server-input", "src/tunnel.rs", "if udp_events & (libc::POLLERR | libc::POLLHUP) != 0 && !self.is_server {", "if udp_events & (libc::POLLERR | libc::POLLHUP) != 0 {"),
    m("client-short-datagram-ignored", "client-input", "src/proto.rs", "return ClientRx::Reconnect(Rejection::TooSmall);", "return ClientRx::Ignored;"),
    m("client-auth-failure-ignored", "client-input", "src/proto.rs", "Err(f) => ClientRx::Reconnect(Rejection::Auth(f)),", "Err(_) => ClientRx::Ignored,"),
    m("client-late-probe-reply-dropped", "client-input", "src/proto.rs", "Ok(payload) => ClientRx::Accepted(Accepted { header: frame.header, payload }),", "Ok(_) if frame.header.is_probe() => ClientRx::Ignored,\n            Ok(payload) => ClientRx::Accepted(Accepted { header: frame.header, payload }),"),
    m("client-recv-error-no-reconnect", "client-input", "src/tunnel.rs", "os::perror(c\"UDP recv failed\");\n                return Flow::from_ok(self.reconnect());", "os::perror(c\"UDP recv failed\");\n                return Flow::Continue;"),
    m("send-server-eagain-logged", "send-errors", "src/tunnel.rs", "os::sendmsg3(self.udp_fd, &self.client_addr, &parts(&self.tx[..n])) < 0\n                    && !would_block(os::errno())", "os::sendmsg3(self.udp_fd, &self.client_addr, &parts(&self.tx[..n])) < 0"),
    m("send-server-error-stops", "send-errors", "src/tunnel.rs", "os::perror(c\"Unable to send UDP packet to client\");", "os::perror(c\"Unable to send UDP packet to client\");\n                    return Flow::Stop;"),
    m("send-client-eagain-reconnects", "send-errors", "src/tunnel.rs", "os::writev3(self.udp_fd, &parts(&self.tx[..n])) < 0 && !would_block(os::errno())", "os::writev3(self.udp_fd, &parts(&self.tx[..n])) < 0"),
    m("send-client-error-ignored", "send-errors", "src/tunnel.rs", "os::perror(c\"Unable to send UDP packet to server\");\n                    return Flow::from_ok(self.reconnect());", "os::perror(c\"Unable to send UDP packet to server\");"),
    m("reconnect-sleep-caps-at-two", "reconnect", "src/lib.rs", "if attempt > 3 { 3 } else { attempt }", "if attempt > 2 { 2 } else { attempt }"),
    m("reconnect-sleep-ramp-to-four", "reconnect", "src/lib.rs", "if attempt > 3 { 3 } else { attempt }", "if attempt > 4 { 3 } else { attempt }"),
    m("reconnect-99-attempts", "reconnect", "src/lib.rs", "pub const RECONNECT_ATTEMPTS: u32 = 100;", "pub const RECONNECT_ATTEMPTS: u32 = 99;"),
    m("reconnect-keeps-reorder-state", "reconnect", "src/tunnel.rs", "        self.reorder.reset();\n", ""),
    m("reconnect-resets-sender-counter", "reconnect", "src/tunnel.rs", "            if self.connect() {\n                return true;", "            if self.connect() {\n                self.sender = Sender::new(self.sender.random());\n                return true;"),
    m("reconnect-gateway-always-probed", "reconnect", "src/tunnel.rs", "if !self.explicit_gateway {", "if true {"),
    m("reconnect-gateway-buffer-65", "reconnect", "src/config.rs", "pub const GATEWAY_BUFFER: usize = 64;", "pub const GATEWAY_BUFFER: usize = 65;"),
    m("mtu-probe-min-577", "mtu-discovery", "src/mtu.rs", "pub const PROBE_MIN: i32 = 576;", "pub const PROBE_MIN: i32 = 577;"),
    m("mtu-probe-max-8999", "mtu-discovery", "src/mtu.rs", "pub const PROBE_MAX: i32 = 9000;", "pub const PROBE_MAX: i32 = 8999;"),
    m("mtu-probe-one-try", "mtu-discovery", "src/mtu.rs", "pub const PROBE_RETRIES: u32 = 2;", "pub const PROBE_RETRIES: u32 = 1;"),
    m("mtu-probe-timeout-400", "mtu-discovery", "src/mtu.rs", "pub const PROBE_TIMEOUT_MS: i32 = 500;", "pub const PROBE_TIMEOUT_MS: i32 = 400;"),
    m("mtu-overhead-47", "mtu-discovery", "src/mtu.rs", "pub const OVERHEAD: i32 = 46;", "pub const OVERHEAD: i32 = 47;"),
    m("mtu-failure-not-clamped", "mtu-discovery", "src/mtu.rs", "if tun_mtu < PROBE_MIN {", "if false {"),
    m("mtu-equal-value-readopted", "mtu-discovery", "src/mtu.rs", "if discovered > 0 && discovered != current_tun_mtu {", "if discovered > 0 {"),
    m("mtu-reply-length-at-least", "mtu-discovery", "src/proto.rs", "Ok(payload) => payload.len() == expected_len,", "Ok(payload) => payload.len() >= expected_len,"),
    m("mtu-effective-minus-15", "mtu-discovery", "src/mtu.rs", "base_mtu.wrapping_sub(MAC_OVERHEAD)", "base_mtu.wrapping_sub(MAC_OVERHEAD - 1)"),
    m("socket-buffer-2mib", "socket-setup", "src/os/mod.rs", "pub const SOCKET_BUFFER_BYTES: c_int = 4 * 1024 * 1024;", "pub const SOCKET_BUFFER_BYTES: c_int = 2 * 1024 * 1024;"),
    m("socket-not-dual-stack", "socket-setup", "src/os/mod.rs", "setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0);", "setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1);"),
    m("socket-client-sndbuf-missing", "socket-setup", "src/os/mod.rs", "    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, SOCKET_BUFFER_BYTES);\n    free_lookup(res);\n    fd", "    free_lookup(res);\n    fd"),
    m("tun-flags-packet-info", "tun-framing", "src/os/linux.rs", "const IFF_NO_PI: i16 = 0x1000;", "const IFF_NO_PI: i16 = 0;"),
    m("tun-write-eagain-fails", "tun-framing", "src/os/mod.rs", "            if e == libc::EAGAIN {\n                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };", "            if false {\n                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };"),
    m("tun-read-eintr-not-retried", "tun-framing", "src/os/mod.rs", "if n < 0 && errno() == libc::EINTR && !exit_signal_received() {\n            continue;", "if false {\n            continue;"),
    m("tun-hup-keeps-running", "tun-framing", "src/tunnel.rs", "os::out(b\"HUP (tun)\\n\");\n            return Flow::Stop;", "os::out(b\"HUP (tun)\\n\");"),
    m("config-client-set-order", "config-commands", "src/config.rs", "    \"ip -6 route add default dev $IF_NAME table 42069\",\n    \"ip rule add not fwmark 42069 table 42069\",", "    \"ip rule add not fwmark 42069 table 42069\",\n    \"ip -6 route add default dev $IF_NAME table 42069\","),
    m("config-server-set-missing-last", "config-commands", "src/config.rs", "    \"iptables -t filter -A FORWARD -i $IF_NAME -o $EXT_IF_NAME -j ACCEPT\",\n];", "];"),
    m("config-client-teardown-incomplete", "config-commands", "src/config.rs", "    \"ip -6 rule delete table main suppress_prefixlength 0\",\n    \"iptables -t raw -D PREROUTING", "    \"iptables -t raw -D PREROUTING"),
    m("config-substitution-order", "config-commands", "src/config.rs", "            (b\"$LOCAL_TUN_IP6\", &self.local_tun_ip6),\n            (b\"$REMOTE_TUN_IP6\", &self.remote_tun_ip6),\n            (b\"$LOCAL_TUN_IP\", &self.local_tun_ip),", "            (b\"$LOCAL_TUN_IP\", &self.local_tun_ip),\n            (b\"$LOCAL_TUN_IP6\", &self.local_tun_ip6),\n            (b\"$REMOTE_TUN_IP6\", &self.remote_tun_ip6),"),
    m("config-ip6-prefix", "config-commands", "src/config.rs", "let mut v = b\"64:ff9b::\".to_vec();", "let mut v = b\"64:ff9a::\".to_vec();"),
    m("config-server-failure-exit-code", "config-commands", "src/tunnel.rs", "if !firewall.apply(true, false) {\n            return cli::EXIT_SETUP_FAILED;", "if !firewall.apply(true, false) {\n            return cli::EXIT_FAILURE;"),
];

const CONTROL: &str = "control";
const COPIED: &[&str] = &["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "src", "xtask"];
const MUTANT_JOB_TIMEOUT_S: u64 = 30;

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to).map_err(|e| format!("create {}: {e}", to.display()))?;
        for entry in std::fs::read_dir(from).map_err(|e| format!("read {}: {e}", from.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::copy(from, to).map(|_| ()).map_err(|e| format!("copy {}: {e}", from.display()))
    }
}

fn mutants_dir() -> PathBuf {
    util::repo_root().join(".work/mutants")
}

fn apply_patch(tree: &Path, mutant: &Mutant) -> Result<()> {
    let path = tree.join(mutant.file);
    let text = util::read(&path)?;
    let live = text.find("#[cfg(test)]").unwrap_or(text.len());
    let (code, tests) = text.split_at(live);
    let hits = code.matches(mutant.find).count();
    if hits != 1 {
        return Err(format!("mutant {}: `{}` matches {hits} times in {} (need exactly 1)", mutant.id, mutant.find.escape_debug(), mutant.file));
    }
    let patched = format!("{}{tests}", code.replacen(mutant.find, mutant.replace, 1));
    std::fs::write(&path, patched).map_err(|e| format!("write {}: {e}", path.display()))
}

fn prepare(mutant: Option<&Mutant>) -> Result<String> {
    let id = mutant.map_or(CONTROL, |m| m.id);
    let dir = mutants_dir().join(id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("clean {}: {e}", dir.display()))?;
    }
    let tree = dir.join("tree");
    let root = util::repo_root();
    for item in COPIED {
        copy_tree(&root.join(item), &tree.join(item))?;
    }
    if let Some(mutant) = mutant {
        apply_patch(&tree, mutant)?;
    }
    Ok(id.to_owned())
}

fn build_all(ids: &[String]) -> Result<Vec<String>> {
    let mut script = String::from("set -u; export CARGO_TARGET_DIR=/target/mutant-build; ");
    for id in ids {
        script.push_str(&format!(
            "cd {CONTAINER_REPO}/.work/mutants/{id}/tree; find . -name '*.rs' -exec touch {{}} +; \
             if cargo build -q --locked -p twice >{CONTAINER_REPO}/.work/mutants/{id}/build.log 2>&1; then \
               mkdir -p /target/mutants/{id}; cp /target/mutant-build/debug/twice /target/mutants/{id}/twice.new && mv -f /target/mutants/{id}/twice.new /target/mutants/{id}/twice; \
             else echo \"BUILD-FAILED {id}\"; fi; "
        ));
    }
    let out = container::Run::new(&script).capture()?;
    Ok(out.lines().filter_map(|l| l.strip_prefix("BUILD-FAILED ").map(str::to_owned)).collect())
}

struct Verdict {
    failing: Vec<String>,
}

fn replay(id: &str, cases: &[Case]) -> Result<Verdict> {
    let mut jobs = Vec::new();
    for c in cases {
        norm::validate(&c.header.normalize)?;
        let mut job = Job::new(Impl::Rust, c, false)?;
        job.bin = Some(format!("/target/mutants/{id}/twice"));
        job.timeout_s = MUTANT_JOB_TIMEOUT_S;
        jobs.push(job);
    }
    let outs = run::run_batch(&jobs)?;
    let mut failing = Vec::new();
    for (c, events) in cases.iter().zip(outs) {
        let exp = norm::apply(&c.header.normalize, &c.expected);
        let act = norm::apply(&c.header.normalize, &events);
        if compare::compare(&exp, &act).is_some() {
            failing.push(c.header.name.clone());
        }
    }
    Ok(Verdict { failing })
}

pub fn run() -> Result<()> {
    let cases = case::all_paths()?.iter().map(|p| Case::load(p)).collect::<Result<Vec<_>>>()?;
    if let Some(c) = cases.iter().find(|c| c.expected.is_empty()) {
        return Err(format!("case {} has no recorded golden events (run --record)", c.header.name));
    }
    let mut ids = vec![prepare(None)?];
    for mutant in MUTANTS {
        ids.push(prepare(Some(mutant))?);
    }
    eprintln!("building {} Rust variants", ids.len());
    let broken = build_all(&ids)?;
    if !broken.is_empty() {
        return Err(format!("variants failed to build (see .work/mutants/<id>/build.log): {}", broken.join(", ")));
    }
    let control = replay(CONTROL, &cases)?;
    if !control.failing.is_empty() {
        return Err(format!("unmodified control build disagrees with the goldens on {} cases, first {}", control.failing.len(), control.failing[0]));
    }
    println!("control: unmodified copy passes all {} cases", cases.len());
    println!("{:<44} {:<16} result", "mutant", "area");
    let mut survived = Vec::new();
    for mutant in MUTANTS {
        let verdict = replay(mutant.id, &cases)?;
        match verdict.failing.first() {
            Some(first) => println!("{:<44} {:<16} KILLED by {} case(s), first {first}", mutant.id, mutant.area, verdict.failing.len()),
            None => {
                println!("{:<44} {:<16} SURVIVED", mutant.id, mutant.area);
                survived.push(mutant.id);
            }
        }
    }
    let areas: std::collections::BTreeSet<&str> = MUTANTS.iter().map(|m| m.area).collect();
    println!("{} mutants over {} areas, {} survived", MUTANTS.len(), areas.len(), survived.len());
    if survived.is_empty() { Ok(()) } else { Err(format!("surviving mutants: {}", survived.join(", "))) }
}
