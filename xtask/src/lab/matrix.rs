use super::common::{self, Binaries, Impl};
use crate::container;
use crate::oracle::ORACLE_BINARY;
use crate::util::Result;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SCRIPT: &str = include_str!("matrix.sh");

pub const USAGE: &str = "usage: cargo xtask lab matrix [--rust-target <triple>] [--jobs <n>] [--only <client>/<server>[/key|/nokey]]...

Runs c/c, c/rust, rust/c and rust/rust, each keyed and without a key, in separate containers.
--rust-target  run the release binary built for that triple (aarch64-unknown-linux-musl)
--jobs         cells run at once (default 4)
--only         run just the named cell; repeatable. The matching C/C cell also runs as the routing reference.";

const GROUPS: [&str; 7] = ["setup", "tunnel", "routing", "routed", "reconnect", "mtu", "teardown"];

const COMMON_CHECKS: &[&str] = &[
    "setup.server",
    "setup.client",
    "setup.handshake",
    "setup.mode",
    "tunnel.ping-c2s",
    "tunnel.ping-s2c",
    "tunnel.tcp-forward",
    "tunnel.tcp-reverse",
    "tunnel.tcp-duplex",
    "tunnel.tcp-server-initiated",
    "routing.changed-c",
    "routing.changed-s",
    "routing.client-rules",
    "routing.client-paths",
    "routing.server-rules",
    "routing.addresses",
    "routing.mtu",
    "routing.matches-c",
    "routed.ping",
    "routed.tcp-forward",
    "routed.tcp-reverse",
    "routed.tcp-duplex",
    "routed.nat-source",
    "reconnect.blackhole-drops",
    "reconnect.blackhole-recovers",
    "reconnect.server-stop",
    "reconnect.server-rules-removed",
    "reconnect.client-retries",
    "reconnect.client-alive",
    "reconnect.server-restart",
    "reconnect.ping-resumes",
    "reconnect.server-sees-client",
    "reconnect.tcp-forward",
    "reconnect.tcp-reverse",
    "reconnect.ping-s2c",
    "reconnect.routed",
    "mtu.discovery",
    "mtu.applied",
    "mtu.matches-reference",
    "mtu.server-unchanged",
    "mtu.ping",
    "mtu.tcp",
    "mtu.client-exit",
    "mtu.server-exit",
    "mtu.teardown-client",
    "mtu.teardown-server",
    "teardown.client-exit",
    "teardown.server-exit",
    "teardown.client-commands",
    "teardown.server-commands",
    "teardown.state-client",
    "teardown.state-server",
];

#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell {
    client: Impl,
    server: Impl,
    keyed: bool,
}

impl Cell {
    fn label(self) -> String {
        format!("{}/{}/{}", self.client.name(), self.server.name(), if self.keyed { "key" } else { "nokey" })
    }

    fn is_reference(self) -> bool {
        self.client == Impl::C && self.server == Impl::C
    }

    fn expected(self) -> Vec<&'static str> {
        let mut ids = COMMON_CHECKS.to_vec();
        if !self.is_reference() {
            ids.push("mtu.reference");
        }
        ids
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
    Skip,
}

struct Check {
    id: String,
    status: Status,
    detail: String,
}

struct Outcome {
    checks: Vec<Check>,
    snaps: BTreeMap<String, String>,
    output: String,
    elapsed: Duration,
}

fn run_cell(cell: Cell, bins: &Binaries) -> Outcome {
    let started = Instant::now();
    let mut run = container::Run::new("exec bash -c \"$MATRIX_SCRIPT\"");
    run.env = vec![
        ("MATRIX_SCRIPT".to_owned(), SCRIPT.to_owned()),
        ("CLIENT_BIN".to_owned(), bins.path(cell.client).to_owned()),
        ("SERVER_BIN".to_owned(), bins.path(cell.server).to_owned()),
        ("ORACLE_BIN".to_owned(), ORACLE_BINARY.to_owned()),
        ("KEYED".to_owned(), if cell.keyed { "1" } else { "0" }.to_owned()),
    ];
    let (output, error) = match run.capture() {
        Ok(out) => (out, None),
        Err(e) => (String::new(), Some(e)),
    };
    let mut checks = Vec::new();
    let mut snaps = BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    for line in output.lines() {
        if let Some(name) = line.strip_prefix("@@BEGIN ") {
            current = Some((name.to_owned(), String::new()));
        } else if line == "@@END" {
            if let Some((name, text)) = current.take() {
                snaps.insert(name, text);
            }
        } else if let Some((_, text)) = current.as_mut() {
            text.push_str(line);
            text.push('\n');
        } else if let Some(rest) = line.strip_prefix("@@ ") {
            let mut parts = rest.splitn(3, '|');
            if let (Some(id), Some(status), Some(detail)) = (parts.next(), parts.next(), parts.next()) {
                let status = if status == "PASS" { Status::Pass } else { Status::Fail };
                checks.push(Check { id: id.to_owned(), status, detail: detail.to_owned() });
            }
        }
    }
    if let Some(e) = error {
        checks.push(Check { id: "container".to_owned(), status: Status::Fail, detail: e });
    }
    Outcome { checks, snaps, output, elapsed: started.elapsed() }
}

fn compare_to_reference(outcome: &mut Outcome, reference: Option<&Outcome>, is_reference: bool) {
    let (status, detail) = if is_reference {
        (Status::Pass, "this cell is the reference".to_owned())
    } else if let Some(reference) = reference {
        let mut diffs = Vec::new();
        for name in ["during.c", "during.s"] {
            let (mine, theirs) = (outcome.snaps.get(name), reference.snaps.get(name));
            match (mine, theirs) {
                (Some(mine), Some(theirs)) if !mine.is_empty() => {
                    for line in theirs.lines().filter(|l| !mine.lines().any(|m| m == *l)) {
                        diffs.push(format!("{name} missing: {line}"));
                    }
                    for line in mine.lines().filter(|l| !theirs.lines().any(|t| t == *l)) {
                        diffs.push(format!("{name} extra: {line}"));
                    }
                }
                _ => diffs.push(format!("{name} snapshot missing in this cell or the reference")),
            }
        }
        if diffs.is_empty() {
            (Status::Pass, "client and server routing, firewall and tun0 state equal the C/C cell's".to_owned())
        } else {
            (Status::Fail, diffs.join("; "))
        }
    } else {
        (Status::Skip, "reference cell did not run".to_owned())
    };
    outcome.checks.push(Check { id: "routing.matches-c".to_owned(), status, detail });
}

fn normalize(cell: Cell, outcome: &mut Outcome) {
    let expected = cell.expected();
    for id in &expected {
        if !outcome.checks.iter().any(|c| c.id == *id) {
            outcome.checks.push(Check {
                id: (*id).to_owned(),
                status: Status::Skip,
                detail: "not reported by the cell".to_owned(),
            });
        }
    }
    let rank = |id: &str| expected.iter().position(|e| *e == id).unwrap_or(usize::MAX);
    outcome.checks.sort_by_key(|c| rank(&c.id));
}

fn group_cell(outcome: &Outcome, group: &str) -> String {
    let in_group: Vec<&Check> = outcome
        .checks
        .iter()
        .filter(|c| c.id.split('.').next() == Some(group))
        .collect();
    let passed = in_group.iter().filter(|c| c.status == Status::Pass).count();
    if passed == in_group.len() { format!("ok {passed}") } else { format!("FAIL {}/{}", passed, in_group.len()) }
}

pub fn run(args: &[String]) -> Result<()> {
    let mut rust_target: Option<String> = None;
    let mut jobs = 4usize;
    let mut only: Vec<Cell> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--rust-target" => {
                rust_target = Some(it.next().ok_or_else(|| format!("--rust-target needs a triple\n\n{USAGE}"))?.clone());
            }
            "--jobs" => {
                jobs = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("--jobs needs a positive number\n\n{USAGE}"))?;
            }
            "--only" => {
                let spec = it.next().ok_or_else(|| format!("--only needs a cell\n\n{USAGE}"))?;
                let parts: Vec<&str> = spec.split('/').collect();
                let which = |s: &str| Impl::parse("--only", Some(&s.to_owned()), USAGE);
                let (client, server) = match parts.as_slice() {
                    [c, s] | [c, s, _] => (which(c)?, which(s)?),
                    _ => return Err(format!("--only expects client/server[/key|/nokey], got `{spec}`\n\n{USAGE}")),
                };
                let modes: Vec<bool> = match parts.get(2).copied() {
                    None => vec![false, true],
                    Some("key") => vec![true],
                    Some("nokey") => vec![false],
                    Some(other) => return Err(format!("--only mode must be key or nokey, got `{other}`\n\n{USAGE}")),
                };
                for keyed in modes {
                    only.push(Cell { client, server, keyed });
                }
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unexpected argument `{other}`\n\n{USAGE}")),
        }
    }

    let mut reported: Vec<Cell> = Vec::new();
    for client in [Impl::C, Impl::Rust] {
        for server in [Impl::C, Impl::Rust] {
            for keyed in [false, true] {
                let cell = Cell { client, server, keyed };
                if only.is_empty() || only.contains(&cell) {
                    reported.push(cell);
                }
            }
        }
    }
    let mut to_run = reported.clone();
    for keyed in [false, true] {
        let reference = Cell { client: Impl::C, server: Impl::C, keyed };
        if reported.iter().any(|c| c.keyed == keyed) && !to_run.contains(&reference) {
            to_run.push(reference);
        }
    }

    let uses_rust = to_run.iter().any(|c| c.client == Impl::Rust || c.server == Impl::Rust);
    let bins = common::prepare(true, uses_rust, rust_target.as_deref())?;
    let started = Instant::now();

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Outcome>>> = Mutex::new(to_run.iter().map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..jobs.min(to_run.len()) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(cell) = to_run.get(i).copied() else { break };
                    let outcome = run_cell(cell, &bins);
                    let bad = outcome.checks.iter().filter(|c| c.status != Status::Pass).count();
                    eprintln!("cell {} finished in {:.0}s: {} failing checks", cell.label(), outcome.elapsed.as_secs_f64(), bad);
                    results.lock().expect("results lock")[i] = Some(outcome);
                }
            });
        }
    });
    let mut outcomes: Vec<Outcome> = results
        .into_inner()
        .expect("results lock")
        .into_iter()
        .map(|o| o.expect("every cell ran"))
        .collect();

    let reference_index = |keyed: bool| to_run.iter().position(|c| c.is_reference() && c.keyed == keyed);
    let mut finished: Vec<(Cell, Outcome)> = Vec::new();
    let reference_snaps: Vec<Option<BTreeMap<String, String>>> = [false, true]
        .iter()
        .map(|k| reference_index(*k).map(|i| outcomes[i].snaps.clone()))
        .collect();
    for (cell, mut outcome) in to_run.iter().copied().zip(outcomes.drain(..)) {
        let reference = reference_snaps[usize::from(cell.keyed)].as_ref().map(|snaps| Outcome {
            checks: Vec::new(),
            snaps: snaps.clone(),
            output: String::new(),
            elapsed: Duration::ZERO,
        });
        compare_to_reference(&mut outcome, reference.as_ref(), cell.is_reference());
        normalize(cell, &mut outcome);
        finished.push((cell, outcome));
    }
    finished.retain(|(cell, _)| reported.contains(cell));

    let mut failed = 0usize;
    let mut total = 0usize;
    for (cell, outcome) in &finished {
        println!("== cell client={} server={} key={} ({:.0}s)", cell.client.name(), cell.server.name(), if cell.keyed { "yes" } else { "no" }, outcome.elapsed.as_secs_f64());
        let mut cell_failed = false;
        for check in &outcome.checks {
            total += 1;
            let tag = match check.status {
                Status::Pass => "PASS",
                Status::Fail => "FAIL",
                Status::Skip => "SKIP",
            };
            if check.status != Status::Pass {
                failed += 1;
                cell_failed = true;
            }
            println!("  {tag} {:<34} {}", check.id, check.detail);
        }
        if cell_failed {
            println!("  --- cell output for {}\n{}", cell.label(), outcome.output);
        }
    }

    println!("\nmatrix summary (ok N = checks passed; FAIL p/t = passed of total, skips count as failures)");
    print!("{:<16}", "client/server/key");
    for g in GROUPS {
        print!(" {g:<11}");
    }
    println!(" {:>5}", "secs");
    for (cell, outcome) in &finished {
        print!("{:<16}", cell.label());
        for g in GROUPS {
            print!(" {:<11}", group_cell(outcome, g));
        }
        println!(" {:>5.0}", outcome.elapsed.as_secs_f64());
    }
    println!("\n{} cells, {} checks, {} not passing, {:.0}s", finished.len(), total, failed, started.elapsed().as_secs_f64());
    if failed == 0 {
        println!("matrix: PASS");
        Ok(())
    } else {
        Err(format!("matrix: FAIL, {failed} of {total} checks did not pass"))
    }
}
