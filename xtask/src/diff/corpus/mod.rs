mod cli;
mod random;
mod io;
mod net;
mod reorder;
mod spec;
mod timeout;

use super::case::{self, Case};
use crate::util::Result;
use spec::Spec;
use std::collections::BTreeSet;

const SEED_CASES: &[&str] = &[
    "client_mtu_discovery_fail",
    "client_reconnect_backoff",
    "client_resolve_fail",
    "client_sigint_teardown",
    "client_tun_send",
    "genkey",
    "server_bad_inputs",
    "server_keyed_inorder",
    "server_named_dns_sigterm_early",
    "server_nokey_inorder",
    "server_reorder_gap",
    "server_tun_open_fail",
    "usage_error",
];

pub fn specs() -> Vec<Spec> {
    let mut all = Vec::new();
    all.extend(cli::cases());
    all.extend(reorder::cases());
    all.extend(timeout::cases());
    all.extend(io::server_cases());
    all.extend(io::client_cases());
    all.extend(io::tun_cases());
    all.extend(net::mtu_cases());
    all.extend(net::exit_cases());
    all.extend(net::signal_cases());
    all.extend(net::reconnect_cases());
    all.extend(net::socket_cases());
    all.extend(net::config_cases());
    all
}

pub fn write_all() -> Result<Vec<String>> {
    let specs = specs();
    let mut seen = BTreeSet::new();
    let mut names = Vec::new();
    for s in &specs {
        if SEED_CASES.contains(&s.name.as_str()) {
            return Err(format!("corpus case {} collides with a seeded case", s.name));
        }
        if !seen.insert(s.name.clone()) {
            return Err(format!("duplicate corpus case name {}", s.name));
        }
        let path = case::cases_dir().join(format!("{}.jsonl", s.name));
        std::fs::write(&path, s.render()).map_err(|e| format!("write {}: {e}", path.display()))?;
        Case::load(&path)?;
        names.push(s.name.clone());
    }
    Ok(names)
}

pub fn write_generated(seed: u64, count: u64) -> Result<Vec<String>> {
    let dir = case::cases_dir().join("generated");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut names = Vec::new();
    for s in random::traces(seed, count) {
        let path = dir.join(format!("{}.jsonl", s.name));
        std::fs::write(&path, s.render()).map_err(|e| format!("write {}: {e}", path.display()))?;
        Case::load(&path)?;
        names.push(s.name);
    }
    Ok(names)
}
