use crate::util;
use serde_json::{Value, json};
use std::process::Command;

pub fn text(prog: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(prog).args(args).current_dir(util::repo_root()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

pub fn timestamp() -> String {
    text("date", &["-u", "+%Y%m%dT%H%M%SZ"]).unwrap_or_else(|| "unknown-time".into())
}

pub struct Gate {
    pub busy: bool,
    pub available: bool,
    pub summary: Value,
}

pub fn perf_gate(once: bool) -> Gate {
    let mut cmd = Command::new("perf-gate-ready");
    if once {
        cmd.arg("-1");
    }
    match cmd.output() {
        Err(e) => Gate { busy: false, available: false, summary: json!({"available": false, "error": e.to_string()}) },
        Ok(out) => {
            let code = out.status.code();
            let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            let lines: Vec<String> = all.lines().filter(|l| !l.trim_start().starts_with("- pid=") && !l.trim_start().starts_with("* pid=")).map(|l| l.chars().take(240).collect()).collect();
            Gate {
                busy: code == Some(75),
                available: true,
                summary: json!({"available": true, "exit_code": code, "status": match code { Some(0) => "ready", Some(75) => "busy", _ => "unreadable" }, "lines": lines}),
            }
        }
    }
}

pub fn thermal() -> Value {
    let raw = text("pmset", &["-g", "therm"]);
    let limit = raw.as_deref().and_then(|t| {
        t.lines().find_map(|l| l.trim().strip_prefix("CPU_Speed_Limit").and_then(|r| r.split('=').nth(1)).and_then(|v| v.trim().parse::<u32>().ok()))
    });
    json!({
        "host_pmset_therm": raw,
        "cpu_speed_limit_percent": limit,
        "throttled": limit.is_some_and(|l| l < 100),
        "guest": "unavailable: no /sys/class/thermal in the Linux guest",
    })
}

pub fn host_load() -> Value {
    json!({
        "loadavg": text("sysctl", &["-n", "vm.loadavg"]),
        "uptime": text("uptime", &[]),
    })
}

pub fn commits() -> Value {
    let root = util::repo_root();
    let head = text("git", &["rev-parse", "HEAD"]);
    let dirty = text("git", &["status", "--porcelain"]).map(|s| !s.is_empty());
    json!({
        "repo": head,
        "repo_dirty": dirty,
        "oracle": util::ORACLE_REV,
        "oracle_hiae_sha256": util::ORACLE_HIAE_SHA256,
        "graviola": util::graviola_locked_rev().ok(),
        "graviola_source": util::GRAVIOLA_SOURCE,
        "root": root.display().to_string(),
    })
}

pub fn host_cpu() -> Value {
    json!({
        "brand": text("sysctl", &["-n", "machdep.cpu.brand_string"]),
        "cores": text("sysctl", &["-n", "hw.ncpu"]),
        "memory_bytes": text("sysctl", &["-n", "hw.memsize"]),
        "os": text("sw_vers", &["-productVersion"]),
        "virtualization": "Linux AArch64 guest under OrbStack",
    })
}
