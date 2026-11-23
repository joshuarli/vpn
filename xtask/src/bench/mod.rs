mod build;
mod meta;
mod plan;
pub mod results;
pub mod stats;
mod validate;

use crate::compare;
use crate::container::{self, Run};
use crate::util::{self, Result};
use serde_json::{Map, Value, json};
use std::path::PathBuf;
use std::time::Instant;

const ALL_LAYERS: [&str; 4] = ["crypto", "packet", "tunnel", "memory"];
const DRIVER: &str = "/src/bench/driver/driver.py";

struct Options {
    suite: String,
    candidate: String,
    baseline: String,
    layers: Vec<String>,
    out: Option<PathBuf>,
    pairs: Option<u32>,
    seed: Option<u64>,
    backend_report: bool,
}

fn parse(args: &[String], forced: Option<&[&str]>) -> Result<Options> {
    let mut o = Options {
        suite: "screen".into(),
        candidate: "c".into(),
        baseline: "c".into(),
        layers: forced.map_or_else(|| ALL_LAYERS.iter().map(|s| (*s).to_owned()).collect(), |f| f.iter().map(|s| (*s).to_owned()).collect()),
        out: None,
        pairs: None,
        seed: None,
        backend_report: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "--suite" => o.suite = value("--suite")?,
            "--candidate" => o.candidate = value("--candidate")?,
            "--baseline" => o.baseline = value("--baseline")?,
            "--layer" if forced.is_none() => {
                o.layers = value("--layer")?.split(',').map(str::to_owned).collect();
            }
            "--out" => o.out = Some(PathBuf::from(value("--out")?)),
            "--pairs" => o.pairs = Some(value("--pairs")?.parse().map_err(|e| format!("--pairs: {e}"))?),
            "--seed" => o.seed = Some(value("--seed")?.parse().map_err(|e| format!("--seed: {e}"))?),
            "--backend-report" => o.backend_report = true,
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    for who in [&o.candidate, &o.baseline] {
        if who != "c" && who != "rust" {
            return Err(format!("candidate and baseline are `c` or `rust`, got `{who}`"));
        }
    }
    for l in &o.layers {
        if !ALL_LAYERS.contains(&l.as_str()) {
            return Err(format!("unknown layer `{l}`, expected one of {ALL_LAYERS:?}"));
        }
    }
    Ok(o)
}

pub fn run(args: &[String]) -> Result<()> {
    if args.first().map(String::as_str) == Some("validate") {
        return validate::run(&args[1..]);
    }
    run_suite(args, None, "")
}

pub fn run_suite(args: &[String], forced: Option<&[&str]>, tag: &str) -> Result<()> {
    let o = parse(args, forced)?;
    let root = util::repo_root();
    let manifest = results::read_json(&root.join("bench/manifest.json"))?;
    let stamp = meta::timestamp();
    let name = if tag.is_empty() { format!("{stamp}-{}", o.suite) } else { format!("{stamp}-{}-{tag}", o.suite) };
    let rel = o.out.clone().unwrap_or_else(|| PathBuf::from("results/bench").join(&name));
    let dir = root.join(&rel);
    std::fs::create_dir_all(dir.join("raw")).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let gate_start = meta::perf_gate(false);
    let thermal_start = meta::thermal();
    let load_start = meta::host_load();
    if gate_start.busy {
        eprintln!("perf gate deferred: host busy (timing verdicts under 10% will be INCONCLUSIVE)");
    }

    let want_rust = o.candidate == "rust" || o.baseline == "rust";
    eprintln!("building bench tools{}", if want_rust { " and the rust candidate" } else { "" });
    let built = build::build(want_rust)?;
    let arms = json!({
        "baseline_ref": built[&o.baseline],
        "candidate_ref": built[&o.candidate],
        "udpprobe": built["udpprobe"],
    });
    let plan = plan::build(&manifest, &o.suite, &o.layers, o.pairs, o.seed, &arms)?;
    std::fs::write(dir.join("plan.json"), serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())? + "\n")
        .map_err(|e| format!("write plan.json: {e}"))?;

    let plan_path = format!("{CONTAINER_REPO}/{}", rel.display());
    let container_meta = {
        let script = format!("python3 -I {DRIVER} --plan {plan_path}/plan.json --layer meta");
        let text = Run::new(&script).capture()?;
        serde_json::from_str::<Value>(text.trim()).map_err(|e| format!("driver meta output: {e}"))?
    };

    let mut chunks: Vec<Value> = Vec::new();
    let mut gate_after: Vec<Value> = Vec::new();
    let started = Instant::now();
    for layer in &o.layers {
        let pairs = plan["layers"][layer.as_str()]["pairs"].as_u64().unwrap_or(0) as u32;
        let timing = layer != "memory";
        for pair in 0..pairs {
            let script = format!(
                "python3 -I {DRIVER} --plan {plan_path}/plan.json --layer {layer} --pair {pair} --out {plan_path}/raw/{layer}-p{pair:02}.jsonl"
            );
            let t0 = Instant::now();
            let result = Run::new(&script).status();
            let (overlap, gate_note) = if timing {
                let g = meta::perf_gate(true);
                (g.busy, g.summary)
            } else {
                (false, Value::Null)
            };
            let throttled = if timing { meta::thermal()["throttled"].as_bool().unwrap_or(false) } else { false };
            eprintln!(
                "[{:>5.0}s] {layer} pair {pair}/{pairs}: {:.1}s{}",
                started.elapsed().as_secs_f64(),
                t0.elapsed().as_secs_f64(),
                if overlap { " (host busy after chunk)" } else { "" }
            );
            gate_after.push(json!({"layer": layer, "pair": pair, "gate": gate_note}));
            chunks.push(json!({
                "layer": layer, "pair": pair, "timing": timing, "overlap": overlap, "throttled": throttled,
                "seconds": t0.elapsed().as_secs_f64(), "error": result.err(),
            }));
            std::fs::write(dir.join("chunks.json"), serde_json::to_string_pretty(&chunks).map_err(|e| e.to_string())? + "\n")
                .map_err(|e| format!("write chunks.json: {e}"))?;
        }
    }

    let gate_end = meta::perf_gate(true);
    let thermal_end = meta::thermal();
    let guest_end = Run::new("cat /proc/loadavg").capture().ok().map(|s| s.trim().to_owned());

    let meta_json = assemble_meta(&o, &manifest, &plan, &built, &container_meta, &dir, &rel, &MetaInputs {
        gate_start: gate_start.summary,
        gate_ready: !gate_start.busy && gate_start.available,
        gate_end: gate_end.summary,
        gate_after,
        thermal_start,
        thermal_end,
        load_start,
        guest_end,
        wall_s: started.elapsed().as_secs_f64(),
    })?;
    std::fs::write(dir.join("meta.json"), serde_json::to_string_pretty(&meta_json).map_err(|e| e.to_string())? + "\n")
        .map_err(|e| format!("write meta.json: {e}"))?;

    let data = results::load(&dir)?;
    let problems = validate::check(&data, &manifest);
    let policy_path = root.join("bench/policy.json");
    let policy = if policy_path.is_file() { Some(results::read_json(&policy_path)?) } else { None };
    let rows = compare::rows(&data, policy.as_ref(), false);
    let text = compare::render(&rows);
    let header = format!(
        "bench {} suite={} baseline={} candidate={} layers={}\nresult {}\n{}\n",
        stamp,
        o.suite,
        o.baseline,
        o.candidate,
        o.layers.join(","),
        rel.display(),
        if gate_start.busy { "perf gate deferred: host busy" } else { "perf gate: ready at start" }
    );
    std::fs::write(dir.join("summary.txt"), format!("{header}\n{text}")).map_err(|e| format!("write summary.txt: {e}"))?;
    print!("{header}\n{text}");
    if o.backend_report {
        for who in ["baseline", "candidate"] {
            println!("backend {who}: {}", meta_json["crypto_backend"][who]);
        }
    }
    if problems.is_empty() {
        println!("\nvalidate: ok ({} samples, all required metadata present)", data.samples.len());
        Ok(())
    } else {
        Err(format!("result is not valid:\n  {}", problems.join("\n  ")))
    }
}

const CONTAINER_REPO: &str = container::CONTAINER_REPO;

struct MetaInputs {
    gate_start: Value,
    gate_ready: bool,
    gate_end: Value,
    gate_after: Vec<Value>,
    thermal_start: Value,
    thermal_end: Value,
    load_start: Value,
    guest_end: Option<String>,
    wall_s: f64,
}

fn distinct(data: &results::Dir, arm: &str, field: &str) -> Value {
    let mut seen: Vec<Value> = Vec::new();
    for s in data.samples.iter().filter(|s| s.arm == arm && s.valid) {
        if let Some(v) = s.env.get(field) {
            if !v.is_null() && !seen.contains(v) {
                seen.push(v.clone());
            }
        }
    }
    Value::Array(seen)
}

#[allow(clippy::too_many_arguments)]
fn assemble_meta(
    o: &Options,
    manifest: &Value,
    plan: &Value,
    built: &Value,
    cm: &Value,
    dir: &std::path::Path,
    rel: &std::path::Path,
    m: &MetaInputs,
) -> Result<Value> {
    let data = results::load_partial(dir)?;
    let commits = meta::commits();
    let arm = |which: &str| -> Value {
        let b = &built[which];
        let commit = if which == "c" { json!(util::ORACLE_REV) } else { commits["repo"].clone() };
        json!({
            "candidate": which,
            "commit": commit,
            "binary_sha256": b["sha256"],
            "build": b["build"],
            "binary_paths": {"twice": b["twice"], "crypto_bench": b["crypto_bench"], "packet_bench": b["packet_bench"]},
            "twice_build_error": b["twice_build_error"],
        })
    };
    let backend = |which: &str, name: &str| -> Value {
        if !built[which]["backend"].is_null() {
            return built[which]["backend"].clone();
        }
        json!(format!("unavailable: {name} crypto bench not built ({})", built[which]["crypto_bench_unavailable"].as_str().unwrap_or("")))
    };
    let mut pins = Map::new();
    if let Some(p) = cm.get("pins") {
        pins.insert("assigned".into(), p.clone());
    }
    let cargo_profile = util::read(&util::repo_root().join("Cargo.toml"))
        .ok()
        .and_then(|t| t.split("[profile.release]").nth(1).map(|s| s.trim().to_owned()));
    let mut mtus = Vec::new();
    let mut tun_mtus = Vec::new();
    for layer in plan["layers"].as_object().into_iter().flatten().map(|(_, v)| v) {
        for s in layer["sessions"].as_array().into_iter().flatten() {
            mtus.push(s["veth_mtu"].clone());
            tun_mtus.push(if s["tun_mtu"].is_null() { json!("default 1420") } else { s["tun_mtu"].clone() });
        }
    }
    mtus.dedup();
    tun_mtus.dedup();
    let socket_layers = o.layers.iter().any(|l| l == "tunnel" || l == "memory");
    let unavailable = |what: &str| json!({"unavailable": format!("{what}: no tunnel or memory layer in this run")});
    let mut reasons: Vec<String> = data.samples.iter().filter(|s| !s.valid).filter_map(|s| s.invalid_reason.clone()).collect();
    reasons.sort();
    reasons.dedup();
    let thermal_throttled = m.thermal_start["throttled"].as_bool().unwrap_or(false) || m.thermal_end["throttled"].as_bool().unwrap_or(false);
    Ok(json!({
        "suite": o.suite,
        "result_dir": rel.display().to_string(),
        "baseline": o.baseline,
        "candidate": o.candidate,
        "layers": o.layers,
        "commits": commits,
        "arms": {"baseline": arm(&o.baseline), "candidate": arm(&o.candidate)},
        "toolchains": {
            "pinned_channel": util::toolchain_channel()?,
            "rustc": cm["rustc"],
            "cargo": cm["cargo"],
            "gcc": cm["gcc"],
            "container_image": container::image_tag()?,
            "host_rustc": meta::text("rustc", &["-V"]),
        },
        "build_flags": {
            "c": {"cflags": built["c_cflags"], "build": built["c"]["build"]},
            "rust": {"cargo_release_profile": cargo_profile, "rustflags": "none (RUSTFLAGS unset); portable target-cpu unless the build sets it", "command": built["rust"]["build"]},
        },
        "target": {"container": cm["rustc_host"], "machine": cm["machine"], "host": "aarch64-apple-darwin (xtask only, never measured)"},
        "libc": cm["libc"],
        "cpu": {
            "host": plan_host_cpu(),
            "container": {"lscpu": cm["lscpu"], "features": cm["cpu_features"], "count": cm["cpu_count"]},
        },
        "crypto_backend": {"baseline": backend(&o.baseline, &o.baseline), "candidate": backend(&o.candidate, &o.candidate)},
        "mtu": {"veth": mtus, "tun": tun_mtus},
        "granted_socket_buffers": if socket_layers {
            json!({"baseline": distinct(&data, "baseline", "granted"), "candidate": distinct(&data, "candidate", "granted"),
                   "sysctl_rmem_max": cm["sysctl_rmem_max"], "sysctl_wmem_max": cm["sysctl_wmem_max"]})
        } else { unavailable("granted socket buffers") },
        "offloads": if socket_layers {
            json!({"tool": cm["ethtool"], "note": "ethtool is not installed in the lab image, so link features from ip -d link are recorded per sample",
                   "baseline": distinct(&data, "baseline", "link"), "candidate": distinct(&data, "candidate", "link")})
        } else { unavailable("offloads") },
        "generators": {
            "iperf3": cm["iperf3"],
            "udpprobe": cm["udpprobe"],
            "tc": cm["tc"],
            "config": {"tunnel": plan["layers"]["tunnel"].clone(), "memory": plan["layers"]["memory"].clone(), "impairments": manifest["impairments"]},
        },
        "core_budget": {
            "affinity": cm["affinity"],
            "pins": cm["pins"],
            "policy": "one dedicated core per twice endpoint, separate cores for generators, probe and echo, micro benchmarks on their own core; taskset inside the container",
        },
        "power_thermal": {"start": m.thermal_start, "end": m.thermal_end, "guest_freq": cm["freq"], "guest_thermal": cm["thermal"], "throttled": thermal_throttled},
        "competing_load": {
            "perf_gate_ready_start": m.gate_start,
            "perf_gate_ready_end": m.gate_end,
            "perf_gate_ready_after_chunks": m.gate_after,
            "loadavg_host_start": m.load_start,
            "loadavg_guest_start": cm["loadavg"],
            "loadavg_guest_end": m.guest_end,
        },
        "perf_gate": {
            "ready_at_start": m.gate_ready,
            "deferred": !m.gate_ready,
            "note": if m.gate_ready { "ready at start" } else { "perf gate deferred: host busy; timing cases under 10% are INCONCLUSIVE; overlap checks recorded but do not invalidate" },
        },
        "seeds": {"suite_seed": plan["seed"], "bootstrap_seed": "policy rules.bootstrap_seed xor fnv(case)", "bootstrap_resamples": stats::RESAMPLES},
        "raw_results": raw_files(dir),
        "invalid_run_reasons": reasons,
        "wall_seconds": m.wall_s,
        "plan": plan,
    }))
}

fn plan_host_cpu() -> Value {
    meta::host_cpu()
}

fn raw_files(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir.join("raw"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| format!("raw/{}", e.file_name().to_string_lossy()))
        .collect();
    v.sort();
    v
}
