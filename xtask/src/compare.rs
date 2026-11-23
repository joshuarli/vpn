use crate::bench::results::{self, Dir, Series};
use crate::bench::stats::{self, Verdict};
use crate::util::{self, Result};
use serde_json::{Value, json};
use std::path::PathBuf;

const MEMORY_PAGE_KB: f64 = 4.0;

pub struct Row {
    pub key: String,
    pub kind: String,
    pub label: String,
    pub verdict: Option<Verdict>,
    pub n_valid: usize,
    pub n_pairs: usize,
    pub base_median: Option<f64>,
    pub cand_median: Option<f64>,
    pub interval: Option<stats::Interval>,
    pub band: Option<f64>,
    pub note: String,
}

fn case_seed(policy_seed: u64, key: &str) -> u64 {
    policy_seed ^ stats::fnv(key)
}

fn rule(policy: &Value, name: &str) -> f64 {
    policy.pointer(&format!("/rules/{name}")).and_then(Value::as_f64).unwrap_or_else(|| panic!("policy rule {name}"))
}

fn min_pairs(meta: &Value) -> usize {
    match meta.pointer("/suite").and_then(Value::as_str) {
        Some("final") => 20,
        _ => 5,
    }
}

fn busy_cap(v: Verdict, lo: f64, hi: f64, floor: f64) -> (Verdict, bool) {
    let keep = match v {
        Verdict::Faster => lo > floor,
        Verdict::Regression => hi < -floor,
        Verdict::WithinMargin | Verdict::Inconclusive => false,
    };
    if keep || v == Verdict::Inconclusive { (v, false) } else { (Verdict::Inconclusive, true) }
}

pub fn judge(series: &Series, policy: Option<&Value>, dir: &Dir) -> Row {
    let effects = series.effects();
    let mut row = Row {
        key: series.key(),
        kind: series.kind.clone(),
        label: series.label.clone(),
        verdict: None,
        n_valid: effects.len(),
        n_pairs: series.pairs.len(),
        base_median: None,
        cand_median: None,
        interval: None,
        band: None,
        note: String::new(),
    };
    if !effects.is_empty() {
        row.base_median = Some(stats::median(&series.base_values()));
        row.cand_median = Some(stats::median(&series.cand_values()));
    }
    let reasons = series.invalid_reasons();
    let Some(policy) = policy else {
        row.note = "no policy".into();
        return row;
    };
    if effects.is_empty() {
        row.verdict = Some(Verdict::Inconclusive);
        row.note = format!("invalid run: {}", reasons.join("; "));
        return row;
    }
    let need = min_pairs(&dir.meta);
    if effects.len() < need {
        row.verdict = Some(Verdict::Inconclusive);
        row.note = format!("{} valid pairs, need {need}; invalid: {}", effects.len(), reasons.join("; "));
        return row;
    }
    let Some(case) = policy.get("cases").and_then(|c| c.get(series.key())) else {
        row.verdict = Some(Verdict::Inconclusive);
        row.note = "no policy entry for this case".into();
        return row;
    };
    let seed = case_seed(policy.pointer("/rules/bootstrap_seed").and_then(Value::as_u64).unwrap_or(0), &series.key());
    let iv = stats::bootstrap_mean(&effects, seed);
    let (lo, hi) = (iv.lo, iv.hi);
    row.interval = Some(iv);
    if series.kind == "timing" {
        let Some(band) = case.get("band").and_then(Value::as_f64) else {
            row.verdict = Some(Verdict::Inconclusive);
            row.note = case.get("inconclusive").and_then(Value::as_str).unwrap_or("A/A band unavailable").to_owned();
            return row;
        };
        row.band = Some(band);
        let mut v = stats::verdict(lo, hi, band);
        if !results::host_gate_ready(&dir.meta) {
            let (capped, changed) = busy_cap(v, lo, hi, rule(policy, "busy_effect_floor").ln_1p());
            v = capped;
            if changed {
                row.note = "perf gate deferred: host busy".into();
            }
        }
        row.verdict = Some(v);
    } else {
        let aa_spread = case.get("aa_spread").and_then(Value::as_f64).unwrap_or(0.0);
        let page = if series.kind == "memory" { MEMORY_PAGE_KB } else { 0.0 };
        let mut tol = aa_spread.max(page);
        if series.kind == "memory" {
            tol = tol.min(rule(policy, "memory_cap_fraction") * row.base_median.unwrap_or(0.0));
        }
        row.band = Some(tol);
        row.verdict = Some(stats::verdict(lo, hi, tol));
    }
    row
}

fn pct(x: f64) -> f64 {
    (x.exp() - 1.0) * 100.0
}

pub fn render(rows: &[Row]) -> String {
    let mut out = String::new();
    let mut counts = [0usize; 4];
    for r in rows {
        let verdict = r.verdict.map_or("NO-POLICY", |v| {
            counts[v as usize] += 1;
            v.name()
        });
        let eff = match (&r.interval, r.kind.as_str()) {
            (Some(iv), "timing") => format!("{:+.2}% [{:+.2}%, {:+.2}%] band {:.2}%", pct(iv.mean), pct(iv.lo), pct(iv.hi), r.band.map_or(f64::NAN, |b| b * 100.0)),
            (Some(iv), _) => format!("{:+.1} [{:+.1}, {:+.1}] {} tol {:.1}", iv.mean, iv.lo, iv.hi, r.label, r.band.unwrap_or(0.0)),
            _ => "-".into(),
        };
        let vals = match (r.base_median, r.cand_median) {
            (Some(b), Some(c)) => format!("{b:.4} -> {c:.4} {}", r.label),
            _ => "-".into(),
        };
        out.push_str(&format!("{verdict:<13} {:<56} n={}/{} {} | {} {}\n", r.key, r.n_valid, r.n_pairs, eff, vals, r.note));
    }
    out.push_str(&format!(
        "\nFASTER {}  WITHIN MARGIN {}  REGRESSION {}  INCONCLUSIVE {}\n",
        counts[Verdict::Faster as usize],
        counts[Verdict::WithinMargin as usize],
        counts[Verdict::Regression as usize],
        counts[Verdict::Inconclusive as usize]
    ));
    out
}

pub fn rows(dir: &Dir, policy: Option<&Value>, include_overlap: bool) -> Vec<Row> {
    results::series(dir, include_overlap).iter().filter(|s| s.gate).map(|s| judge(s, policy, dir)).collect()
}

fn row_json(r: &Row) -> Value {
    json!({
        "case": r.key,
        "kind": r.kind,
        "verdict": r.verdict.map(Verdict::name),
        "valid_pairs": r.n_valid,
        "pairs": r.n_pairs,
        "baseline_median": r.base_median,
        "candidate_median": r.cand_median,
        "effect_mean": r.interval.as_ref().map(|i| i.mean),
        "effect_lo": r.interval.as_ref().map(|i| i.lo),
        "effect_hi": r.interval.as_ref().map(|i| i.hi),
        "band": r.band,
        "note": r.note,
    })
}

fn calibrate(dir: &Dir, manifest: &Value, include_overlap: bool) -> Result<Value> {
    let seed = manifest.pointer("/suites/screen/seed").and_then(Value::as_u64).unwrap_or(0);
    let rules = json!({
        "bootstrap_resamples": stats::RESAMPLES,
        "confidence": 0.95,
        "bootstrap_seed": seed,
        "band_min": 0.01,
        "band_cap": 0.03,
        "band_multiplier": 2.0,
        "memory_page_kb": MEMORY_PAGE_KB,
        "memory_cap_fraction": 0.02,
        "busy_effect_floor": 0.10,
        "min_valid_pairs": {"screen": 5, "final": 20},
        "verdicts": {
            "FASTER": "lower bound > 0",
            "WITHIN MARGIN": "lower bound >= -band",
            "REGRESSION": "upper bound < -band",
            "INCONCLUSIVE": "otherwise, or the A/A band exceeds the cap, or the host is busy and the effect is under 10%"
        },
        "orientation": "higher is better; lower-is-better metrics use the inverted ratio or negated difference",
        "timing_effect": "mean of per-pair ln(candidate/baseline), 10000-resample seeded bootstrap, 95% interval",
        "memory_and_count_effect": "mean of per-pair difference in the metric's unit; tolerance max(one page, A/A spread) capped at 2% of the baseline value for memory, A/A spread for counts",
        "invalid_run": [
            "endpoint crash or nonzero exit",
            "generator saturates",
            "direct ceiling under 1.25x the tunnel result (checked on unimpaired links; netem steps skip the direct run because the impairment, not the tool, limits the path and twice reorders what the direct path cannot)",
            "granted socket buffers or offloads differ between arms",
            "thermal throttling reported",
            "perf-gate-ready -1 reports overlap (applies only when the run started with a ready host)"
        ],
        "busy_host": "check perf-gate-ready once; if busy do not wait, timing verdicts under 10% are INCONCLUSIVE, memory, allocation and count gates still run",
        "gate_policy": "per case only; no aggregate decides a gate"
    });
    let mut cases = serde_json::Map::new();
    for s in results::series(dir, include_overlap).iter().filter(|s| s.gate) {
        let key = s.key();
        let effects = s.effects();
        let mut entry = serde_json::Map::new();
        entry.insert("kind".into(), json!(s.kind));
        entry.insert("higher_is_better".into(), json!(s.higher));
        entry.insert("label".into(), json!(s.label));
        entry.insert("aa_pairs".into(), json!(effects.len()));
        if effects.is_empty() {
            entry.insert("inconclusive".into(), json!(format!("no valid A/A pairs: {}", s.invalid_reasons().join("; "))));
            entry.insert("band".into(), Value::Null);
        } else if s.kind == "timing" {
            let iv = stats::bootstrap_mean(&effects, case_seed(seed, &key));
            let hw = (iv.hi - iv.lo) / 2.0;
            let raw = 2.0 * hw;
            entry.insert("aa".into(), json!({
                "mean_log_ratio": iv.mean, "lo": iv.lo, "hi": iv.hi, "halfwidth": hw,
                "stdev": stats::stdev(&effects), "spread": stats::spread(&effects),
                "median_value": stats::median(&s.base_values()),
            }));
            if effects.len() < 5 {
                entry.insert("band".into(), Value::Null);
                entry.insert("inconclusive".into(), json!("fewer than 5 valid A/A pairs"));
            } else if raw > 0.03 {
                entry.insert("band".into(), Value::Null);
                entry.insert("inconclusive".into(), json!(format!("A/A needs a {:.2}% band, above the 3% cap", raw * 100.0)));
            } else {
                entry.insert("band".into(), json!(raw.max(0.01)));
            }
        } else {
            let mut all = s.base_values();
            all.extend(s.cand_values());
            entry.insert("aa_spread".into(), json!(stats::spread(&all)));
            entry.insert("aa_reference_value".into(), json!(stats::median(&s.base_values())));
        }
        cases.insert(key, Value::Object(entry));
    }
    Ok(json!({
        "version": 1,
        "frozen": true,
        "note": "derived from a C against C A/A run; never widened after a candidate has been measured",
        "calibration": {
            "source": dir.path.file_name().map(|n| n.to_string_lossy().into_owned()),
            "suite": dir.meta.get("suite"),
            "host_ready_at_start": results::host_gate_ready(&dir.meta),
            "includes_overlap_pairs": include_overlap,
            "note": if include_overlap { "pairs flagged by perf-gate-ready -1 overlap were kept because the host was never quiet during the run; spreads are therefore an upper bound on a quiet host and the rerun on a quiet host is a Needs-environment item" } else { "overlap pairs excluded" },
            "arms": dir.meta.get("arms").map(|a| json!({
                "baseline": a.pointer("/baseline/candidate"),
                "candidate": a.pointer("/candidate/candidate")
            })),
            "perf_gate": dir.meta.get("perf_gate"),
        },
        "rules": rules,
        "cases": Value::Object(cases),
    }))
}

pub fn run(args: &[String]) -> Result<()> {
    let mut policy_path = util::repo_root().join("bench/policy.json");
    let mut dir: Option<PathBuf> = None;
    let mut do_calibrate = false;
    let mut force = false;
    let mut include_overlap = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--policy" => policy_path = PathBuf::from(it.next().ok_or("--policy needs a path")?),
            "--calibrate" => do_calibrate = true,
            "--force" => force = true,
            "--include-overlap" => include_overlap = true,
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other => dir = Some(PathBuf::from(other)),
        }
    }
    let dir = match dir {
        Some(d) if d.is_absolute() => d,
        Some(d) => std::env::current_dir().map_err(|e| e.to_string())?.join(d),
        None => results::latest()?,
    };
    let data = results::load(&dir)?;
    if do_calibrate {
        if policy_path.exists() && !force {
            return Err(format!("{} exists and is frozen; pass --force to rederive before any candidate is measured", policy_path.display()));
        }
        let manifest = results::read_json(&util::repo_root().join("bench/manifest.json"))?;
        let policy = calibrate(&data, &manifest, include_overlap)?;
        let text = serde_json::to_string_pretty(&policy).map_err(|e| e.to_string())?;
        std::fs::write(&policy_path, text + "\n").map_err(|e| format!("write {}: {e}", policy_path.display()))?;
        println!("wrote {}", policy_path.display());
        return Ok(());
    }
    let policy = results::read_json(&policy_path)?;
    let rows = rows(&data, Some(&policy), include_overlap);
    let text = render(&rows);
    println!("compare {} against {}\n", dir.display(), policy_path.display());
    print!("{text}");
    let report = json!({"results": dir.file_name().map(|n| n.to_string_lossy().into_owned()), "policy": policy_path.file_name().map(|n| n.to_string_lossy().into_owned()), "cases": rows.iter().map(row_json).collect::<Vec<_>>()});
    std::fs::write(dir.join("verdicts.json"), serde_json::to_string_pretty(&report).map_err(|e| e.to_string())? + "\n")
        .map_err(|e| format!("write verdicts.json: {e}"))?;
    Ok(())
}
