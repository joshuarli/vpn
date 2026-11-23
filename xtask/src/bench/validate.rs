use super::plan;
use super::results::{self, Dir};
use crate::util::{self, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

pub fn required_metadata(manifest: &Value) -> Vec<String> {
    manifest["required_metadata"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default()
}

pub fn check(dir: &Dir, manifest: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    for pointer in required_metadata(manifest) {
        match dir.meta.pointer(&pointer) {
            None | Some(Value::Null) => problems.push(format!("meta.json is missing {pointer}")),
            Some(Value::String(s)) if s.is_empty() => problems.push(format!("meta.json has empty {pointer}")),
            _ => {}
        }
    }
    let suite = dir.meta["suite"].as_str().unwrap_or_default();
    let Some(plan_layers) = dir.meta.pointer("/plan/layers").and_then(Value::as_object) else {
        problems.push("meta.json has no plan.layers".into());
        return problems;
    };
    for (name, layer) in plan_layers {
        let pairs = layer["pairs"].as_u64().unwrap_or(0) as u32;
        let have: BTreeSet<(String, String, u32, String)> = dir
            .samples
            .iter()
            .filter(|s| &s.layer == name)
            .map(|s| (s.unit.clone(), s.metric.clone(), s.pair, s.arm.clone()))
            .collect();
        for (unit, metrics) in plan::expected_units(name, layer) {
            for metric in metrics {
                for pair in 0..pairs {
                    for arm in ["baseline", "candidate"] {
                        if !have.contains(&(unit.clone(), metric.clone(), pair, arm.to_owned())) {
                            problems.push(format!("{suite}: no {arm} sample for {unit}#{metric} pair {pair}"));
                        }
                    }
                }
            }
        }
        for ch in dir.chunks.iter().filter(|c| &c.layer == name) {
            if let Some(e) = &ch.error {
                problems.push(format!("chunk {name} pair {} failed: {e}", ch.pair));
            }
        }
    }
    for s in &dir.samples {
        if !s.valid && s.invalid_reason.as_deref().unwrap_or("").is_empty() {
            problems.push(format!("invalid sample without a reason: {}#{}", s.unit, s.metric));
        }
        if s.valid && s.value.is_none() {
            problems.push(format!("valid sample without a value: {}#{}", s.unit, s.metric));
        }
    }
    if problems.len() > 40 {
        let more = problems.len() - 40;
        problems.truncate(40);
        problems.push(format!("... and {more} more"));
    }
    problems
}

pub fn run(args: &[String]) -> Result<()> {
    let dir = match args.first() {
        Some(p) => PathBuf::from(p),
        None => results::latest()?,
    };
    let manifest = results::read_json(&util::repo_root().join("bench/manifest.json"))?;
    let data = results::load(&dir)?;
    let problems = check(&data, &manifest);
    if problems.is_empty() {
        println!("validate {}: ok ({} samples, {} required metadata fields)", dir.display(), data.samples.len(), required_metadata(&manifest).len());
        Ok(())
    } else {
        Err(format!("{} is not a valid result:\n  {}", dir.display(), problems.join("\n  ")))
    }
}
