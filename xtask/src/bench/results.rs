use crate::util::{self, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Clone)]
pub struct Sample {
    pub layer: String,
    pub unit: String,
    pub metric: String,
    pub value: Option<f64>,
    pub unit_label: String,
    pub higher_is_better: bool,
    pub kind: String,
    pub gate: bool,
    pub arm: String,
    pub pair: u32,
    pub valid: bool,
    pub invalid_reason: Option<String>,
    pub env: Value,
}

#[derive(Deserialize, Clone)]
pub struct Chunk {
    pub layer: String,
    pub pair: u32,
    pub overlap: bool,
    pub throttled: bool,
    pub error: Option<String>,
}

pub struct Dir {
    pub path: PathBuf,
    pub meta: Value,
    pub samples: Vec<Sample>,
    pub chunks: Vec<Chunk>,
}

pub fn results_root() -> PathBuf {
    util::repo_root().join("results/bench")
}

pub fn latest() -> Result<PathBuf> {
    let root = results_root();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .map_err(|e| format!("read {}: {e}", root.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("meta.json").is_file())
        .collect();
    dirs.sort();
    dirs.pop().ok_or_else(|| format!("no results under {}", root.display()))
}

pub fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_str(&util::read(path)?).map_err(|e| format!("parse {}: {e}", path.display()))
}

pub fn load(path: &Path) -> Result<Dir> {
    load_with(path, read_json(&path.join("meta.json"))?)
}

pub fn load_partial(path: &Path) -> Result<Dir> {
    load_with(path, Value::Null)
}

fn load_with(path: &Path, meta: Value) -> Result<Dir> {
    let chunks: Vec<Chunk> = serde_json::from_value(read_json(&path.join("chunks.json"))?)
        .map_err(|e| format!("chunks.json: {e}"))?;
    let mut samples = Vec::new();
    let raw = path.join("raw");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&raw)
        .map_err(|e| format!("read {}: {e}", raw.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    for file in files {
        for (i, line) in util::read(&file)?.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let s: Sample = serde_json::from_str(line)
                .map_err(|e| format!("{}:{}: {e}", file.display(), i + 1))?;
            samples.push(s);
        }
    }
    Ok(Dir { path: path.to_path_buf(), meta, samples, chunks })
}

pub struct Pair {
    pub base: Option<f64>,
    pub cand: Option<f64>,
    pub effect: Option<f64>,
    pub invalid: Option<String>,
}

pub struct Series {
    pub unit: String,
    pub metric: String,
    pub kind: String,
    pub higher: bool,
    pub gate: bool,
    pub label: String,
    pub pairs: Vec<Pair>,
}

impl Series {
    pub fn key(&self) -> String {
        format!("{}#{}", self.unit, self.metric)
    }

    pub fn valid_pairs(&self) -> impl Iterator<Item = &Pair> {
        self.pairs.iter().filter(|p| p.effect.is_some())
    }

    pub fn effects(&self) -> Vec<f64> {
        self.valid_pairs().filter_map(|p| p.effect).collect()
    }

    pub fn base_values(&self) -> Vec<f64> {
        self.valid_pairs().filter_map(|p| p.base).collect()
    }

    pub fn cand_values(&self) -> Vec<f64> {
        self.valid_pairs().filter_map(|p| p.cand).collect()
    }

    pub fn invalid_reasons(&self) -> Vec<String> {
        let mut reasons: Vec<String> = self.pairs.iter().filter_map(|p| p.invalid.clone()).collect();
        reasons.sort();
        reasons.dedup();
        reasons
    }
}

fn env_part(env: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in ["granted", "link"] {
        if let Some(v) = env.get(key) {
            out.insert(key.to_owned(), v.clone());
        }
    }
    Value::Object(out)
}

fn effect(kind: &str, higher: bool, base: f64, cand: f64) -> Option<f64> {
    if kind == "timing" {
        if base <= 0.0 || cand <= 0.0 {
            return None;
        }
        let r = (cand / base).ln();
        Some(if higher { r } else { -r })
    } else {
        let d = cand - base;
        Some(if higher { d } else { -d })
    }
}

pub fn host_gate_ready(meta: &Value) -> bool {
    meta.pointer("/perf_gate/ready_at_start").and_then(Value::as_bool).unwrap_or(false)
}

pub fn series(dir: &Dir, include_overlap: bool) -> Vec<Series> {
    let mut map: BTreeMap<(String, String), BTreeMap<u32, [Option<&Sample>; 2]>> = BTreeMap::new();
    for s in &dir.samples {
        let slot = map.entry((s.unit.clone(), s.metric.clone())).or_default().entry(s.pair).or_default();
        match s.arm.as_str() {
            "baseline" => slot[0] = Some(s),
            _ => slot[1] = Some(s),
        }
    }
    let gate_ready = host_gate_ready(&dir.meta);
    let mut out = Vec::new();
    for ((unit, metric), pairs) in map {
        let first = pairs.values().flat_map(|p| p.iter().flatten()).next().expect("series has a sample");
        let mut series = Series {
            unit: unit.clone(),
            metric: metric.clone(),
            kind: first.kind.clone(),
            higher: first.higher_is_better,
            gate: first.gate,
            label: first.unit_label.clone(),
            pairs: Vec::new(),
        };
        for (pair, slot) in pairs {
            let (Some(b), Some(c)) = (slot[0], slot[1]) else {
                series.pairs.push(Pair { base: None, cand: None, effect: None, invalid: Some("missing arm sample".into()) });
                continue;
            };
            let mut invalid = None;
            for s in [b, c] {
                if !s.valid && invalid.is_none() {
                    invalid = Some(s.invalid_reason.clone().unwrap_or_else(|| "invalid sample".into()));
                } else if s.value.is_none() && invalid.is_none() {
                    invalid = Some("no value".into());
                }
            }
            if invalid.is_none() {
                if let Some(chunk) = dir.chunks.iter().find(|ch| ch.layer == b.layer && ch.pair == pair) {
                    if chunk.throttled && b.kind == "timing" {
                        invalid = Some("thermal throttling reported".into());
                    } else if chunk.overlap && gate_ready && !include_overlap && b.kind == "timing" {
                        invalid = Some("perf-gate-ready -1 reported overlap".into());
                    }
                }
            }
            if invalid.is_none() && env_part(&b.env) != env_part(&c.env) {
                invalid = Some("granted buffers or offloads differ between arms".into());
            }
            let (base, cand) = (b.value, c.value);
            let eff = match (invalid.is_none(), base, cand) {
                (true, Some(x), Some(y)) => effect(&b.kind, b.higher_is_better, x, y),
                _ => None,
            };
            if invalid.is_none() && eff.is_none() {
                invalid = Some("non-positive timing value".into());
            }
            series.pairs.push(Pair { base, cand, effect: eff, invalid });
        }
        out.push(series);
    }
    out
}
