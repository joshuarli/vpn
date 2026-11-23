use super::case::{self, Case};
use super::run::{self, Impl, Job};
use super::{compare, norm};
use crate::util::{self, Result};
use serde_json::Value;
use std::collections::BTreeSet;

const CLASSES: &[&str] = &["defined", "oracle-defect", "intentional-deviation"];
const REQUIRED_IDS: &[&str] = &[
    "DEV-001", "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007", "SEC-008", "SEC-009",
    "QRK-001", "QRK-002", "QRK-003", "QRK-004",
];

fn text<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

fn strings(entry: &Value, key: &str) -> Vec<String> {
    entry
        .get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

fn source_checks(entry: &Value) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for item in entry.get("source_evidence").and_then(Value::as_array).into_iter().flatten() {
        let file = item.get("file").and_then(Value::as_str).ok_or("source_evidence needs file")?;
        let needle = item.get("contains").and_then(Value::as_str).ok_or("source_evidence needs contains")?;
        out.push((file.to_owned(), needle.to_owned()));
    }
    Ok(out)
}

pub fn run() -> Result<()> {
    let path = util::repo_root().join("compat/ledger.json");
    let doc: Value = serde_json::from_str(&util::read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
    let entries = doc.get("entries").and_then(Value::as_array).ok_or("compat/ledger.json needs an entries array")?;
    let mut problems = Vec::new();
    let mut ids = BTreeSet::new();
    for (n, e) in entries.iter().enumerate() {
        let id = text(e, "id").unwrap_or("<missing id>").to_owned();
        if !ids.insert(id.clone()) {
            problems.push(format!("{id}: duplicate id"));
        }
        for key in ["title", "reproducer", "c_behavior", "rust_behavior", "class", "milestone"] {
            if text(e, key).is_none() {
                problems.push(format!("entry {n} ({id}): missing `{key}`"));
            }
        }
        match text(e, "class") {
            Some(c) if CLASSES.contains(&c) => {}
            Some(c) => problems.push(format!("{id}: class `{c}` is not one of {CLASSES:?}")),
            None => {}
        }
        if strings(e, "evidence").is_empty() && e.get("source_evidence").is_none() {
            problems.push(format!("{id}: needs evidence or source_evidence"));
        }
        if let Some(r) = text(e, "reproducer") {
            if !case::resolve(r).is_file() {
                problems.push(format!("{id}: reproducer case `{r}` does not exist"));
            }
        }
        if id == "DEV-001" && text(e, "class") != Some("intentional-deviation") {
            problems.push("DEV-001 must be an intentional-deviation".to_owned());
        }
    }
    for required in REQUIRED_IDS {
        if !ids.contains(*required) {
            problems.push(format!("missing required entry {required}"));
        }
    }
    if !problems.is_empty() {
        return Err(format!("ledger is incomplete:\n  {}", problems.join("\n  ")));
    }

    let mut cases = Vec::new();
    for e in entries {
        let name = text(e, "reproducer").unwrap_or_default();
        cases.push(Case::load(&case::resolve(name))?);
    }
    let mut jobs = Vec::new();
    for c in &cases {
        norm::validate(&c.header.normalize)?;
        if c.expected.is_empty() {
            return Err(format!("reproducer {} has no recorded golden events", c.header.name));
        }
        jobs.push(Job::new(Impl::C, c, false)?);
        jobs.push(Job::new(Impl::Rust, c, false)?);
    }
    let outs = run::run_batch(&jobs)?;
    let mut failures = Vec::new();
    println!("{:<8} {:<22} {:<46} result", "id", "class", "reproducer");
    for (i, e) in entries.iter().enumerate() {
        let id = text(e, "id").unwrap_or_default();
        let c = &cases[i];
        let exp = norm::apply(&c.header.normalize, &c.expected);
        let mut notes = Vec::new();
        for (which, events) in [(Impl::C, &outs[2 * i]), (Impl::Rust, &outs[2 * i + 1])] {
            let act = norm::apply(&c.header.normalize, events);
            if let Some(m) = compare::compare(&exp, &act) {
                notes.push(format!("{} disagrees with the golden events: {}", which.name(), m.report.lines().next().unwrap_or("")));
                continue;
            }
            for needle in strings(e, "evidence") {
                if !compare::contains_text(&act, &needle) {
                    notes.push(format!("{} output lacks evidence {needle:?}", which.name()));
                }
            }
        }
        for (file, needle) in source_checks(e)? {
            let body = util::read(&util::repo_root().join(&file))?;
            if !body.contains(&needle) {
                notes.push(format!("{file} lacks {needle:?}"));
            }
        }
        let class = text(e, "class").unwrap_or_default();
        let case_name = &c.header.name;
        if notes.is_empty() {
            println!("{id:<8} {class:<22} {case_name:<46} reproduced by C and Rust");
        } else {
            println!("{id:<8} {class:<22} {case_name:<46} FAILED");
            for n in &notes {
                println!("           {n}");
            }
            failures.push(id.to_owned());
        }
    }
    println!("{} ledger entries, {} failed", entries.len(), failures.len());
    if failures.is_empty() { Ok(()) } else { Err(format!("ledger entries failed: {}", failures.join(", "))) }
}
