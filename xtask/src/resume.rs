use crate::util::{self, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const USAGE: &str = "usage: cargo xtask resume [--verify-final]

Without arguments, print the campaign Status section and the integration HEAD.
--verify-final rebuilds the recorded best pair in a clean worktree and reruns
the correctness gates, then runs the benchmark and comparison as informational
steps because the owner lifted performance gates.";

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        None => state(),
        Some("--verify-final") if args.len() == 1 => verify_final(),
        Some("-h" | "--help") => Err(USAGE.to_owned()),
        Some(other) => Err(format!("resume: unexpected argument `{other}`\n{USAGE}")),
    }
}

fn git<'a>(cmd: &'a mut Command, dir: &Path) -> &'a mut Command {
    cmd.current_dir(dir)
}

fn state() -> Result<()> {
    let root = util::repo_root();
    let plan = util::read(&root.join("plan.md"))?;
    let status = plan
        .split("## Status")
        .nth(1)
        .and_then(|s| s.split("\n## ").next())
        .unwrap_or("")
        .trim();
    println!("{status}\n");
    let head = util::capture(git(Command::new("git").args(["rev-parse", "HEAD"]), &root))?;
    let branch = util::capture(git(Command::new("git").args(["rev-parse", "--abbrev-ref", "HEAD"]), &root))?;
    println!("integration pair: {} @ {}", branch.trim(), head.trim().chars().take(12).collect::<String>());
    let pair = util::read(&root.join("results/final-pair.json"))?;
    let doc: serde_json::Value = serde_json::from_str(&pair).map_err(|e| format!("results/final-pair.json: {e}"))?;
    println!("recorded pair: {}", doc["commit"].as_str().unwrap_or("<missing>"));
    println!("  oracle:   {}", doc["oracle"].as_str().unwrap_or("<missing>"));
    println!("  graviola: {}", doc["graviola"].as_str().unwrap_or("<missing>"));
    Ok(())
}

fn recorded_commit() -> Result<String> {
    let text = util::read(&util::repo_root().join("results/final-pair.json"))?;
    let doc: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("results/final-pair.json: {e}"))?;
    doc["commit"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "results/final-pair.json has no commit".to_owned())
}

fn clean_checkout(commit: &str) -> Result<PathBuf> {
    let root = util::repo_root();
    let dir = root.join(".work/verify-final");
    if !dir.join(".git").exists() {
        eprintln!("resume: creating clean checkout at {}", dir.display());
        util::status(git(
            Command::new("git").args(["worktree", "add", "--detach", dir.to_str().ok_or("non-UTF-8 worktree path")?, commit]),
            &root,
        ))?;
    }
    let actual = util::capture(git(Command::new("git").args(["rev-parse", "HEAD"]), &dir))?;
    if !actual.starts_with(commit) {
        return Err(format!("verify checkout is at {}, expected {commit}", actual.trim()));
    }
    let dirty = util::capture(git(Command::new("git").args(["status", "--porcelain"]), &dir))?;
    if !dirty.trim().is_empty() {
        return Err(format!("verify checkout is dirty:\n{}", dirty.trim_end()));
    }
    Ok(dir)
}

fn step(dir: &Path, args: &[&str], required: bool) -> Result<bool> {
    eprintln!("resume: cargo xtask {}", args.join(" "));
    let status = Command::new("cargo")
        .arg("xtask")
        .args(args)
        .current_dir(dir)
        .status()
        .map_err(|e| format!("spawn cargo xtask {}: {e}", args.join(" ")))?;
    if status.success() {
        Ok(true)
    } else if required {
        Err(format!("required verification step failed: cargo xtask {}", args.join(" ")))
    } else {
        eprintln!("resume: informational step failed (performance gates lifted): cargo xtask {}", args.join(" "));
        Ok(false)
    }
}

fn verify_final() -> Result<()> {
    let commit = recorded_commit()?;
    let dir = clean_checkout(&commit)?;
    eprintln!("resume: verifying pair {commit} in {}", dir.display());

    let required: &[&[&str]] = &[
        &["oracle", "verify"],
        &["test"],
        &["crypto-diff", "--all-available"],
        &["diff", "--self-check"],
        &["diff", "--ledger"],
        &["diff", "--all"],
        &["lab", "matrix"],
    ];
    let mut passed = 0usize;
    for args in required {
        step(&dir, args, true)?;
        passed += 1;
    }
    let informational: &[&[&str]] = &[
        &["bench", "--suite", "final", "--candidate", "rust", "--baseline", "c"],
        &["compare", "--policy", "bench/policy.json"],
    ];
    let mut informational_passed = 0usize;
    for args in informational {
        if step(&dir, args, false)? {
            informational_passed += 1;
        }
    }
    println!(
        "resume --verify-final: PASS ({passed}/{} correctness gates; {informational_passed}/{} performance steps passed, gates lifted)",
        required.len(),
        informational.len()
    );
    Ok(())
}
