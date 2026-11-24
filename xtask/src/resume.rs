use crate::util::{self, Result};
use std::path::Path;
use std::process::Command;

const USAGE: &str = "usage: cargo xtask resume

Print the roadmap Status section and the integration HEAD.";

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        None => state(),
        Some("-h" | "--help") => Err(USAGE.to_owned()),
        Some(other) => Err(format!("resume: unexpected argument `{other}`\n{USAGE}")),
    }
}

fn git<'a>(cmd: &'a mut Command, dir: &Path) -> &'a mut Command {
    cmd.current_dir(dir)
}

fn state() -> Result<()> {
    let root = util::repo_root();
    let roadmap = util::read(&root.join("docs/roadmap.md"))?;
    let status = roadmap
        .split("## Status")
        .nth(1)
        .and_then(|s| s.split("\n## ").next())
        .unwrap_or("")
        .trim();
    println!("{status}\n");
    let head = util::capture(git(Command::new("git").args(["rev-parse", "HEAD"]), &root))?;
    let branch = util::capture(git(Command::new("git").args(["rev-parse", "--abbrev-ref", "HEAD"]), &root))?;
    println!("HEAD: {} @ {}", branch.trim(), head.trim().chars().take(12).collect::<String>());
    Ok(())
}
