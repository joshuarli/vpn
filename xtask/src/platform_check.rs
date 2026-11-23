use crate::util::{self, Result};
use std::path::Path;
use std::process::Command;

const TARGETS: [&str; 5] = [
    "aarch64-apple-darwin",
    "x86_64-unknown-freebsd",
    "x86_64-unknown-netbsd",
    "x86_64-unknown-openbsd",
    "x86_64-unknown-dragonfly",
];

const TARGET_DIR: &str = ".work/target-platform-check";
const MAX_ERROR_LINES: usize = 60;

enum Outcome {
    Checked,
    Blocked(String),
    Failed(String),
}

fn sysroot() -> Result<String> {
    let out = util::capture(Command::new("rustc").arg("--print").arg("sysroot").current_dir(util::repo_root()))?;
    Ok(out.trim().to_owned())
}

fn has_prebuilt_std(sysroot: &str, target: &str) -> bool {
    Path::new(sysroot).join("lib/rustlib").join(target).join("lib").is_dir()
}

fn error_excerpt(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .skip_while(|l| !l.starts_with("error"))
        .collect();
    let mut text = lines.iter().take(MAX_ERROR_LINES).copied().collect::<Vec<_>>().join("\n");
    if lines.len() > MAX_ERROR_LINES {
        text.push_str("\n...");
    }
    if text.is_empty() { stderr.trim().to_owned() } else { text }
}

fn check(sysroot: &str, target: &str) -> Result<Outcome> {
    let root = util::repo_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root)
        .args(["check", "--locked", "-p", "twice", "--target", target])
        .arg("--target-dir")
        .arg(root.join(TARGET_DIR));
    if !has_prebuilt_std(sysroot, target) {
        cmd.arg("-Zbuild-std=std,panic_abort");
    }
    let out = cmd.output().map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    if out.status.success() {
        return Ok(Outcome::Checked);
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let excerpt = error_excerpt(&stderr);
    if stderr.contains("could not compile `twice`") {
        Ok(Outcome::Failed(excerpt))
    } else {
        Ok(Outcome::Blocked(excerpt))
    }
}

pub fn run(args: &[String]) -> Result<()> {
    util::no_args("platform-check", args)?;
    let sysroot = sysroot()?;
    let mut failed = Vec::new();
    for target in TARGETS {
        let std_source = if has_prebuilt_std(&sysroot, target) { "prebuilt std" } else { "build-std" };
        eprintln!("checking {target} ({std_source})");
        match check(&sysroot, target)? {
            Outcome::Checked => println!("{target}: CHECKED (compile only)"),
            Outcome::Blocked(why) => println!("{target}: BLOCKED: {why}"),
            Outcome::Failed(why) => {
                println!("{target}: FAILED in twice: {why}");
                failed.push(target);
            }
        }
    }
    println!("platform-check compiles only; no target was run, so none is runtime validated");
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("twice does not compile for {}", failed.join(", ")))
    }
}
