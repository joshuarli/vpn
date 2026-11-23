use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub type Result<T> = std::result::Result<T, String>;

pub const ORACLE_REV: &str = "391c461697c871e542c7beb44631e77e4c5646dd";
pub const ORACLE_HIAE_SHA256: &str =
    "05f745a783317f3e6dc3b0a85a71075eacd1a2a6f82711243e8f6c053c3d6f05";
pub const ORACLE_DIR: &str = "oracle/upstream";
pub const GRAVIOLA_SOURCE: &str = "git+https://github.com/laputa-systems/graviola?branch=twice-hiae";
pub const GRAVIOLA_REMOTE: &str = "https://github.com/laputa-systems/graviola";
pub const GRAVIOLA_BRANCH: &str = "twice-hiae";
pub const FRANK_DENIS_NOTICE: &str = "Copyright (c) 2025-2026 Frank Denis";

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repo root")
        .to_path_buf()
}

pub fn work_dir() -> Result<PathBuf> {
    let dir = repo_root().join(".work/tmp");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    Ok(dir)
}

pub fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

pub fn capture(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd:?} exited with {}", out.status));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("{cmd:?} printed non-UTF-8: {e}"))
}

pub fn status(cmd: &mut Command) -> Result<()> {
    let st = cmd.status().map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} exited with {st}"))
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let out = if cfg!(target_os = "macos") {
        capture(Command::new("shasum").args(["-a", "256"]).arg(path))?
    } else {
        capture(Command::new("sha256sum").arg(path))?
    };
    out.split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| format!("no digest for {}", path.display()))
}

pub fn toolchain_channel() -> Result<String> {
    let text = read(&repo_root().join("rust-toolchain.toml"))?;
    text.lines()
        .find_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("channel")?.trim_start().strip_prefix('=')?;
            Some(rest.trim().trim_matches('"').to_owned())
        })
        .ok_or_else(|| "rust-toolchain.toml has no channel".to_owned())
}

pub fn graviola_locked_rev() -> Result<String> {
    let lock = read(&repo_root().join("Cargo.lock"))?;
    let prefix = format!("source = \"{GRAVIOLA_SOURCE}#");
    lock.lines()
        .find_map(|l| l.strip_prefix(&prefix)?.strip_suffix('"').map(str::to_owned))
        .ok_or_else(|| format!("Cargo.lock has no graviola package from {GRAVIOLA_SOURCE}"))
}

pub fn no_args(command: &str, args: &[String]) -> Result<()> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(format!("{command} takes no arguments, got {args:?}"))
    }
}
