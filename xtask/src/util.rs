use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub type Result<T> = std::result::Result<T, String>;

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repo root")
        .to_path_buf()
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

pub fn no_args(command: &str, args: &[String]) -> Result<()> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(format!("{command} takes no arguments, got {args:?}"))
    }
}
