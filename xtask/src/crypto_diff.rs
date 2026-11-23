use crate::container;
use crate::oracle;
use crate::util::{self, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const HARNESS: &str = "harness/crypto-diff";
const USAGE: &str = "usage: cargo xtask crypto-diff [--graviola DIR] [harness options]

--graviola DIR picks the Graviola checkout to test (default: $GRAVIOLA_DIR, then ~/repos/graviola).
Everything else goes to the harness; run `cargo xtask crypto-diff --help-harness` to list it.
--qemu is not implemented yet.";

struct RestoreLock {
    path: PathBuf,
    original: Vec<u8>,
}

impl Drop for RestoreLock {
    fn drop(&mut self) {
        if let Err(e) = std::fs::write(&self.path, &self.original) {
            eprintln!("warning: could not restore {}: {e}", self.path.display());
        }
    }
}

pub fn run(args: &[String]) -> Result<()> {
    let mut graviola: Option<PathBuf> = None;
    let mut forward: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--graviola" => {
                let dir = it.next().ok_or("--graviola needs a directory")?;
                graviola = Some(PathBuf::from(dir));
            }
            "--qemu" => {
                return Err("--qemu is not implemented yet (slice H2)".to_owned());
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--help-harness" => forward.push("--help".to_owned()),
            _ => forward.push(arg.clone()),
        }
    }

    let dir = graviola
        .or_else(container::graviola_checkout)
        .ok_or("no Graviola checkout: pass --graviola, set GRAVIOLA_DIR, or clone ~/repos/graviola")?;
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("Graviola checkout {}: {e}", dir.display()))?;
    let crate_dir = dir.join("graviola");
    if !crate_dir.join("Cargo.toml").is_file() {
        return Err(format!("{} has no graviola/Cargo.toml", dir.display()));
    }
    let crate_dir = crate_dir
        .to_str()
        .filter(|p| !p.contains(['"', '\\', '\n']))
        .ok_or("Graviola path must be UTF-8 without quotes or backslashes")?
        .to_owned();

    oracle::verify()?;

    let root = util::repo_root();
    let lock = root.join(HARNESS).join("Cargo.lock");
    let _restore = RestoreLock {
        original: std::fs::read(&lock).map_err(|e| format!("read {}: {e}", lock.display()))?,
        path: lock,
    };
    let target = util::work_dir()?.join("crypto-diff-target");

    eprintln!("crypto-diff: Graviola at {crate_dir}");
    util::status(
        Command::new("cargo")
            .current_dir(&root)
            .args(["run", "--release", "--quiet", "--manifest-path"])
            .arg(Path::new(HARNESS).join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .arg("--config")
            .arg(format!(
                "patch.\"{}\".graviola.path=\"{crate_dir}\"",
                util::GRAVIOLA_REMOTE
            ))
            .arg("--")
            .args(&forward),
    )
}
