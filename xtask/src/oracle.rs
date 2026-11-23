use crate::container::{self, CONTAINER_TARGET};
use crate::util::{self, Result};
use std::process::Command;

pub const ORACLE_BINARY: &str = "/target/oracle/twice";

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("verify") => {
            let mut report = match &args[1..] {
                [] => verify()?,
                [flag] if flag == "--check-remote" => verify_with_remote()?,
                _ => return Err("usage: cargo xtask oracle verify [--check-remote]".to_owned()),
            };
            report.push("oracle verify: ok".to_owned());
            for line in report {
                println!("{line}");
            }
            Ok(())
        }
        Some("build") => {
            util::no_args("oracle build", &args[1..])?;
            build()?;
            println!("{ORACLE_BINARY}");
            Ok(())
        }
        _ => Err("expected `verify` or `build`".to_owned()),
    }
}

pub fn verify() -> Result<Vec<String>> {
    let root = util::repo_root();
    let oracle = root.join(util::ORACLE_DIR);
    let mut report = Vec::new();

    let head = util::capture(Command::new("git").arg("-C").arg(&oracle).args(["rev-parse", "HEAD"]))?;
    let head = head.trim();
    if head != util::ORACLE_REV {
        return Err(format!("oracle at {head}, pinned {}", util::ORACLE_REV));
    }
    report.push(format!("oracle rev: {head}"));

    let dirty = util::capture(
        Command::new("git")
            .arg("-C")
            .arg(&oracle)
            .args(["status", "--porcelain", "--untracked-files=all", "--ignored"]),
    )?;
    if !dirty.trim().is_empty() {
        return Err(format!("oracle tree differs from its pinned commit:\n{dirty}"));
    }

    let digest = util::sha256_file(&oracle.join("src/HiAE_amalgamated.c"))?;
    if digest != util::ORACLE_HIAE_SHA256 {
        return Err(format!("src/HiAE_amalgamated.c hashes to {digest}, pinned {}", util::ORACLE_HIAE_SHA256));
    }
    report.push(format!("oracle HiAE_amalgamated.c sha256: {digest}"));

    for license in [root.join("LICENSE"), oracle.join("LICENSE")] {
        if !util::read(&license)?.contains(util::FRANK_DENIS_NOTICE) {
            return Err(format!("{} lacks `{}`", license.display(), util::FRANK_DENIS_NOTICE));
        }
    }
    report.push(format!("license notice: {}", util::FRANK_DENIS_NOTICE));

    let locked = util::graviola_locked_rev()?;
    if let Some(dir) = container::graviola_checkout() {
        let local = util::capture(Command::new("git").arg("-C").arg(&dir).args(["rev-parse", "HEAD"]))?;
        if local.trim() != locked {
            return Err(format!("local graviola checkout is at {}, Cargo.lock pins {locked}", local.trim()));
        }
    }
    report.push(format!("graviola rev: {locked} (pinned by Cargo.lock)"));
    Ok(report)
}

fn verify_with_remote() -> Result<Vec<String>> {
    let mut report = verify()?;
    let locked = util::graviola_locked_rev()?;
    let remote = util::capture(
        Command::new("git").args(["ls-remote", util::GRAVIOLA_REMOTE, &format!("refs/heads/{}", util::GRAVIOLA_BRANCH)]),
    )?;
    let published = remote.split_whitespace().next().unwrap_or("");
    if published != locked {
        return Err(format!(
            "Cargo.lock pins graviola {locked}, but {} is at {published:?}",
            util::GRAVIOLA_BRANCH
        ));
    }
    report.push(format!("graviola published {} at {published}", util::GRAVIOLA_BRANCH));
    Ok(report)
}

pub fn build() -> Result<()> {
    verify()?;
    let script = format!(
        "rm -rf /b && mkdir -p /b {CONTAINER_TARGET}/oracle && cp -r /src/{}/. /b/ && cd /b && rm -rf .git \
         && make -s CC=gcc >/dev/null && cp twice .cflags {CONTAINER_TARGET}/oracle/",
        util::ORACLE_DIR
    );
    container::Run::new(&script).status()
}
