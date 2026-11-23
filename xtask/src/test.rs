use crate::util::{self, Result};
use std::process::Command;

const USAGE: &str = "usage: cargo xtask test [--os]

Runs the locked unit suite for the twice library. --os filters to os:: tests.";

pub fn run(args: &[String]) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["test", "--locked", "-p", "twice", "--lib"]);
    match args.first().map(String::as_str) {
        None => {}
        Some("--os") if args.len() == 1 => {
            cmd.args(["os::"]);
        }
        Some("-h" | "--help") => return Err(USAGE.to_owned()),
        Some(other) => return Err(format!("test: unexpected argument `{other}`\n{USAGE}")),
    }
    util::status(cmd.current_dir(util::repo_root()))
}
