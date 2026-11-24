mod common;
mod smoke;

use crate::release;
use crate::util::Result;

const USAGE: &str = "usage: cargo xtask lab <command> [args]

commands:
  release [--target <triple>]
                   build the static musl release binaries and report size and linkage
  smoke [--key] [--discover-mtu] [--rust-target <triple>]
                   run a real Rust-to-Rust tunnel between two network namespaces joined by a
                   veth pair, pass ping and TCP traffic in both directions, check the TUN MTU,
                   stop both ends with SIGTERM, and require clean exit and complete rule teardown";

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("release") => release::run(&args[1..]),
        Some("smoke") => smoke::run(&args[1..]),
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown lab command `{other}`\n\n{USAGE}")),
        None => Err(USAGE.to_owned()),
    }
}
