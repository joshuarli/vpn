mod common;
mod matrix;
mod smoke;
pub mod topology;

use crate::release;
use crate::util::Result;

const USAGE: &str = "usage: cargo xtask lab <command> [args]

commands:
  matrix [--rust-target <triple>] [--jobs <n>] [--only <client>/<server>[/key|/nokey]]
                   run the full c/rust client/server matrix, keyed and not, with traffic, routing,
                   a routed LAN behind the server, MTU discovery, reconnect and teardown checks
  release [--target <triple>]
                   build the static musl release binaries and report size and linkage
  smoke --client rust|c --server rust|c [--key]
                   run a real tunnel between two network namespaces joined by a veth pair, pass
                   ping and TCP traffic in both directions, check the TUN MTU, stop both ends with
                   SIGTERM, and require clean exit and complete rule teardown";

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("matrix") => matrix::run(&args[1..]),
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
