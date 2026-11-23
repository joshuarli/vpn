mod smoke;
pub mod topology;

use crate::util::Result;

const USAGE: &str = "usage: cargo xtask lab <command> [args]

commands:
  smoke --client rust|c --server rust|c [--key]
                   run a real tunnel between two network namespaces joined by a veth pair, pass
                   ping and TCP traffic in both directions, check the TUN MTU, stop both ends with
                   SIGTERM, and require clean exit and complete rule teardown";

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("smoke") => smoke::run(&args[1..]),
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown lab command `{other}`\n\n{USAGE}")),
        None => Err(USAGE.to_owned()),
    }
}
