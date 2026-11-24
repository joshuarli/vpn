mod container;
mod crypto_diff;
mod diff;
mod doctor;
mod lab;
mod oracle;
mod platform_check;
mod release;
mod resume;
mod test;
mod util;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <command> [args]

commands:
  doctor           report toolchain, pins, oracle hash, and container capabilities
  oracle verify    check the frozen oracle and Graviola pins
  oracle build     build the unmodified C oracle inside the lab container
  test             run the Rust test suites
  crypto-diff      compare Graviola HiAE with the C oracle byte for byte
  diff             replay deterministic traces through C and Rust
  lab              real tunnels in network namespaces
  platform-check   check non-Linux targets
  resume           show campaign state or verify the final pair";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "doctor" => doctor::run(rest),
        "oracle" => oracle::run(rest),
        "test" => test::run(rest),
        "crypto-diff" => crypto_diff::run(rest),
        "diff" => diff::run(rest),
        "lab" => lab::run(rest),
        "platform-check" => platform_check::run(rest),
        "resume" => resume::run(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown command `{other}`\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask {command}: {e}");
            ExitCode::FAILURE
        }
    }
}
