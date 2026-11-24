mod container;
mod lab;
mod platform_check;
mod release;
mod resume;
mod test;
mod util;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <command> [args]

commands:
  test             run the Rust test suites
  lab              real tunnels in network namespaces
  platform-check   check non-Linux targets
  resume           show campaign state";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "test" => test::run(rest),
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
