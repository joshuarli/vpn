use crate::bench;
use crate::util::Result;

pub fn run(args: &[String]) -> Result<()> {
    bench::run_suite(args, Some(&["memory"]), "mem")
}
