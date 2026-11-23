use crate::container::{self, CONTAINER_REPO};
use crate::oracle::{self, ORACLE_BINARY};
use crate::release;
use crate::util::Result;

const DEBUG_BINARY: &str = "/target/debug/twice";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Impl {
    C,
    Rust,
}

impl Impl {
    pub fn parse(flag: &str, value: Option<&String>, usage: &str) -> Result<Impl> {
        match value.map(String::as_str) {
            Some("c") => Ok(Impl::C),
            Some("rust") => Ok(Impl::Rust),
            other => Err(format!("{flag} expects c or rust, got {other:?}\n\n{usage}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Impl::C => "c",
            Impl::Rust => "rust",
        }
    }
}

pub struct Binaries {
    rust: String,
}

impl Binaries {
    pub fn path(&self, which: Impl) -> &str {
        match which {
            Impl::C => ORACLE_BINARY,
            Impl::Rust => &self.rust,
        }
    }
}

pub fn prepare(uses_c: bool, uses_rust: bool, rust_target: Option<&str>) -> Result<Binaries> {
    if uses_c && container::Run::new(&format!("test -x {ORACLE_BINARY}")).status().is_err() {
        eprintln!("C oracle binary missing; building it");
        oracle::build()?;
    }
    let rust = match (uses_rust, rust_target) {
        (false, _) => DEBUG_BINARY.to_owned(),
        (true, None) => {
            container::Run::new(&format!("cd {CONTAINER_REPO} && cargo build -q --locked -p twice"))
                .status()?;
            DEBUG_BINARY.to_owned()
        }
        (true, Some(triple)) => release::lab_binary(triple)?,
    };
    Ok(Binaries { rust })
}
