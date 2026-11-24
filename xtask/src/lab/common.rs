use crate::container::{self, CONTAINER_REPO};
use crate::release;
use crate::util::Result;

const DEBUG_BINARY: &str = "/target/debug/twice";

pub fn prepare(rust_target: Option<&str>) -> Result<String> {
    match rust_target {
        None => {
            container::Run::new(&format!("cd {CONTAINER_REPO} && cargo build -q --locked -p twice")).status()?;
            Ok(DEBUG_BINARY.to_owned())
        }
        Some(triple) => release::lab_binary(triple),
    }
}
