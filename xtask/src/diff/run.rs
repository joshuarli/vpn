use super::case::{Case, Header};
use super::script;
use crate::container::{self, CONTAINER_REPO};
use crate::util::{self, Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SHIM_SO: &str = "/target/oracle/twice_shim.so";
const C_BINARY: &str = "/target/oracle/twice";
const RUST_BINARY: &str = "/target/debug/twice";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Impl {
    C,
    Rust,
}

impl Impl {
    pub fn name(self) -> &'static str {
        match self {
            Impl::C => "c",
            Impl::Rust => "rust",
        }
    }

    fn binary(self) -> &'static str {
        match self {
            Impl::C => C_BINARY,
            Impl::Rust => RUST_BINARY,
        }
    }
}

const JOB_TIMEOUT_S: u64 = 120;

pub struct Job {
    pub which: Impl,
    pub header: Header,
    pub script: String,
    pub bin: Option<String>,
    pub timeout_s: u64,
}

impl Job {
    pub fn new(which: Impl, case: &Case, calls: bool) -> Result<Job> {
        Job::from_parts(which, &case.header, &case.inputs, calls)
    }

    pub fn from_parts(which: Impl, header: &Header, inputs: &[super::case::Input], calls: bool) -> Result<Job> {
        Ok(Job {
            which,
            header: header.clone(),
            script: script::compile(header, inputs, calls)?,
            bin: None,
            timeout_s: JOB_TIMEOUT_S,
        })
    }
}

fn batch_dir() -> PathBuf {
    util::repo_root().join(".work/diff/batch")
}

fn ensure_oracle() -> Result<()> {
    static CHECKED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if CHECKED.get().is_some() {
        return Ok(());
    }
    if container::Run::new(&format!("test -x {C_BINARY}")).status().is_err() {
        eprintln!("C oracle binary missing; building it");
        crate::oracle::build()?;
    }
    let _ = CHECKED.set(());
    Ok(())
}

fn write_job(dir: &std::path::Path, job: &Job) -> Result<()> {
    let sandbox = dir.join("sb");
    std::fs::create_dir_all(&sandbox).map_err(|e| format!("create {}: {e}", sandbox.display()))?;
    for (path, hex) in &job.header.files {
        let rel = std::path::Path::new(path);
        if rel.is_absolute() || rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(format!("case file path must stay inside the sandbox: {path}"));
        }
        let dest = sandbox.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&dest, script::decode_hex(hex)?).map_err(|e| format!("write {}: {e}", dest.display()))?;
        set_mode(&dest, 0o600)?;
    }
    std::fs::write(dir.join("script"), &job.script).map_err(|e| e.to_string())?;
    let bin = job.bin.as_deref().unwrap_or(job.which.binary());
    let meta = json!({"bin": bin, "argv": job.header.argv, "timeout_s": job.timeout_s});
    std::fs::write(dir.join("job.json"), meta.to_string()).map_err(|e| e.to_string())
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
}

pub fn run_batch(jobs: &[Job]) -> Result<Vec<Vec<Value>>> {
    if jobs.is_empty() {
        return Ok(Vec::new());
    }
    ensure_oracle()?;
    let dir = batch_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("clean {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    for (i, job) in jobs.iter().enumerate() {
        let jd = dir.join(format!("job{i:05}"));
        write_job(&jd, job)?;
    }
    let want_rust = jobs.iter().any(|j| j.which == Impl::Rust && j.bin.is_none());
    let rust_build = if want_rust {
        format!("cd {CONTAINER_REPO} && (cargo build -q --locked -p twice >{CONTAINER_REPO}/.work/diff/batch/rust_build.log 2>&1 || true); ")
    } else {
        String::new()
    };
    let script = format!(
        "set -eu; H=/target/oracle; S={CONTAINER_REPO}/oracle/shim; \
         [ -f $H/hiae_shim.o ] || gcc -c -O2 -fPIC -fvisibility=hidden -march=native -w \
           -I{CONTAINER_REPO}/oracle/upstream/include -o $H/hiae_shim.o {CONTAINER_REPO}/oracle/upstream/src/HiAE_amalgamated.c; \
         if ! cmp -s $S/twice_shim.c $H/shim.src || [ ! -f {SHIM_SO} ]; then \
           gcc -shared -fPIC -O2 -Wall -Wextra -U_FORTIFY_SOURCE -o {SHIM_SO} $S/twice_shim.c $H/hiae_shim.o -ldl -lpthread \
           && cp $S/twice_shim.c $H/shim.src; fi; \
         {rust_build}python3 -I $S/run_jobs.py {CONTAINER_REPO}/.work/diff/batch"
    );
    container::Run::new(&script).status()?;
    let mut all = Vec::new();
    for (i, job) in jobs.iter().enumerate() {
        let jd = dir.join(format!("job{i:05}"));
        all.push(collect(&jd, job)?);
    }
    Ok(all)
}

fn text_event(name: &str, bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(t) => json!({"ev": name, "text": t}),
        Err(_) => json!({"ev": name, "hex": script::encode_hex(bytes)}),
    }
}

fn collect(jd: &std::path::Path, job: &Job) -> Result<Vec<Value>> {
    let trace = util::read(&jd.join("trace.jsonl"))?;
    let mut events = Vec::new();
    for line in trace.lines().filter(|l| !l.trim().is_empty()) {
        events.push(serde_json::from_str::<Value>(line).map_err(|e| format!("shim trace line {line:?}: {e}"))?);
    }
    let last_t = events.iter().filter_map(|e| e.get("t_ms").and_then(Value::as_u64)).max().unwrap_or(0);
    let result: Value = serde_json::from_str(&util::read(&jd.join("result.json"))?).map_err(|e| e.to_string())?;
    let stdout = std::fs::read(jd.join("stdout")).map_err(|e| e.to_string())?;
    let stderr = std::fs::read(jd.join("stderr")).map_err(|e| e.to_string())?;
    events.push(text_event("stdout", &stdout));
    events.push(text_event("stderr", &stderr));
    let mut files: BTreeMap<String, Value> = BTreeMap::new();
    for f in result["files"].as_array().into_iter().flatten() {
        let path = f["path"].as_str().unwrap_or_default().to_owned();
        files.insert(path.clone(), json!({"ev": "file", "path": path, "mode": f["mode"], "hex": f["hex"]}));
    }
    events.extend(files.into_values());
    let exit = if let Some(err) = result["spawn_error"].as_str() {
        let log = std::fs::read_to_string(jd.parent().unwrap().join("rust_build.log")).unwrap_or_default();
        let log = if job.which == Impl::Rust { log } else { String::new() };
        json!({"ev": "exit", "spawn_error": err, "build_log": log.trim()})
    } else if result["timeout"].as_bool() == Some(true) {
        json!({"ev": "exit", "t_ms": last_t, "timeout": true})
    } else {
        match result["returncode"].as_i64() {
            Some(rc) if rc < 0 => json!({"ev": "exit", "t_ms": last_t, "signal": -rc}),
            Some(rc) => json!({"ev": "exit", "t_ms": last_t, "code": rc}),
            None => json!({"ev": "exit", "t_ms": last_t, "unknown": true}),
        }
    };
    events.push(exit);
    Ok(events)
}

pub fn run_one(which: Impl, case: &Case, calls: bool) -> Result<Vec<Value>> {
    let mut out = run_batch(&[Job::new(which, case, calls)?])?;
    Ok(out.remove(0))
}
