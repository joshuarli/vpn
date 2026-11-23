use crate::container::{self, CONTAINER_REPO, CONTAINER_TARGET};
use crate::util::{self, Result};
use std::process::Command;

pub const LAB_TARGET: &str = "aarch64-unknown-linux-musl";
pub const TARGETS: [&str; 2] = ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"];

const ARTIFACT_DIR: &str = ".work/release";
const HOST_TARGET_DIR: &str = ".work/target-host";

pub struct Report {
    pub triple: String,
    pub size: u64,
    pub machine: String,
    pub kind: String,
    pub built_in: &'static str,
}

impl Report {
    pub fn line(&self) -> String {
        format!(
            "{}: {} bytes, {}, {} (built {})",
            self.triple, self.size, self.kind, self.machine, self.built_in
        )
    }
}

pub fn lab_binary(triple: &str) -> Result<String> {
    if triple != LAB_TARGET {
        return Err(format!(
            "the lab runs {LAB_TARGET} natively; {triple} cannot execute there (supported: {LAB_TARGET})"
        ));
    }
    let report = build(triple)?;
    eprintln!("{}", report.line());
    Ok(format!("{CONTAINER_TARGET}/{triple}/release/twice"))
}

pub fn build(triple: &str) -> Result<Report> {
    if !TARGETS.contains(&triple) {
        return Err(format!("unsupported release target `{triple}` (supported: {})", TARGETS.join(", ")));
    }
    let built_in = if container_has_target(triple) {
        build_in_container(triple)?;
        "in the lab container"
    } else {
        build_on_host(triple)?;
        "on the host with rust-lld"
    };
    let mut report = inspect(triple)?;
    report.built_in = built_in;
    Ok(report)
}

fn container_has_target(triple: &str) -> bool {
    let script = format!("d=$(rustc --print target-libdir --target {triple}) && test -d \"$d\"");
    container::Run::new(&script).capture().is_ok()
}

fn artifact(triple: &str) -> String {
    format!("{CONTAINER_REPO}/{ARTIFACT_DIR}/{triple}/twice")
}

fn build_in_container(triple: &str) -> Result<()> {
    let script = format!(
        "cd {CONTAINER_REPO} && cargo build -q --release --locked -p twice --target {triple} \
         && mkdir -p {dir} && cp {CONTAINER_TARGET}/{triple}/release/twice {dir}/twice",
        dir = format!("{CONTAINER_REPO}/{ARTIFACT_DIR}/{triple}")
    );
    container::Run::new(&script).status()
}

fn build_on_host(triple: &str) -> Result<()> {
    let root = util::repo_root();
    let target_dir = root.join(HOST_TARGET_DIR);
    let linker_var = format!("CARGO_TARGET_{}_LINKER", triple.to_uppercase().replace('-', "_"));
    util::status(
        Command::new("cargo")
            .current_dir(&root)
            .args(["build", "-q", "--release", "--locked", "-p", "twice", "--target", triple])
            .env("CARGO_TARGET_DIR", &target_dir)
            .env(linker_var, "rust-lld")
            .env("RUSTFLAGS", "-C link-self-contained=yes"),
    )?;
    let out_dir = root.join(ARTIFACT_DIR).join(triple);
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("create {}: {e}", out_dir.display()))?;
    let built = target_dir.join(triple).join("release/twice");
    let dest = out_dir.join("twice");
    std::fs::copy(&built, &dest)
        .map_err(|e| format!("copy {} to {}: {e}", built.display(), dest.display()))?;
    Ok(())
}

fn inspect(triple: &str) -> Result<Report> {
    let path = artifact(triple);
    let script = format!(
        "f={path}; echo size=$(stat -c %s $f); \
         echo machine=$(readelf -h $f | sed -n 's/^ *Machine: *//p'); \
         echo type=$(readelf -h $f | sed -n 's/^ *Type: *\\([A-Z]*\\).*/\\1/p'); \
         echo interp=$(readelf -lW $f | grep -c INTERP || true); \
         echo needed=$(readelf -dW $f | grep -c NEEDED || true)"
    );
    let out = container::Run::new(&script).capture()?;
    let field = |key: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(str::to_owned)
            .ok_or_else(|| format!("inspection of {triple} printed no {key}"))
    };
    let interp: u32 = field("interp")?.parse().map_err(|e| format!("interp count: {e}"))?;
    let needed: u32 = field("needed")?.parse().map_err(|e| format!("needed count: {e}"))?;
    if interp != 0 || needed != 0 {
        return Err(format!("{triple} is not static: {interp} INTERP segments, {needed} NEEDED entries"));
    }
    let elf_type = field("type")?;
    Ok(Report {
        triple: triple.to_owned(),
        size: field("size")?.parse().map_err(|e| format!("size: {e}"))?,
        machine: field("machine")?,
        kind: if elf_type == "DYN" { "static-pie, no INTERP, no NEEDED".to_owned() } else { "static, no INTERP, no NEEDED".to_owned() },
        built_in: "",
    })
}

pub fn run(args: &[String]) -> Result<()> {
    let mut targets: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--target" => targets.push(it.next().ok_or("--target needs a triple")?.clone()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
    }
    if targets.is_empty() {
        targets = TARGETS.iter().map(|t| (*t).to_owned()).collect();
    }
    for triple in &targets {
        let report = build(triple)?;
        println!("{}", report.line());
        println!("  artifact: {ARTIFACT_DIR}/{triple}/twice");
    }
    Ok(())
}
