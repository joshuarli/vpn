use crate::util::{self, Result};
use std::path::PathBuf;
use std::process::Command;

const DOCKERFILE: &str = "docker/lab.Dockerfile";
const CARGO_REGISTRY_VOLUME: &str = "twice-lab-cargo-registry";
const CARGO_GIT_VOLUME: &str = "twice-lab-cargo-git";

pub const CONTAINER_REPO: &str = "/src";
pub const CONTAINER_GRAVIOLA: &str = "/graviola";
pub const CONTAINER_TARGET: &str = "/target";

pub fn image_tag() -> Result<String> {
    let root = util::repo_root();
    let digest = util::sha256_file(&root.join(DOCKERFILE))?;
    let channel = util::toolchain_channel()?;
    Ok(format!("twice-lab:{}-{channel}", &digest[..12]))
}

pub fn ensure_image() -> Result<String> {
    let tag = image_tag()?;
    let present = Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", &tag])
        .output()
        .map_err(|e| format!("spawn docker: {e}"))?
        .status
        .success();
    if !present {
        let root = util::repo_root();
        eprintln!("building lab image {tag}");
        util::status(
            Command::new("docker")
                .arg("build")
                .arg("--build-arg")
                .arg(format!("TOOLCHAIN={}", util::toolchain_channel()?))
                .arg("-f")
                .arg(root.join(DOCKERFILE))
                .arg("-t")
                .arg(&tag)
                .arg(root.join("docker")),
        )?;
    }
    Ok(tag)
}

fn target_volume(root: &std::path::Path) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in root.as_os_str().as_encoded_bytes() {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    format!("twice-lab-target-{hash:016x}")
}

pub fn graviola_checkout() -> Option<PathBuf> {
    std::env::var_os("GRAVIOLA_DIR").map(PathBuf::from).or_else(|| {
        let home = std::env::var_os("HOME")?;
        let dir = PathBuf::from(home).join("repos/graviola");
        dir.join("graviola/Cargo.toml").is_file().then_some(dir)
    })
}

pub struct Run<'a> {
    pub script: &'a str,
    pub env: Vec<(String, String)>,
    pub graviola: Option<PathBuf>,
}

impl<'a> Run<'a> {
    pub fn new(script: &'a str) -> Self {
        Run { script, env: Vec::new(), graviola: None }
    }

    fn command(&self) -> Result<Command> {
        let tag = ensure_image()?;
        let root = util::repo_root();
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "-i", "--network", "bridge"])
            .args(["--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN", "--cap-add", "MKNOD"])
            .args(["--device", "/dev/net/tun"])
            .args(["--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined"])
            .arg("-v")
            .arg(format!("{}:{CONTAINER_REPO}", root.display()))
            .arg("-v")
            .arg(format!("{CARGO_REGISTRY_VOLUME}:/opt/cargo/registry"))
            .arg("-v")
            .arg(format!("{CARGO_GIT_VOLUME}:/opt/cargo/git"))
            .arg("-v")
            .arg(format!("{}:{CONTAINER_TARGET}", target_volume(&root)))
            .args(["-e", &format!("CARGO_TARGET_DIR={CONTAINER_TARGET}")]);
        if let Some(dir) = &self.graviola {
            cmd.arg("-v").arg(format!("{}:{CONTAINER_GRAVIOLA}", dir.display()));
        }
        for (k, v) in &self.env {
            cmd.arg("-e").arg(format!("{k}={v}"));
        }
        cmd.arg(&tag).args(["sh", "-euc", self.script]);
        Ok(cmd)
    }

    pub fn status(&self) -> Result<()> {
        util::status(&mut self.command()?)
    }

    pub fn capture(&self) -> Result<String> {
        util::capture(&mut self.command()?)
    }
}
