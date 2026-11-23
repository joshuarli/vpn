use crate::container;
use crate::oracle;
use crate::util::{self, Result};
use std::process::Command;

const CAPABILITY_PROBE: &str = r#"
echo "container arch: $(uname -m), kernel $(uname -r), cpus $(nproc)"
echo "container toolchain: $(rustc -V)"
echo "container gcc: $(gcc -dumpfullversion), glibc $(ldd --version | head -1 | awk '{print $NF}')"
mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
ip netns add doctor-probe
ip -n doctor-probe link set lo up
ip netns exec doctor-probe iptables -t nat -A POSTROUTING -o lo -j ACCEPT
ip netns exec doctor-probe iptables -t nat -D POSTROUTING -o lo -j ACCEPT
ip netns exec doctor-probe ip tuntap add dev doctor0 mode tun
ip netns exec doctor-probe ip link del doctor0
ip netns del doctor-probe
echo "container capabilities: netns, iptables-nft, tun: ok"
"#;

pub fn run(args: &[String]) -> Result<()> {
    util::no_args("doctor", args)?;
    let channel = util::toolchain_channel()?;
    let root = util::repo_root();
    let active = util::capture(Command::new("rustup").args(["show", "active-toolchain"]).current_dir(&root))?;
    if !active.starts_with(&channel) {
        return Err(format!("active toolchain `{}` is not the pinned {channel}", active.trim()));
    }
    let rustc = util::capture(Command::new("rustc").arg("-V").current_dir(&root))?;
    let rustc = rustc.trim();
    println!("toolchain: {channel} (host {rustc})");
    let graviola_toolchain = container::graviola_checkout()
        .map(|dir| util::read(&dir.join("rust-toolchain.toml")))
        .transpose()?;
    match graviola_toolchain {
        Some(text) if text.contains(&format!("\"{channel}\"")) => println!("graviola toolchain: {channel}"),
        Some(text) => return Err(format!("graviola rust-toolchain.toml differs from {channel}:\n{text}")),
        None => println!("graviola toolchain: no local checkout"),
    }
    for line in oracle::verify()? {
        println!("{line}");
    }
    let tag = container::ensure_image()?;
    println!("container image: {tag}");
    print!("{}", container::Run::new(CAPABILITY_PROBE).capture()?);
    println!("doctor: ok");
    Ok(())
}
