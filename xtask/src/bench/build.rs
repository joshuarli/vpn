use crate::container::Run;
use crate::util::{self, Result};
use serde_json::{Map, Value, json};
use std::process::Command;

const SCRIPT: &str = r#"
set +e
mkdir -p /target/bench/c /target/bench/log /target/bench-rust
cd /src
F="$(cat /target/oracle/.cflags)"
O=oracle/upstream
echo "c.cflags=$F"
echo "gcc=$(gcc --version | head -1)"
gcc $F -o /target/bench/c/crypto_bench bench/c/crypto_bench.c $O/src/HiAE_amalgamated.c >/target/bench/log/c-crypto.log 2>&1; echo "c.crypto_rc=$?"
gcc $F -I$O/include -I$O/src -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc -o /target/bench/c/packet_bench bench/c/packet_bench.c $O/src/os.c $O/src/HiAE_amalgamated.c >/target/bench/log/c-packet.log 2>&1; echo "c.packet_rc=$?"
gcc -O2 -Wall -W -o /target/bench/c/udpprobe bench/c/udpprobe.c >/target/bench/log/udpprobe.log 2>&1; echo "udpprobe_rc=$?"
echo "c.twice.sha256=$(sha256sum /target/oracle/twice | cut -d' ' -f1)"
echo "c.crypto_bench.sha256=$(sha256sum /target/bench/c/crypto_bench | cut -d' ' -f1)"
echo "c.packet_bench.sha256=$(sha256sum /target/bench/c/packet_bench | cut -d' ' -f1)"
echo "udpprobe.sha256=$(sha256sum /target/bench/c/udpprobe | cut -d' ' -f1)"
echo "c.backend_probe=$(/target/bench/c/crypto_bench --op encrypt --size 64 --ms 5 --warmup-ms 1)"
if [ "$BUILD_RUST" = 1 ]; then
  cargo build --locked --release -p twice >/target/bench/log/rust-twice.log 2>&1; echo "rust.twice_rc=$?"
  echo "rust.twice_err=$(grep -m1 -E '^error' /target/bench/log/rust-twice.log | head -c 300)"
  [ -f /target/release/twice ] && echo "rust.twice.sha256=$(sha256sum /target/release/twice | cut -d' ' -f1)"
  (cd bench/rust-crypto && CARGO_TARGET_DIR=/target/bench-rust cargo update -p graviola --precise "$GRAVIOLA_REV" >/target/bench/log/rust-crypto.log 2>&1 \
     && CARGO_TARGET_DIR=/target/bench-rust cargo build --release >>/target/bench/log/rust-crypto.log 2>&1); echo "rust.crypto_rc=$?"
  echo "rust.crypto_err=$(grep -m1 -E '^error' /target/bench/log/rust-crypto.log | head -c 300)"
  [ -f /target/bench-rust/release/twice-crypto-bench ] && echo "rust.crypto_bench.sha256=$(sha256sum /target/bench-rust/release/twice-crypto-bench | cut -d' ' -f1)"
  [ -f /target/bench-rust/release/twice-crypto-bench ] && echo "rust.backend_probe=$(/target/bench-rust/release/twice-crypto-bench --op encrypt --size 64 --ms 5 --warmup-ms 1)"
  echo "rust.rustc=$(rustc -V)"
fi
"#;

fn build_oracle() -> Result<()> {
    let oracle = util::repo_root().join(util::ORACLE_DIR);
    let head = util::capture(Command::new("git").arg("-C").arg(&oracle).args(["rev-parse", "HEAD"]))?;
    if head.trim() != util::ORACLE_REV {
        return Err(format!("oracle at {}, pinned {}", head.trim(), util::ORACLE_REV));
    }
    let digest = util::sha256_file(&oracle.join("src/HiAE_amalgamated.c"))?;
    if digest != util::ORACLE_HIAE_SHA256 {
        return Err(format!("src/HiAE_amalgamated.c hashes to {digest}, pinned {}", util::ORACLE_HIAE_SHA256));
    }
    let script = format!(
        "rm -rf /b && mkdir -p /b /target/oracle && cp -r /src/{}/. /b/ && cd /b && rm -rf .git \
         && make -s CC=gcc >/dev/null && cp twice .cflags /target/oracle/",
        util::ORACLE_DIR
    );
    Run::new(&script).status()
}

pub fn build(want_rust: bool) -> Result<Value> {
    build_oracle()?;
    let mut run = Run::new(SCRIPT);
    run.env.push(("BUILD_RUST".into(), if want_rust { "1" } else { "0" }.into()));
    run.env.push(("GRAVIOLA_REV".into(), if want_rust { util::graviola_locked_rev()? } else { String::new() }));
    let out = run.capture()?;
    let mut kv = Map::new();
    for line in out.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.to_owned(), Value::String(v.to_owned()));
        }
    }
    let get = |k: &str| kv.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let rc_ok = |k: &str| get(k) == "0";
    if !rc_ok("c.crypto_rc") || !rc_ok("c.packet_rc") || !rc_ok("udpprobe_rc") {
        return Err(format!("C bench tools failed to build: {kv:?}"));
    }
    let backend = |k: &str| -> Value {
        serde_json::from_str::<Value>(&get(k)).ok().and_then(|v| v.get("backend").cloned()).unwrap_or(Value::Null)
    };
    let mut c = json!({
        "twice": "/target/oracle/twice",
        "crypto_bench": "/target/bench/c/crypto_bench",
        "packet_bench": "/target/bench/c/packet_bench",
        "sha256": {
            "twice": get("c.twice.sha256"),
            "crypto_bench": get("c.crypto_bench.sha256"),
            "packet_bench": get("c.packet_bench.sha256"),
        },
        "backend": backend("c.backend_probe"),
        "build": "gcc with oracle .cflags: gcc $(cat .cflags) -Iinclude -o twice src/twice.c src/os.c src/HiAE_amalgamated.c; strip",
    });
    c["crypto_bench_unavailable"] = Value::Null;
    c["packet_bench_unavailable"] = Value::Null;
    let mut rust = json!({
        "twice": "/target/release/twice",
        "crypto_bench": null,
        "packet_bench": null,
        "sha256": {"twice": get("rust.twice.sha256")},
        "backend": backend("rust.backend_probe"),
        "build": "cargo build --locked --release -p twice (profile release: codegen-units 1, lto fat, panic abort, strip)",
        "crypto_bench_unavailable": "rust crypto bench not built",
        "packet_bench_unavailable": "not available for rust yet: the twice library has no packet-path bench harness",
        "twice_build_error": null,
    });
    if want_rust {
        if !rc_ok("rust.twice_rc") {
            rust["twice_build_error"] = json!(get("rust.twice_err"));
        }
        if rc_ok("rust.crypto_rc") {
            rust["crypto_bench"] = json!("/target/bench-rust/release/twice-crypto-bench");
            rust["crypto_bench_unavailable"] = Value::Null;
            rust["sha256"]["crypto_bench"] = json!(get("rust.crypto_bench.sha256"));
        } else {
            rust["crypto_bench_unavailable"] = json!(format!("rust crypto bench build failed: {}", get("rust.crypto_err")));
        }
    } else {
        rust["twice_build_error"] = json!("rust candidate not requested");
    }
    Ok(json!({
        "c": c,
        "rust": rust,
        "udpprobe": "/target/bench/c/udpprobe",
        "udpprobe_sha256": get("udpprobe.sha256"),
        "gcc": get("gcc"),
        "c_cflags": get("c.cflags"),
        "rustc_container": get("rust.rustc"),
    }))
}
