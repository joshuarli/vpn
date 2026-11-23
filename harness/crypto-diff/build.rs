use std::env;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("cannot spawn {cmd:?}: {e}"));
    assert!(status.success(), "{cmd:?} exited with {status}");
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join("../../oracle/upstream/src/HiAE_amalgamated.c");
    let source = source
        .canonicalize()
        .unwrap_or_else(|e| panic!("pinned oracle source {}: {e}", source.display()));
    println!("cargo:rerun-if-changed={}", source.display());
    let target = env::var("TARGET").unwrap_or_default().replace('-', "_");
    let cc_var = format!("CC_{target}");
    let ar_var = format!("AR_{target}");
    for var in [cc_var.as_str(), ar_var.as_str(), "CC", "AR"] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let object = out.join("hiae_c.o");
    let archive = out.join("libhiae_c.a");
    let cc = env::var(&cc_var)
        .or_else(|_| env::var("CC"))
        .unwrap_or_else(|_| "cc".to_owned());
    let ar = env::var(&ar_var)
        .or_else(|_| env::var("AR"))
        .unwrap_or_else(|_| "ar".to_owned());

    run(Command::new(cc)
        .args(["-O2", "-fPIC", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object));
    let _ = std::fs::remove_file(&archive);
    run(Command::new(ar).arg("crs").arg(&archive).arg(&object));

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=hiae_c");
}
