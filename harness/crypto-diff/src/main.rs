mod c;
mod case;
mod rng;
mod rs;

use std::ffi::CStr;
use std::process::ExitCode;

use case::{Case, check};
use rng::{Rng, derive};

const USAGE: &str = "usage: crypto-diff [options]

  --backend NAME      arm-neon | arm-sha3 | aesni | vaes (repeatable)
  --all-available     run every backend this host can run; list the rest as skipped
  --qemu              this process is an x86_64 build running under qemu-x86_64 (bytes only;
                      `cargo xtask crypto-diff --qemu` builds and launches it)
  --seed N            seed for all generated data (decimal or 0x hex); default is random
  --random-cases N    number of randomized cases per backend (default 3000)
  --case S:M:A:MO:AO  rerun one case: seed:msg_len:ad_len:msg_offset:ad_offset
  --inject-fault N    make Rust flip a ciphertext bit when msg_len >= N (harness self-test)

Exit status: 0 all bytes equal, 1 a difference or wrong C backend, 2 usage or unavailable backend.";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Backend {
    ArmNeon,
    ArmSha3,
    AesNi,
    Vaes,
}

const ALL: [Backend; 4] = [Backend::ArmNeon, Backend::ArmSha3, Backend::AesNi, Backend::Vaes];

impl Backend {
    fn parse(name: &str) -> Option<Self> {
        ALL.into_iter().find(|b| b.cli() == name)
    }

    fn cli(self) -> &'static str {
        match self {
            Self::ArmNeon => "arm-neon",
            Self::ArmSha3 => "arm-sha3",
            Self::AesNi => "aesni",
            Self::Vaes => "vaes",
        }
    }

    fn c_name(self) -> &'static CStr {
        match self {
            Self::ArmNeon => c"ARM NEON",
            Self::ArmSha3 => c"ARM SHA3",
            Self::AesNi => c"AES-NI",
            Self::Vaes => c"VAES+AVX512",
        }
    }

    fn host_support(self) -> Result<(), String> {
        let ok = match self {
            Self::ArmNeon => host::aarch64(false),
            Self::ArmSha3 => host::aarch64(true),
            Self::AesNi => host::x86_64(false),
            Self::Vaes => host::x86_64(true),
        };
        if ok {
            Ok(())
        } else {
            Err(format!(
                "backend {} cannot run on this host (arch {}, cpu features missing or wrong architecture)",
                self.cli(),
                std::env::consts::ARCH
            ))
        }
    }
}

mod host {
    #[cfg(target_arch = "aarch64")]
    pub fn aarch64(sha3: bool) -> bool {
        std::arch::is_aarch64_feature_detected!("neon")
            && std::arch::is_aarch64_feature_detected!("aes")
            && (!sha3 || std::arch::is_aarch64_feature_detected!("sha3"))
    }

    #[cfg(not(target_arch = "aarch64"))]
    pub fn aarch64(_sha3: bool) -> bool {
        false
    }

    #[cfg(target_arch = "x86_64")]
    pub fn x86_64(vaes: bool) -> bool {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("avx")
            && (!vaes
                || (std::arch::is_x86_feature_detected!("vaes")
                    && std::arch::is_x86_feature_detected!("avx512f")))
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn x86_64(_vaes: bool) -> bool {
        false
    }
}

struct Options {
    backends: Vec<Backend>,
    all_available: bool,
    qemu: bool,
    seed: Option<u64>,
    random_cases: usize,
    single_case: Option<Case>,
}

fn parse_u64(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|e| format!("bad number {text:?}: {e}"))
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        backends: Vec::new(),
        all_available: false,
        qemu: false,
        seed: None,
        random_cases: 3000,
        single_case: None,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--backend" => {
                let name = value("--backend")?;
                o.backends.push(
                    Backend::parse(&name).ok_or_else(|| format!("unknown backend {name:?}"))?,
                );
            }
            "--all-available" => o.all_available = true,
            "--qemu" => o.qemu = true,
            "--seed" => o.seed = Some(parse_u64(&value("--seed")?)?),
            "--random-cases" => o.random_cases = parse_u64(&value("--random-cases")?)? as usize,
            "--inject-fault" => rs::inject_fault_from_len(parse_u64(&value("--inject-fault")?)? as usize),
            "--case" => {
                let text = value("--case")?;
                let f: Vec<&str> = text.split(':').collect();
                if f.len() != 5 {
                    return Err("--case wants seed:msg_len:ad_len:msg_off:ad_off".into());
                }
                o.single_case = Some(Case {
                    seed: parse_u64(f[0])?,
                    msg_len: parse_u64(f[1])? as usize,
                    ad_len: parse_u64(f[2])? as usize,
                    msg_off: parse_u64(f[3])? as usize,
                    ad_off: parse_u64(f[4])? as usize,
                });
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if o.backends.is_empty() && !o.all_available {
        return Err("choose --backend NAME or --all-available".into());
    }
    if o.qemu && !cfg!(target_arch = "x86_64") {
        return Err(format!(
            "--qemu needs an x86_64 build running under qemu-x86_64, not {}; use `cargo xtask crypto-diff --qemu`",
            std::env::consts::ARCH
        ));
    }
    Ok(o)
}

const AD_LENS: [usize; 10] = [0, 1, 15, 16, 17, 31, 255, 256, 257, 512];
const LONG_LENS: [usize; 24] = [
    513, 767, 768, 769, 1023, 1024, 1025, 1399, 1400, 1401, 1472, 2047, 2048, 2049, 4095, 4096,
    4097, 8191, 8192, 9000, 16384, 32767, 65507, 65536,
];

fn case_seed(seed: u64, index: u64) -> u64 {
    derive(seed, 0x100 + index).next_u64()
}

fn deterministic_cases(seed: u64) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut add = |msg_len: usize, ad_len: usize| {
        let n = cases.len() as u64;
        cases.push(Case {
            seed: case_seed(seed, n),
            msg_len,
            ad_len,
            msg_off: (n % 16) as usize,
            ad_off: ((n / 16 + n) % 16) as usize,
        });
    };
    for msg_len in 0..=512 {
        for ad_len in AD_LENS {
            add(msg_len, ad_len);
        }
    }
    for msg_len in LONG_LENS.into_iter().chain([65537, 65535]) {
        for ad_len in [0, 17, 1400] {
            add(msg_len, ad_len);
        }
    }
    for ad_len in [1399, 1400, 4097, 9000, 65507, 65536] {
        for msg_len in [0, 1, 16, 17] {
            add(msg_len, ad_len);
        }
    }
    cases
}

fn random_len(rng: &mut Rng) -> usize {
    match rng.below(10) {
        0..=3 => rng.below(601),
        4..=6 => rng.below(2049),
        7..=8 => rng.below(16385),
        _ => rng.below(70001),
    }
}

fn random_cases(seed: u64, count: usize) -> Vec<Case> {
    let mut rng = derive(seed, 0xabc);
    (0..count)
        .map(|i| Case {
            seed: case_seed(seed, 0x1_0000 + i as u64),
            msg_len: random_len(&mut rng),
            ad_len: if rng.below(3) == 0 { 0 } else { random_len(&mut rng) % 2049 },
            msg_off: rng.below(64),
            ad_off: rng.below(64),
        })
        .collect()
}

fn report_failure(backend: Backend, case: Case, message: &str) -> ExitCode {
    let (min, min_message) = case::minimize(case);
    eprintln!("FAIL {}: {message}", backend.cli());
    eprintln!("  failing case: {}", case.describe());
    eprintln!("  minimized:    {}", min.describe());
    eprintln!("  minimized failure: {min_message}");
    eprintln!("  rerun: crypto-diff --backend {} {}", backend.cli(), min.flag());
    ExitCode::from(1)
}

fn run_backend(backend: Backend, o: &Options, seed: u64) -> Result<Result<(), ExitCode>, String> {
    backend.host_support()?;
    if !rs::AVAILABLE {
        return Err(rs::UNAVAILABLE_REASON.to_owned());
    }
    c::force_implementation(backend.c_name())?;
    let selected = c::implementation_name();
    let want = backend.c_name().to_string_lossy();
    println!(
        "backend {}: C oracle asked for {want:?}, selected {selected:?}",
        backend.cli()
    );
    if selected != want {
        eprintln!("FAIL {}: requested C backend {want:?} but {selected:?} ran", backend.cli());
        return Ok(Err(ExitCode::from(1)));
    }

    let phases: Vec<(&str, Vec<Case>)> = match o.single_case {
        Some(case) => vec![("single", vec![case])],
        None => vec![
            ("deterministic", deterministic_cases(seed)),
            ("random", random_cases(seed, o.random_cases)),
        ],
    };
    let mut comparisons = 0u64;
    let mut cases = 0u64;
    for (name, list) in phases {
        for case in &list {
            match check(case) {
                Ok(n) => comparisons += u64::from(n),
                Err(message) => return Ok(Err(report_failure(backend, *case, &message))),
            }
            cases += 1;
        }
        println!("  {name}: {} cases ok", list.len());
    }

    let after = c::implementation_name();
    if after != want {
        eprintln!("FAIL {}: C backend changed to {after:?} during the run", backend.cli());
        return Ok(Err(ExitCode::from(1)));
    }
    println!(
        "PASS {}: {cases} cases, {comparisons} byte comparisons, C backend {after:?} throughout",
        backend.cli()
    );
    Ok(Ok(()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse_args(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("crypto-diff: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let seed = options.seed.unwrap_or_else(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Rng::new(nanos ^ u64::from(std::process::id()) << 32).next_u64()
    });
    println!("crypto-diff seed {seed:#x} (reproduce with --seed {seed:#x})");
    if options.qemu {
        println!("crypto-diff: x86_64 build under QEMU user emulation: byte parity only, no native timing or CPU proof");
    }

    let mut plan = Vec::new();
    for backend in &options.backends {
        plan.push(*backend);
    }
    let mut skipped = Vec::new();
    if options.all_available {
        for backend in ALL {
            if plan.contains(&backend) {
                continue;
            }
            match backend.host_support() {
                Ok(()) => plan.push(backend),
                Err(why) => skipped.push((backend, why)),
            }
        }
    }
    for (backend, why) in &skipped {
        println!("SKIPPED {}: {why}", backend.cli());
    }

    let mut ran = 0;
    for backend in plan {
        match run_backend(backend, &options, seed) {
            Ok(Ok(())) => ran += 1,
            Ok(Err(code)) => return code,
            Err(why) => {
                eprintln!("crypto-diff: {}: {why}", backend.cli());
                return ExitCode::from(2);
            }
        }
    }
    if ran == 0 {
        eprintln!("crypto-diff: no backend ran");
        return ExitCode::from(2);
    }
    println!("crypto-diff: {ran} backend(s) byte-identical, seed {seed:#x}");
    ExitCode::SUCCESS
}
