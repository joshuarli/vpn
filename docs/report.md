# Twice Rust port — final handoff

## Outcome

The repository contains a working Rust implementation of `jedisct1/twice` using
HiAE from the `laputa-systems/graviola` `twice-hiae` fork. On the primary host
(Linux AArch64 in OrbStack on an Apple M5 Max) the port is byte-faithful to the
frozen C oracle across 1,094 differential runs, interoperates with C in all
eight client/server/keyed combinations, and every inherited deviation is
reproduced and recorded. Correctness and interoperability are complete.

Performance and memory parity remain unproven. The owner lifted performance
gates on 2026-11-23 and asked to prioritize feature completion, so timing
results are informational. The rust-versus-C screen also reports implausible
memory deltas and several `REGRESSION` verdicts; the measurement arms need
correction before any memory-parity claim is made.

## Best pair and reproduction

| Item | Value |
| --- | --- |
| Integration commit | `twice-final` tag, recorded in `results/final-pair.json` |
| Oracle | `391c461697c871e542c7beb44631e77e4c5646dd` in `oracle/upstream` |
| Oracle `HiAE_amalgamated.c` | SHA-256 `05f745a783317f3e6dc3b0a85a71075eacd1a2a6f82711243e8f6c053c3d6f05` |
| Graviola | `ad177b4a64f96274a4494e4a65d6d861c3369044` on `twice-hiae` |
| Toolchain | `nightly-2026-11-09` with `rust-src`, `llvm-tools`, `clippy` |
| Lab image | `twice-lab:b09cc3ade3a5-nightly-2026-11-09` |

Reproduce the accepted correctness pair from the tagged integration checkout:

```
cargo xtask doctor
cargo xtask resume --verify-final
```

Run the verifier from that same checkout: the tag records the pair, and the
fixed verifier code lives in the tagged commit. `oracle verify` checks the
pinned oracle and Graviola rev from `Cargo.lock` without network; add
`oracle verify --check-remote` to also compare Graviola's published branch.

`resume --verify-final` creates a fresh `.work/tmp/verify-final-<stamp>` clean
detached worktree of the recorded commit and reruns `oracle verify`, `test`,
`crypto-diff --all-available`, `diff --self-check`, `diff --ledger`,
`diff --all`, and `lab matrix`. Add `--with-bench` to also run the benchmark
and comparison as informational steps; they are skipped by default because
performance gates are lifted.

## Acceptance evidence

| Deliverable | Command | Result |
| --- | --- | --- |
| Pins, hash, toolchain, container | `cargo xtask doctor` | ok |
| Unit suite | `cargo xtask test` | 147 passed, 0 failed on macOS arm64; one BSD-only test is excluded there, so a Linux run reports fewer (`--os` filters OS tests) |
| HiAE byte parity | `cargo xtask crypto-diff --all-available` | verified for available backends; AES-NI bytes proven under QEMU |
| Differential oracle | `cargo xtask diff --all` | 1,094 passed, 0 failed |
| Mutation coverage | `cargo xtask diff --mutation-check` | 82 mutants over 21 areas, 0 survived |
| Differential harness self-check | `cargo xtask diff --self-check` | passes |
| Compatibility ledger | `cargo xtask diff --ledger` | 19 entries, 0 failed |
| Real interoperability | `cargo xtask lab matrix` | 8 cells, 422 checks, 0 not passing |
| Musl release binaries | `cargo xtask lab matrix --rust-target aarch64-unknown-linux-musl`; `cargo xtask lab release --target x86_64-unknown-linux-musl` | AArch64 static-pie: 8 cells, 422 checks, 0 not passing; x86-64 static-pie: native smoke PASS |
| Cross-platform compile | `cargo xtask platform-check` | macOS compile-checked; BSD targets compile-checked but runtime is out of scope |
| Benchmark suite | `cargo xtask bench --suite screen/final` | raw data under `results/bench/`; the final suite was stopped after its crypto and packet layers because a busy host made tunnel pairs take ~268 s each and performance gates are lifted, so no final summary or verdicts were produced |
| Comparison | `cargo xtask compare --policy bench/policy.json` | informational; no gate accepted |
| Clean-checkout reproducibility | `cargo xtask resume --verify-final` | PASS: 7/7 correctness gates from a fresh clean worktree at `twice-final`, using the verifier recorded in that same tag |

## Findings and deviations

`compat/ledger.json` records 19 entries: `DEV-001` (the intentional CPU
envelope), nine `SEC-*` inherited security weaknesses (zero-key mode, fixed
nonce MTU probes, unauthenticated probe reflection, replay-driven peer changes
and epoch resets, remote reconnect on a bad datagram, non-atomic `genkey`
permissions, `atoi` overflow, and late probe replies), and nine `QRK-*`
defined quirks. Each has a reproducer, both implementations' observed output,
and a class. The weaknesses are reproduced exactly and never fixed, as the
owner required.

Production dependencies are `graviola` and `libc` only. There is no C HiAE in
the production graph and no bring-up FFI hook in the production path; Rust
calls OS effects through `libc` as prescribed by P10.

## Gate states

`VERIFIED`: G0, H1, H2, T1, S1, T2, T3 (compile only), B1, D1, X1, I1,
B2-prep, and primary-host correctness/interoperability.

`INCONCLUSIVE`: performance parity — gates lifted by owner; timing results are
informational only.

`UNVERIFIED`: memory parity — the rust-versus-C screen's RSS magnitudes and
`REGRESSION` verdicts indicate the measurement arms are not comparable; do not
interpret them as a product result.

`PARKED`: O1, O2, O3 — optimization deferred when performance gates were
lifted. Reopen only if the owner reinstates the parity gates.

## Needs environment

- Native macOS `utun`, routes, and teardown: the `lab native-macos` command
  referenced in `plan.md` is not implemented, and `sudo -n` on `josh@m1-max`
  requires a password. This proof remains open.
- x86-64 Linux AES-NI/musl runtime: VERIFIED on `josh@threadripper` (AMD Ryzen 9
  9950X, Alpine x86-64). `cargo xtask lab release --target
  x86_64-unknown-linux-musl` produced a 492,272-byte static-pie binary with no
  `INTERP` or `NEEDED`, and a two-namespace keyed tunnel smoke passed 3/3 pings
  in each direction with both endpoints exiting 0 and printing `Done.`.
  VAES/AVX512 remains open: no host with those features was measured.
- Bare-metal Linux AArch64 performance: no non-virtualized host.
- BSD runtime: removed from scope by owner decision on 2026-11-23.
