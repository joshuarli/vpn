# Twice Rust port — historical acceptance report

This records the completed parity campaign. The owner has since decided to stop
maintaining compatibility with the C implementation, so the oracle, differential
harness, compatibility ledger, and performance/memory tooling were removed. The
evidence below is a historical claim about the `twice-final` tag, not a live
gate: the commands it names no longer exist. To reproduce it, check out
`twice-final`, whose commit still contains the verifier and its inputs.

## Accepted pair

| Item | Value |
| --- | --- |
| Integration commit | `twice-final` tag, with its recorded `results/final-pair.json` |
| Oracle | `391c461697c871e542c7beb44631e77e4c5646dd` in `oracle/upstream` |
| Oracle `HiAE_amalgamated.c` | SHA-256 `05f745a783317f3e6dc3b0a85a71075eacd1a2a6f82711243e8f6c053c3d6f05` |
| Graviola | `ad177b4a64f96274a4494e4a65d6d861c3369044` on `twice-hiae` |
| Toolchain | `nightly-2026-11-09` with `rust-src`, `llvm-tools`, `clippy` |
| Lab image | `twice-lab:b09cc3ade3a5-nightly-2026-11-09` |

## Recorded results at the tag

- Differential oracle: 1,094 runs, 0 failures.
- Mutation coverage: 82 mutants over 21 areas, 0 survived.
- Compatibility ledger: 19 reproduced entries — one intentional CPU envelope,
  nine inherited security weaknesses, nine defined quirks.
- Real interoperability: 8 matrix cells, 422 checks, 0 not passing.
- Unit suite: 147 passed, 0 failed on macOS arm64; one BSD-only test excluded there.
- HiAE byte parity: verified for available backends; AES-NI bytes proven under QEMU.
- Cross-platform compile: macOS and BSD targets compile-checked; BSD runtime was
  removed from scope by owner decision on 2026-11-23.

## Never proven or out of scope

Performance and memory parity were never accepted and are now out of scope by
owner decision. Native macOS runtime proof needs password-enabled `sudo` on
`m1-max`. VAES/AVX512 was never measured. Bare-metal AArch64 performance was
moot once the performance gates were dropped.

## Disposition of the findings

The ledger and its normalizations are gone from the working tree. The nine
`SEC-*` weaknesses were reproduced deliberately only because parity required it;
they are now live backlog items in [TODO.md](../TODO.md). `DEV-001` — no software
HiAE fallback — remains a chosen product constraint documented in the README.
