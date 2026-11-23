# Twice Rust Port Campaign

## Status

- **Goal:** an exact Rust port of `jedisct1/twice` using HiAE from the `laputa-systems/graviola` fork, proven against the C original, then at performance and memory parity.
- **Last accepted pair:** `twice-final`, the tag on the final integration commit; verify it by running `cargo xtask resume` from that same checkout (the verifier itself lives there).
- **Accepted:** G0, H1, H2, T1, S1, T2, T3, B1, D1, X1, I1, B2-prep, L1, C1 verification. **Red:** none. **Parked:** O1, O2, O3 (owner lifted performance gates 2026-11-23 and asked to prioritize feature completion).
- **Running:** none. The final benchmark was stopped after its crypto and packet layers because a busy host made tunnel pairs take ~268 s each; its timing gates are lifted and no verdicts were accepted.
- **Next slice:** none locally. BSD runtime is out of scope by owner decision 2026-11-23; macOS native runtime remains on **Needs environment** (`sudo` on `m1-max` needs a password).
- **Resume:** read this file, run `git status -sb` and `git worktree list`, then run `cargo xtask resume --verify-final`.

| Milestone | State |
| --- | --- |
| C reference and baseline | G0 accepted: pins, oracle build, lab image |
| Graviola HiAE byte parity | VERIFIED arm-neon and arm-sha3 native; aesni bytes under QEMU (`ad177b4`) |
| Rust behavioral parity | VERIFIED on primary host: 1,094 diff runs pass, 82 mutants over 21 areas killed, 19 ledger entries reproduced |
| Real C/Rust interoperability | VERIFIED on primary host: 8 matrix cells, 422 checks, 0 not passing |
| Performance parity | INCONCLUSIVE: performance gates lifted by owner 2026-11-23; timing verdicts are informational, not accepted |
| Memory parity | UNVERIFIED: rust-vs-c screen reports implausible RSS deltas and several vmsize/reorder REGRESSIONs; measurement arms need correction before any claim |
| Native platform gates | Linux AArch64 VERIFIED by `lab matrix`; Linux x86-64 musl VERIFIED by native smoke on `threadripper`; macOS compile-checked only, native runtime on **Needs environment**; BSD out of scope by owner 2026-11-23 |
| Stretch improvements | parked with O1–O3 when performance gates were lifted |

Gate states are `VERIFIED`, `FAILED`, `BLOCKED`, `INCONCLUSIVE`, and `UNVERIFIED`. Primary-host completion and full-platform completion are reported separately.

## Handoff

The accepted pair, acceptance evidence, gate states, compatibility findings,
benchmark limitations and remaining environment work live in
[docs/report.md](docs/report.md). This file is retained because
`cargo xtask resume` reads its Status section.
