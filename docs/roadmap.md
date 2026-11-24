# Roadmap

This is the single plan for this repository: all current and future work, and the handoff for resuming it. Campaigns are sections below, and their items interleave in **Sequence**. "Resume the roadmap" means continue from **Status**.

## Status

- **Goal:** maintain `twice` as a standalone Rust point-to-point VPN tunnel. Byte parity with the C original, and performance and memory parity against it, were retired by owner decision; [report.md](report.md) is the historical record.
- **Last accepted pair:** `twice-final`, the tag on the final integration commit. The oracle, harness, ledger, and verifier that proved it live in that tag, not in the working tree.
- **Running:** none.
- **Backlog:** inherited weaknesses from the C original are tracked in [TODO.md](../TODO.md). Unsupported CPUs fail at startup rather than falling back to software HiAE, as a product constraint.
- **Next slice:** triage the inherited weaknesses; macOS native runtime proof remains on **Needs environment** (`sudo` on `m1-max` needs a password). BSD runtime is out of scope by owner decision 2026-11-23.
- **Resume:** read this Status, run `git status -sb` and `git worktree list`, then run `cargo xtask resume`.

| Completed work (historical) | State |
| --- | --- |
| C reference and baseline | Accepted: pins, oracle build, lab image |
| Graviola HiAE byte parity | Verified arm-neon and arm-sha3 native; AES-NI bytes under QEMU (`ad177b4`) |
| Rust behavioral parity | Verified on primary host: 1,094 diff runs, 82 mutants over 21 areas, 19 ledger entries |
| Real C/Rust interoperability | Verified on primary host: 8 matrix cells, 422 checks |
| Performance and memory parity | Out of scope by owner decision |
| Native platform gates | Linux AArch64 and x86-64 musl verified; macOS compile-checked only; BSD out of scope |

Gate states are `VERIFIED`, `FAILED`, `BLOCKED`, `INCONCLUSIVE`, and `UNVERIFIED`. Primary-host completion and full-platform completion are reported separately.

## Campaign: Twice Rust port

The parity campaign is closed. [Acceptance evidence](report.md) records what was verified at `twice-final` and what was never proven.

## Handoff

The accepted pair, historical acceptance evidence, and remaining environment work live in [report.md](report.md).
