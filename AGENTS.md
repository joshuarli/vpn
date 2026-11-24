# AGENTS

This repo holds `twice`, a Rust point-to-point VPN tunnel. Compatibility with
the C original was retired by owner decision; [docs/report.md](docs/report.md)
records the historical parity evidence.

Build and check: `cargo build --locked --release`, `cargo xtask test`,
`cargo xtask platform-check`.

Invariants:

- `rust-toolchain.toml` and the Graviola pin do not change.
- Production dependencies are `graviola` and `libc` only; no C HiAE in production.
- Unsupported CPUs fail at startup instead of falling back to software HiAE.
- No formatters. Performance and memory parity are out of scope by owner decision.
- Inherited weaknesses from the C original are tracked in `TODO.md`, not restored.

Docs: [README.md](README.md) for use, [docs/report.md](docs/report.md) for the
historical parity record, and [docs/roadmap.md](docs/roadmap.md) for current and
future work. Its Status is the resume point.
