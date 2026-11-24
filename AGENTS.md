# AGENTS

This repo holds `twice`, a Rust point-to-point VPN tunnel with a planned SOCKS5
proxy mode.

Build and check: `cargo build --locked --release`, `cargo xtask test`,
`cargo xtask platform-check`.

Invariants:

- `rust-toolchain.toml` and the Graviola pin do not change.
- Production dependencies are `graviola` and `libc` only; no C HiAE in production.
- Unsupported CPUs fail at startup instead of falling back to software HiAE.
- No formatters.
- Known protocol weaknesses are tracked in `TODO.md`, not restored.

Docs: [README.md](README.md) for use and [docs/roadmap.md](docs/roadmap.md) for
current and future work. Its Status is the resume point.
