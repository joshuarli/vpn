# AGENTS

This repo holds `twice`, a Rust tunnel port that must remain byte-compatible
with the pinned C oracle.

Build and check: `cargo build --locked --release`, `cargo xtask test`,
`cargo xtask doctor`. The `xtask` alias is defined in `.cargo/config.toml`.

Invariants:

- `rust-toolchain.toml` and the oracle/Graviola pins do not change.
- Production dependencies are `graviola` and `libc` only; no C HiAE in production.
- Compatibility differences are recorded in `compat/ledger.json`, not fixed.
- No formatters. Performance gates are lifted by owner decision; correctness gates are not.

Docs: [README.md](README.md) for use, [docs/report.md](docs/report.md) for
acceptance evidence and remaining gaps, [plan.md](plan.md) for the campaign
record. `plan.md` is read by `cargo xtask resume`, so its Status section is
load-bearing; do not delete or rename it.
