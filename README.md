# twice

A Rust port of the Twice VPN tunnel. It is byte-compatible with the frozen
C original and uses HiAE from the `laputa-systems/graviola` fork.

## Requirements

- Rust `nightly-2026-11-09` (pinned in `rust-toolchain.toml`).
- x86-64 with AES, PCLMULQDQ, AVX2, ADX, BMI and POPCNT, or AArch64 with AES,
  NEON, PMULL and SHA2. There is no software HiAE fallback; other CPUs exit
  with a clear error at startup.
- Root or `CAP_NET_ADMIN` to create a TUN interface and change routes.

## Run

```
cargo build --locked --release
./target/release/twice genkey                 # writes vpn.key
sudo ./target/release/twice -k vpn.key server auto
sudo ./target/release/twice -k vpn.key -d client <server-address>
```

The positional arguments after `server` or `client` are, in order: server
address, port (`auto`), TUN name (`auto`), local TUN IP (`auto`), remote TUN IP
(`auto`), and for the client the gateway IP (`auto`). Options `-k`, `-m` and
`-d` must come before the mode. `twice genkey [path]` writes a 256-bit key with
mode `0600`.

Run `./target/release/twice` with no arguments to see the full usage text.

## Verification

`cargo xtask doctor` checks the toolchain, pins, oracle hash and container
capabilities. `cargo xtask test` runs the unit suite. `cargo xtask
resume --verify-final` checks the recorded pair from a clean checkout. See
[docs/report.md](docs/report.md) for what is verified and what is not.

## License

MIT. Retains Frank Denis's Twice copyright notice.
