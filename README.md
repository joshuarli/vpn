# twice

A standalone Rust point-to-point VPN tunnel using HiAE from the
`laputa-systems/graviola` fork.

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
`-d` must come before the mode. `-k` is required: every run encrypts and
authenticates with the shared key, and there is no unkeyed mode. `twice genkey [path]` writes a 256-bit key with
mode `0600`.

Run `./target/release/twice` with no arguments to see the full usage text.

## Wire format

Each UDP datagram is a 16-byte header, the HiAE ciphertext, and a 16-byte tag.
The header is two little-endian 64-bit values, `random` and `counter`, and is
the cipher nonce. Both peers use the same key, so data and MTU probes use
disjoint nonces:

- Data: `random` is the sender's session value and `counter` counts up from 1.
  `random` is never `2^64-1`.
- MTU probe: `random` is `2^64-1` and `counter` is the sender's session value
  plus the number of probes it has sent. The payload is `0xAA` bytes. The
  server authenticates a probe before echoing it unchanged, and it never
  echoes a probe datagram over 8,970 bytes, the largest one discovery sends.
  It echoes a probe only when its counter is above every probe it has echoed
  from the same sender process, and it remembers the last 64 such senders.

Replay protection is held in memory and has no handshake. A receiver drops
counters it has already delivered and datagrams from the last 64 sender epochs
it has replaced. After a receiver restart, or once 64 newer epochs have pushed
out the epoch of a captured datagram, that datagram is accepted as the start
of a new epoch and delivered once.

## Verification

`cargo xtask test` runs the unit suite. `cargo xtask lab smoke` runs a real
Rust-to-Rust tunnel through network namespaces. `cargo xtask platform-check`
checks non-Linux targets. `cargo xtask resume` prints the roadmap status.

## License

MIT. Retains Frank Denis's Twice copyright notice.
