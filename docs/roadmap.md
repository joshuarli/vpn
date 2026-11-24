# Roadmap

This is the single plan for this repository: all current and future work, and the handoff for resuming it. Campaigns are sections below, and their items interleave in **Sequence**. "Resume the roadmap" means continue from **Status**.

## Status

- **Goal:** maintain `twice` as a standalone Rust point-to-point VPN tunnel and add SOCKS5 proxying as a second networking mode. Byte parity with the C original, and performance and memory parity against it, were retired by owner decision; [report.md](report.md) is the historical record.
- **Last accepted pair:** `twice-final`, the tag on the final integration commit. The oracle, harness, ledger, and verifier that proved it live in that tag, not in the working tree.
- **Running:** none.
- **Backlog:** the eight inherited weaknesses from the C original were fixed on 2026-11-24. Of the three follow-up replay and reflection tickets, the reconnect replay and probe reflection were fixed on 2026-11-24. VPN-12 (replay across a receiver restart) awaits an owner decision between a handshake and a persisted epoch record, tracked in [TODO.md](../TODO.md). The proxy campaign below is greenlit but not started.
- **Next slice:** decide the encrypted proxy transport and whether Rustls may become a production dependency, then implement rootless SOCKS5 CONNECT with remote DNS.
- **Needs environment:** native macOS runtime proof needs password-enabled `sudo` on `m1-max`. VAES/AVX512 has no host. BSD runtime is out of scope by owner decision 2026-11-23.
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

## Sequence

1. Decide the proxy transport and the dependency change it requires.
2. Implement rootless SOCKS5 CONNECT with remote DNS, authentication, and IPv4 and IPv6.
3. Add SOCKS5 UDP ASSOCIATE on a separate datagram transport.
4. Add client identities, destination policies, statistics, and HTTP CONNECT.
5. Benchmark against the peers named below. Add multiplexing only if the numbers justify it.

## Campaign: Twice Rust port

The parity campaign is closed. [Acceptance evidence](report.md) records what was verified at `twice-final` and what was never proven. Keep the tag and its compatibility suite indefinitely as the legacy reference.

## Campaign: SOCKS5 proxy mode

### Add SOCKS5 as a second mode, not as a change to Twice

The two modes solve different problems:

- **VPN:** transparent, system-wide IP tunneling.
- **SOCKS5:** selective, unprivileged, application-level tunneling.
- **Together:** one small networking tool covering personal remote connectivity and proxying.

For browsers, CLI tools, containers, and individual applications, proxying is usually the better fit. Proxy-only mode must need no TUN device, no root, no routing changes, and no firewall manipulation.

`src/tunnel.rs` is a two-descriptor TUN and UDP event loop. `src/proto.rs` is a packet-oriented codec. Neither is a general-purpose reliable stream transport. Preserve both unchanged and build the proxy data plane beside them.

### Start from the current baseline

| Area | Current state |
| --- | --- |
| Twice port | Complete; parity campaign closed at `twice-final` |
| Oracle, harness, ledger | Retired from the working tree; retained in the `twice-final` tag |
| Inherited weaknesses | Fixed; follow-up tickets in [TODO.md](../TODO.md) |
| Production dependencies | `graviola` and `libc` |
| Encryption | HiAE |
| Transport | UDP, point-to-point IP packets |
| Performance and memory parity | Retired by owner decision |
| Native macOS runtime | Unverified; needs password-enabled `sudo` on `m1-max` |

### Use mieru as a feature oracle, not a porting target

Mieru separates SOCKS5 request handling, logical sessions, multiplexing, and transports into distinct modules with dedicated tests. Its protocol specification is unusually explicit. Adopt that separation as a design model, not its code.

Adopt these capabilities:

- TCP and UDP transports.
- Session multiplexing, after investigation.
- SOCKS5 UDP ASSOCIATE.
- Remote DNS resolution.
- IPv4 and IPv6.
- Outbound SOCKS5 chaining.
- Per-user destination restrictions.

Do not adopt these choices:

- Time-dependent password key derivation. Its 64 PBKDF2 iterations and clock synchronization requirement add fragility without a stated need.
- A custom encrypted wire protocol without a specific requirement.
- Random padding and entropy manipulation for ordinary proxying.
- A gRPC and Protobuf management layer.

Much of mieru's complexity serves censorship resistance, which is out of scope here. Mieru is GPL-3.0 and this repository is MIT, so implement the functionality independently.

### Keep the data planes independent

Investigate TLS 1.3 for the encrypted proxy transport, using Rustls with Graviola primitives. Authenticate clients and pin server identity. Adding Rustls changes the production dependency invariant in [AGENTS.md](../AGENTS.md); that change needs owner approval before the transport is implemented.

For TCP CONNECT, use one upstream connection per proxied connection. Add no multiplexing protocol, congestion controller, or reliable-UDP layer until benchmarks justify one.

For UDP, evaluate a standardized secure datagram transport separately. Running latency-sensitive datagrams over a reliable TCP stream causes head-of-line blocking.

### Prioritize the feature set

| Capability | Priority |
| --- | --- |
| SOCKS5 CONNECT | P0 |
| Rootless client and server | P0 |
| Remote DNS (`socks5h`) | P0 |
| Authenticated, encrypted remote transport | P0 |
| IPv4 and IPv6 dual stack | P0 |
| SOCKS5 UDP ASSOCIATE | P1 |
| Upstream SOCKS5 chaining | P1 |
| HTTP CONNECT frontend | P1 |
| Multiple independently revocable client identities | P1 |
| Destination access policies | P1 |
| Connection and bandwidth statistics | P1 |
| Adaptive connection pooling or multiplexing | P2 |
| VPN-backed proxy egress | P2 |
| Censorship-resistant transport | Deferred |

The intended CLI shape is:

```
vpn proxy server --listen :8443 --identity server.key
vpn proxy client user@server:8443 --listen 127.0.0.1:1080
vpn proxy local --listen 127.0.0.1:1080
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

Apply these defaults from the first slice:

- Bind loopback by default.
- Never fall back silently to a direct connection.
- Bound every buffer.
- Propagate TCP half-closes correctly.
- Apply destination policies after DNS resolution.

### Treat performance as a stretch goal, not a gate

These are targets to aim for, not measured results and not acceptance gates. Performance parity with the C port stays retired.

| Metric | Target |
| --- | --- |
| Idle RSS per endpoint | <= 5 MiB |
| Idle CPU usage | Near zero |
| Bulk TCP throughput | >= 95% of an equivalent direct encrypted baseline |
| Incremental memory per idle connection | <= 32 KiB userspace |
| Concurrent connections | 10,000+ |
| Steady-state allocations | Zero where practical |
| Native dependencies | No C crypto or external runtime |
| Static Linux musl executable | <= 2 MiB |

Benchmark against mieru, OpenSSH dynamic forwarding, Shadowsocks Rust, and direct sockets. Include connection churn, tail latency, simultaneous short and long flows, packet loss, constrained bandwidth, RSS scaling, and syscall counts. Let multiplexing earn its place through these measurements.

### Keep the legacy boundary explicit

The inherited Twice weaknesses were acceptable inside the exact-port campaign, where parity required reproducing them. They must not constrain the new product. The proxy mode must not inherit Twice authentication semantics. Work the remaining tickets in [TODO.md](../TODO.md) on their own merits, independent of proxy work.

### Record what is not yet verified

The review behind this campaign did not audit mieru's cryptography, verify the Rustls integration, or benchmark any implementation. Treat those three items as open until measured here.

## Handoff

The accepted pair and historical acceptance evidence live in [report.md](report.md). The Twice backlog lives in [TODO.md](../TODO.md). Resume from **Status**, then work through **Sequence**.
