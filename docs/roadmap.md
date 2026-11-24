# Roadmap

This is the single plan for this repository: all current and future work, and the handoff for resuming it. Campaigns are sections below, and their items interleave in **Sequence**. "Resume the roadmap" means continue from **Status**.

## Status

- **Goal:** maintain `twice` as a standalone Rust point-to-point VPN tunnel and add SOCKS5 proxying as a second networking mode.
- **Running:** none.
- **Backlog:** VPN-12 (replay across a receiver restart) awaits an owner decision between a handshake and a persisted epoch record, tracked in [TODO.md](../TODO.md). The proxy campaign below is greenlit but not started.
- **Next slice:** decide the encrypted proxy transport and whether Rustls may become a production dependency, then implement rootless SOCKS5 CONNECT with remote DNS.
- **Resume:** read this Status, run `git status -sb` and `git worktree list`, then run `cargo xtask resume`.

## Sequence

1. Decide the proxy transport and the dependency change it requires.
2. Implement rootless SOCKS5 CONNECT with remote DNS, authentication, and IPv4 and IPv6.
3. Add SOCKS5 UDP ASSOCIATE on a separate datagram transport.
4. Add client identities, destination policies, statistics, and HTTP CONNECT.
5. Benchmark against the peers named below. Add multiplexing only if the numbers justify it.

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
| Inherited weaknesses | Fixed; follow-up tickets in [TODO.md](../TODO.md) |
| Production dependencies | `graviola` and `libc` |
| Encryption | HiAE |
| Transport | UDP, point-to-point IP packets |
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

These are targets to aim for, not measured results and not acceptance gates.

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

Inherited protocol weaknesses must not constrain the new product. The proxy mode must not inherit Twice authentication semantics. Work the remaining tickets in [TODO.md](../TODO.md) on their own merits, independent of proxy work.

### Record what is not yet verified

The review behind this campaign did not audit mieru's cryptography, verify the Rustls integration, or benchmark any implementation. Treat those three items as open until measured here.

## Handoff

The open protocol backlog lives in [TODO.md](../TODO.md). Resume from **Status**, then work through **Sequence**.
