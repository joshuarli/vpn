# Twice Rust Port Campaign

## Status

- **Goal:** an exact Rust port of `jedisct1/twice` using HiAE from the `laputa-systems/graviola` fork, proven against the C original, then at performance and memory parity.
- **Last accepted pair:** none.
- **Accepted:** none. **Red:** none. **Parked:** none.
- **Next slice:** G0.
- **Resume:** read this file, run `git status -sb`, then run the acceptance command of the next slice.

| Milestone | State |
| --- | --- |
| C reference and baseline | not started |
| Graviola HiAE byte parity | not started |
| Rust behavioral parity | not started |
| Real C/Rust interoperability | not started |
| Performance parity | not started |
| Memory parity | not started |
| Native platform gates | not started |
| Stretch improvements | not started |

Gate states are `VERIFIED`, `FAILED`, `BLOCKED`, `INCONCLUSIVE`, and `UNVERIFIED`. Primary-host completion and full-platform completion are reported separately.

## Charter

- **Do the implementation.** A plan, scaffold, harness, or successful round trip is not completion.
- **Decide and keep going.** No question is left for runtime. Record a decision only when a later slice depends on it, by rewriting **Decisions**.
- **Stop only** when every local deliverable passes or every remaining item is parked behind a hard stop. **Needs environment** items do not hold the campaign open.
- **Hard stops park the item:** an effect outside **Execution boundary**, a change to a frozen oracle or acceptance policy, or a loop that cannot check anything. Complete all independent work first.
- **Parity before optimization.** Until phase 4, performance is measured and logged. Only the egregious thresholds below gate earlier work.
- **Fix egregious problems in their own commit:** a packet-path allocation after initialization, a Rust case over 2x C CPU time or peak RSS, a narrow test over 60 s, or any crash, data race, or unauthenticated delivery. Record anything else in `compat/ledger.json` or `results/experiments.jsonl`.
- **Failure rule:** establish the cause with `root-cause` before retrying. An item gets two attempts with materially different approaches, then parks on its branch with the cause, reproducer, and retry condition. Never repeat an unavailable environment.
- **Steering:** run the [parent steering checkpoint](/Users/josh/.claude/skills/orchestrate/references/campaigns.md#parent-steering-checkpoint) after each accepted slice, on resume, and after a slice fails twice.
- **Delegation is native Claude Code subagents only (owner, 2026-11-23).** Never call `pi-subagent-bridge`, its MCP tools, its `scope-check`, or Codex. Use `sonnet` for worker and mechanic lanes, `haiku` for read-only scouts, and `opus` at `xhigh` only for exceptional architecture or adversarial review. If the pinned model is unavailable, that lane is blocked. Never use a `fable` model.
- **Lane scope:** the parent creates each worktree at `.work/wt/<lane>`, names it as the only writable location, and checks `git diff --name-only <base>...HEAD` against the slice's owned paths before integrating. Follow the [worktree lifecycle](/Users/josh/.claude/skills/orchestrate/SKILL.md#worktree-lifecycle).
- **Parallelism:** run ready slices with disjoint owned paths in parallel, up to `perf-gate-ready -s` headroom. The parent is the only writer of root `Cargo.toml`, `Cargo.lock`, and this file. Performance measurements are serial per host.
- **Toolchain:** the owner's `rust-toolchain.toml` (`nightly-2026-11-09` with `rust-src`, `llvm-tools`, `clippy`) is binding here, and Graviola pins the same channel. Never edit, override, or bypass either file. Containers install exactly this channel. Adding a `rustup` target to it is allowed.
- **Commits:** small Conventional Commits with the workstream (`crypto`, `core`, `harness`, `bench`, `platform`) as scope and the item ID in the body. Code comments never cite this doc. No formatters.
- **Scratch:** `.work/` only, never `/tmp` or `$TMPDIR` on the host. `.work/` is disposable, so required results are committed under `results/`.

## Decisions

### Owner

1. **Graviola publication (2026-11-23).** The executor may push only branch `twice-hiae` to `laputa-systems/graviola`, so `Cargo.lock` can pin an exact public revision. No other branch, PR, release, package, or remote.
2. **CPU envelope (2026-11-23).** The port supports x86-64 and AArch64 CPUs meeting Graviola's baseline and exits with a clear startup error elsewhere. No software HiAE backend ships. This is ledger entry `DEV-001`, an intentional deviation from C's table-based fallback.
3. **Native subagents only (2026-11-23).** See **Charter**.
4. **Toolchain (2026-11-23).** `rust-toolchain.toml` is binding. See **Charter**.

### Prescribed

| ID | Decision | Reason | Reversed by |
| --- | --- | --- | --- |
| P1 | The port lives in this repo (`joshuarli/vpn`, branch `master`), package and binary `twice`. | The owner created this repo and toolchain for it. | Owner |
| P2 | Twice oracle is `391c461697c871e542c7beb44631e77e4c5646dd`, as submodule `oracle/upstream`. `src/HiAE_amalgamated.c` must hash to SHA-256 `05f745a783317f3e6dc3b0a85a71075eacd1a2a6f82711243e8f6c053c3d6f05`. | Current upstream HEAD at preflight. The reference never moves during the campaign. | Owner |
| P3 | Graviola work happens in `~/repos/graviola` on `twice-hiae`, created by merging `origin/laputa/main` (`bbb6286`) into `origin/main` (`6f71172`). | `main` lacks the fork's zmm16-31 wipe, zeroisation, and CPU-gate fixes that HiAE's secret handling needs. The merge is clean and its 220 Graviola tests pass on AArch64. | Merge no longer clean |
| P4 | Graviola API is `graviola::aead::HiAe`: `new(key: [u8; 32])`, `encrypt(&self, nonce: &[u8; 16], aad, inout: &mut [u8], tag_out: &mut [u8; 16])`, `decrypt(&self, nonce, aad, inout, tag: &[u8; 16]) -> Result<(), Error>`, `mac(&self, nonce, data) -> [u8; 16]`, `verify_mac(&self, nonce, data, tag) -> Result<(), Error>`. | Matches existing in-place AEAD conventions, allocates nothing, and needs no overlapping references. | Measured need |
| P5 | Failed `decrypt` zeroises all of `inout` before returning `Error::DecryptFailed`. Tags compare with `ct_equal`. Keys zeroise on drop. Each kernel runs under `Entry::new_secret()` and clears every register class it uses. | Unauthenticated plaintext never leaves the API, and wire output is unchanged. | None |
| P6 | HiAE lives in `low/{aarch64,x86_64}/hiae.rs` plus safe `mid/hiae.rs`, using AES round instructions directly. No Cargo feature. Dispatch checks each kernel's exact CPU features and does not change other algorithms' requirements. | Fits the existing layers. | Binary-size regression over 5% |
| P7 | Do not copy `rust-hiae` code into Graviola. It may be read, and its published vectors may be used with attribution. | Its `MIT OR Apache-2.0` code cannot be relicensed to Graviola's `Apache-2.0 OR ISC OR MIT-0`. Its soft backend also uses a secret-indexed S-box. | Author permission |
| P8 | The port is MIT and keeps Frank Denis's Twice copyright notice. | It is derived from MIT-licensed code. | Owner |
| P9 | Production dependencies are `graviola` and `libc` only. `xtask` may add `serde` and `serde_json`. Any other dependency needs a recorded maintenance, license, build-time, and binary-size check within the gates here. No async runtime or threads. | Draft's small-tunnel requirement. | Measured need |
| P10 | Rust calls OS effects through `libc` symbols, and reads randomness from `/dev/urandom`. | One `LD_PRELOAD` shim can then drive the unmodified C binary and the Rust binary, with no test hook in production. | None |
| P11 | The oracle is the unmodified C source built with its own Makefile flags, dynamically linked against glibc, under `oracle/shim/twice_shim.c`. The shim controls `clock_gettime`, `poll`, `read`, `readv`, `write`, `writev`, `recv`, `recvfrom`, `send`, `sendmsg`, `sendto`, `socket`, `connect`, `bind`, `setsockopt`, `fcntl`, `open`, `ioctl`, `sleep`, `popen`, `pclose`, `fork`, `execvp`, `waitpid`, `getaddrinfo`, `getnameinfo`, and `signal`. | Keeps C state-transition logic intact. `sleep`, name resolution, and subprocesses are decisions the draft's list omitted. | None |
| P12 | Primary host is Linux AArch64 in OrbStack on this Apple M5 Max, in a disposable container with its own network namespaces. | Proven by running the C tunnel here. | None |
| P13 | Inherited security weaknesses are reproduced and recorded, never fixed in this campaign. Memory corruption and undefined behavior are not reproduced. | The owner requires exactness and no silent protocol change. | Owner |
| P14 | `cargo xtask` is the only command interface. | Draft allows it and it avoids extra tooling. | None |

### Delegated

- **Internal Rust structure:** executor's choice inside P9 and P10. Tests assert observable behavior.
- **Reorder storage:** executor's choice if it preserves all 1,024 slots, the full accepted payload domain, and worst-case information.
- **Traffic tools:** `iperf3` plus a small `xtask` UDP probe by default. Substitute only if the tool saturates before the direct-path ceiling, and log the reason.
- **Screening sample size:** at least 5 ABBA pairs. Final validation uses at least 20.

## Compatibility contract

Exactness covers observable behavior for defined upstream operations: datagram bytes, cryptographic outputs, CLI, stdout and stderr per stream, exit status, packet acceptance, delivery order, duplicate and loss handling, reordering, timeouts, peer changes, counters, reconnects, MTU discovery and configuration, TUN framing, and routing and firewall setup and cleanup. It excludes C layouts, allocation strategy, and undefined behavior.

**Allowed normalizations only:** the startup random value and values derived from it, generated keys, kernel-assigned interface names, OS error text after a `perror` or `gai_strerror` prefix, and process IDs. Each is listed in `compat/normalizations.json`. Interleaving between stdout and stderr is not compared because C buffers stdout on a pipe.

**`compat/ledger.json`** has one entry per difference or finding: `id`, minimal reproducer, C behavior, Rust behavior, class (`defined`, `oracle-defect`, `intentional-deviation`), and milestone. An undecided entry blocks its milestone.

### Behavior inventory

Paths are in `oracle/upstream`. D1 needs a named case for every row. Behaviors marked *predicted* come from reading the source, and D1 confirms them.

| Area | Required behavior | Source |
| --- | --- | --- |
| Wire | 8-byte little-endian random value, 8-byte little-endian counter, payload, 16-byte tag; the 16-byte header is the nonce, AD is empty in encrypted mode | `src/twice.c:820`, `:830` |
| No-key mode | All-zero key; payload is cleartext; tag is `HiAE_mac` (init, absorb payload as AD, finalize with message length 0) | `src/twice.c:838`, `src/HiAE_amalgamated.c:2237` |
| Key file | Reads the first 32 bytes, accepts trailing bytes, rejects short files | `src/twice.c:101` |
| Options | `-k`, `-m`, `-d` must precede the mode; `-m` clears discovery, `-d` sets it, so order matters; `atoi` parsing; range 68 to 9000 | `src/twice.c:1261` |
| Mode | Anything other than exactly `server` is a client | `src/twice.c:1302` |
| `genkey` | Recognized only as `argv[1]`, with alias `generate-key`; refuses an existing path; writes then `chmod 0600` | `src/twice.c:1198` |
| Exit status | Usage 254; early setup errors 1; server firewall or `doit` setup failure 255; event-loop failure after setup still prints `Done.` and exits 0 | `src/twice.c:1150`, `:1112`, `:1390`, `:1405` |
| Signals | First SIGINT or SIGTERM requests clean exit and restores the default handler | `src/twice.c:128` |
| Reorder | 1,024 slots by `counter % 1024`; duplicate and collision drop; jump at or beyond the window resets and delivers | `src/twice.c:423`, `:536` |
| Timeout | Strictly over 2,000 ms, checked at least 50 ms apart, skips to the lowest buffered counter | `src/twice.c:399`, `:408`, `:783` |
| Peer epoch | Random-value change resets reorder state and accepts that counter | `src/twice.c:500` |
| Counter wrap | Sender increments random after `UINT64_MAX`; receiver arithmetic wraps as unsigned | `src/twice.c:812`, `:536` |
| Oversize | TUN reads over `tun_mtu + 62` drop and end that loop iteration | `src/twice.c:585`, `:805` |
| Server input | Under 16 bytes ignored; probe magic echoed before authentication; failed auth dropped; peer address updates after auth and before replay checks | `src/twice.c:933`, `:949`, `:996` |
| Client input | Under 16 bytes ignored; 16 to 31 bytes or failed auth triggers reconnect; late authenticated probe replies enter reorder (*predicted*) | `src/twice.c:1019`, `:1036`, `:1052`, `:1078` |
| Send errors | Server logs and continues; client reconnects except on `EAGAIN` | `src/twice.c:859`, `:906` |
| Reconnect | 100 attempts, sleeping `min(i, 3)` seconds; reorder reset; sender counter preserved | `src/twice.c:324`, `:331` |
| MTU discovery | Client-only binary search 576 to 9000; 2 tries at 500 ms; failure yields 576; observed 9000 path gives `tun_mtu` 8938 and interface MTU 8922 | `src/twice.c:718`, `include/twice.h:59` |
| Socket setup | Requests 4 MiB buffers; server is dual-stack where available | `src/twice.c:204`, `:208` |
| TUN framing | Linux raw; macOS and OpenBSD 4-byte family header, with writes under 20 bytes returning 0; other BSDs raw | `src/os.c:213`, `:224`, `:255` |
| Config commands | Exact argv and order per OS and role, including default-route suppression and teardown | `src/os.c:414` |

**Seed ledger entries for X1:** public zero-key mode, fixed-nonce keyed probes, unauthenticated probe reflection, replay-driven peer-address change, replayed old-epoch reset, remote client reconnect on a bad datagram, non-atomic `genkey` permissions, `atoi` overflow (undefined behavior), and the late-probe-reply path.

## Baseline

Measured 2026-11-23 on Apple M5 Max, 18 cores, 48 GiB, with Linux AArch64 7.2 under OrbStack.

| Check | Result |
| --- | --- |
| Twice C build | 1.1 s, 68,408-byte stripped binary |
| Real C tunnel in namespaces | Keyed, no-key, and `-d` all passed ping and TCP, exited 0, and left no rules behind |
| `rust-hiae` vs C on ARM NEON and ARM SHA3 | 10,620 byte-identical cases. This qualifies it as a second vector source only |
| Graviola merged base, AArch64 | 220 tests pass, about 6 s warm |
| Graviola `main` x86-64 lib tests under QEMU `-cpu max` | 174 pass in 64 s cold. QEMU exposes VAES but not AVX512 |

**Known false red:** Graviola's 8 `cavp` tests fail unless you run `git submodule update --init thirdparty/cavp thirdparty/wycheproof`.

**Host caveat:** `perf-gate-ready` reported `constrained` because swap was about 88% used. Timing claims need the rule in **Performance acceptance**. Memory and allocation measurements always run.

## Sequence

Items in one workstream run in order. Parallel-safe sets after G0: `{H*}` in Graviola, `{T1, T2, T3}` in `src/`, `{S1, D1}` in `oracle/` and `xtask/src/diff/`, and `{B1, B2}` in `bench/` and `xtask/src/bench/`.

### Phase 0: ground

**G0: repo, pins, command surface.** Owns all root files, `oracle/upstream`, `xtask/src/main.rs`, `compat/`, `LICENSE`. Commit the owner's staged `rust-toolchain.toml` unchanged in the first commit. Create the workspace, Graviola branch per P3 (push it), pinned container image by digest, and subcommands `doctor`, `oracle`, `test`, `crypto-diff`, `diff`, `lab`, `platform-check`, `bench`, `mem`, `compare`, and `resume`.
Acceptance: `cargo xtask doctor && cargo xtask oracle verify` reports the toolchain, both pins, the C hash, and container capabilities, and fails on a modified oracle file.

### Phase 1: parity and completeness

**H1: HiAE on AArch64.** Prereq G0. Owns Graviola `low/aarch64/hiae.rs`, `mid/hiae.rs`, `tests/hiae*`, and exports. Implements P4 to P6 with a NEON kernel. Covers every case in **Crypto correctness**.
Acceptance: `cargo xtask crypto-diff --backend arm-neon` and `cargo test --locked -p graviola` in Graviola.

**H2: HiAE on x86-64 AES-NI.** Prereq H1. Owns Graviola `low/x86_64/hiae.rs`.
Acceptance: `cargo xtask crypto-diff --backend aesni --qemu`. This proves bytes only, and native proof is on **Needs environment**.

**T1: pure protocol core.** Prereq G0. Owns `src/{cli,proto,reorder,mtu,config}.rs`. No I/O in decision logic.
Acceptance: `cargo test --locked -p twice --lib`.

**S1: deterministic oracle.** Prereq G0. Owns `oracle/shim/`, `oracle/cases/`, `xtask/src/diff/`. Implements P11, a JSONL trace format, replay, normalization, and delta-debugging minimization.
Acceptance: `cargo xtask diff --self-check` replays a trace twice through C with identical results, and fails on a deliberately altered expected event.

**T2: Linux tunnel vertical slice.** Prereq H1, T1. Owns `src/{main,tunnel,crypto}.rs`, `src/os/{mod,linux}.rs`. Implements the single-threaded poll loop and full Linux configuration.
Acceptance: `cargo xtask lab smoke --client rust --server c --key` then `--client c --server rust --key`, each passing traffic in both directions.

**D1: behavioral corpus.** Prereq S1, T2. Owns `oracle/cases/**` and fixes in `src/` by handoff from T-series. One named case per **Behavior inventory** row, plus: in-order, duplicates, gaps, reverse bursts, slot collisions, window boundaries, jumps, unexpected first counters, peer restarts, old epochs, near-wrap counters, timeout boundaries, multiple gaps, truncation, invalid tags, malformed and oversized datagrams, send pressure, `EINTR`, TUN write failures, reconnect errors, MTU outcomes, CLI and key-file edges. Add seeded generated traces and save each minimized disagreement.
Acceptance: `cargo xtask diff --all` passes, and `cargo xtask diff --mutation-check` shows at least one failing case for each of a fixed set of deliberate Rust faults, one per inventory area.

**I1: real interoperability.** Prereq T2. Owns `xtask/src/lab/`. Runs the 4-way client/server matrix in keyed and no-key modes, with forward, reverse, and simultaneous traffic, real TUN, routing, MTU discovery, disconnect and reconnect, and teardown. Adds a routed topology for forwarding. Asserts rules exist while running and are gone after exit.
Acceptance: `cargo xtask lab matrix`.

**T3: macOS and BSD paths.** Prereq T2. Owns `src/os/{macos,bsd}.rs`. Ports every upstream path. Tests framing with socket pairs.
Acceptance: `cargo test --locked -p twice os::` on macOS, and `cargo xtask platform-check` for FreeBSD, NetBSD, OpenBSD, and DragonFly targets, using `-Zbuild-std` where no prebuilt std exists. A target that cannot check is `BLOCKED` with the exact error. Compilation is never reported as runtime validation.

**B1: benchmark suite and frozen policy.** Prereq G0, may run beside phase 1. Owns `bench/`, `xtask/src/bench/`. Implements Layers A to C, memory, `compare`, and screening and final suites with JSON and readable summaries. Measures C and A/A repeatability, then commits `bench/manifest.json` and `bench/policy.json` before any optimization.
Acceptance: `cargo xtask bench --suite screen --candidate c --baseline c` emits a valid result with every required metadata field.

### Phase 2: hardening

**X1: security characterization.** Prereq D1. Owns `compat/ledger.json`. Records a reproducer for each seed entry.
Acceptance: `cargo xtask diff --ledger` runs every reproducer and fails on an undecided entry.

**B2: parity measurement.** Prereq D1, I1, B1. Runs the final suite on the best pair.
Acceptance: `cargo xtask bench --suite final --candidate rust --baseline c && cargo xtask compare --policy bench/policy.json` produces per-case verdicts.

### Phase 3: linux target completion

**L1: musl builds.** Prereq T2. Owns release profile and `xtask/src/release.rs`. Builds Linux x86-64 and AArch64 musl. Runs the AArch64 build natively through I1.
Acceptance: `cargo xtask lab matrix --rust-target aarch64-unknown-linux-musl`. The x86-64 build is `UNVERIFIED` at runtime until the **Needs environment** command passes.

### Phase 4: optimization

Starts only after D1, I1, and B2. For each experiment: state the bottleneck and mechanism, make the smallest change, run affected correctness checks and paired benchmarks, keep or revert on evidence, and append to `results/experiments.jsonl`.

**O1: ARM SHA3 kernel.** Prereq B2. C selects this backend on the primary host, so required comparisons use it. Acceptance: `cargo xtask crypto-diff --backend arm-sha3` plus paired Layer A.

**O2: tunnel optimization, in order:** compact reorder metadata and storage, reusable buffers and avoidable copies, allocation-free in-place crypto, in-order fast path, empty-window and timeout cost, Graviola backend gaps, bounded batching. Batching must pass fairness, ordering, latency, and error checks with no long stall in the opposite direction. Oversized accepted datagrams keep a valid storage path. Acceptance per experiment: `cargo xtask diff --all`, `cargo xtask lab matrix`, and `cargo xtask compare` on affected cases.

**O3: stretch.** Targets are at least 10% improvement in a CPU-limited throughput, packet-rate, or CPU-per-byte workload, at least 25% lower RSS in representative ordinary workloads, and lower allocation and retained memory under reorder pressure. Confirm each win with a fresh run or held-out trace. Missing a stretch target does not fail the campaign. Stop when two consecutive experiments give no confirmed gain.

### Phase 5: close

**C1.** Remove bring-up FFI from production paths, and prove liveness with `dead-code-archaeology`. Run an independent `review`, and fix its P1 and P2 findings. Write `docs/report.md` with the final handoff. Close lanes per the [campaign reference](/Users/josh/.claude/skills/orchestrate/references/campaigns.md#close-or-pause).
Acceptance: `cargo xtask resume --verify-final` rebuilds the best pair from a clean checkout, then reruns `crypto-diff`, `diff --all`, `lab matrix`, and `compare`.

## Acceptance

Correctness and interoperability must pass before any performance result can qualify a candidate.

| Deliverable | Proof | Fails when |
| --- | --- | --- |
| Frozen, attributed inputs | `cargo xtask oracle verify` | Any pin, hash, or license notice differs |
| HiAE and HiAE-MAC in Graviola | `cargo xtask crypto-diff --all-available` and Graviola tests | Any byte differs, or a backend was not actually selected |
| No C crypto in production | `cargo tree -e normal` and symbol check in `resume --verify-final` | Production graph or binary contains `HiAE_` C symbols or builds C |
| Rust behavioral parity | `cargo xtask diff --all`, `--mutation-check` | Any unledgered difference or surviving mutation |
| Real interop | `cargo xtask lab matrix` | Any cell, direction, mode, or teardown check fails or is skipped |
| Benchmark suite | `cargo xtask bench --suite screen` and `final` | Required metadata or raw data is missing |
| Performance and memory parity | `cargo xtask compare --policy bench/policy.json` | Any required case is a confirmed regression |
| Findings and limits | `cargo xtask diff --ledger`, `docs/report.md` | Any undecided entry, or a gate state is omitted |
| Reproducibility | `cargo xtask resume --verify-final` | A clean checkout cannot reproduce the pair |

**Not sufficient for completion:** a build, Rust-only interop, one happy-path transfer, a microbenchmark win, a skipped privileged test, a cross-compile, or an unexercised backend.

### Crypto correctness

Fixed vectors and C differentials cover empty messages, empty and nonempty AD, every length 0 to 512, lengths around each block boundary, typical packets, jumbo sizes, 65,507 and 65,536 bytes, unaligned buffers, encryption and decryption in both directions, exact MAC equality, corruption of ciphertext, nonce, AD, key, and tag, buffer-boundary rejection, zeroised output on failure, and forced runs of every available backend. Use published HiAE vectors plus the pinned C oracle. Randomized cases use recorded seeds and minimized failures. Run existing Graviola tests for affected functionality, and include other algorithms if shared dispatch or secret handling changes. Never call this HiAE implementation formally verified.

### Benchmark coverage

- **Layer A, crypto:** encrypt, successful decrypt, failed verify, MAC generate and verify at small, MTU, jumbo, and larger diagnostic sizes, with per-operation overhead and throughput. Record the selected backend. The required comparison is automatic best backend against automatic best backend. Matched backends are diagnostic. Never disable C's fastest path.
- **Layer B, packet path:** framing, full packet processing, buffer insert and drain, timeout processing, and peer resets, using in-order, sparse reorder, nearly full window, repeated gaps and recovery, repeated resets, and large payloads. Record time per packet, allocation count and volume, and retained capacity. The normal packet path targets zero allocations after initialization.
- **Layer C, tunnel:** TCP goodput, UDP offered and received rate, loss, duplication, ordering, small-packet rate, CPU per delivered GiB and packet, and latency distributions at fixed load and saturation, in forward, reverse, and duplex. Include a direct no-tunnel ceiling and impairments: clean, delay, isolated and burst loss, reorder and duplication, constrained MTU. Loaded latency uses an independent probe stream.
- **Memory:** per endpoint and combined, excluding generators: virtual size, requested and live heap, retained capacity, idle RSS, RSS under matched load, peak RSS under identical reorder pressure, memory retained after drain, stack use, and granted socket buffers and kernel memory where observable. Use a fresh process per peak phase and identical payload and occupancy traces, with ordinary and large datagrams. Linux RSS/PSS and macOS physical footprint are reported separately. A memory win may not come from a smaller window, rejected inputs, a shorter timeout, dropped traffic, or kernel buffering.

### Performance acceptance

`bench/policy.json` is frozen before optimization and is never widened after seeing a candidate.

- **Recorded for every run:** both commits, binary hashes, toolchains, full build flags, target, libc, CPU, crypto backend, MTU, granted socket buffers, offloads, generator version and config, core budget and affinity, power and thermal state, competing load, seeds, raw results, and invalid-run reason.
- **Builds:** compare equivalent release builds. Host-tuned Rust is compared with C's native flags, and portable builds are reported separately.
- **Design:** equal endpoint cores, warm-up, ABBA pairs, at least 5 for screening and 20 for final. Use a seeded 10,000-resample bootstrap of per-run paired log ratios for a 95% interval.
- **Timing band:** `max(1%, 2 × A/A interval half-width)`, capped at 3%. If A/A needs more than 3%, the case is `INCONCLUSIVE`.
- **Memory tolerance:** `max(one page, observed A/A spread)`, capped at 2% of the C value.
- **Verdict, oriented so higher is better:** `FASTER` if the lower bound is above 0. `WITHIN MARGIN` if the lower bound is at or above minus the band. `REGRESSION` if the upper bound is below minus the band, which blocks the gate. Otherwise `INCONCLUSIVE`.
- **Invalid run:** either endpoint crashes or exits nonzero, generator saturates, the direct ceiling is under 1.25x the tunnel result, granted buffers or offloads differ between arms, thermal throttling is reported, or `perf-gate-ready -1` reports overlap. Retain the sample and reason.
- **Busy host:** check `perf-gate-ready` once. If it is not ready, do not wait. Absolute and sub-10% timing cases are `INCONCLUSIVE`, and the owner's rerun goes on **Needs environment**. Memory, allocation, and work-count gates still run.
- **Reporting:** every result is per case. A geometric mean never decides a gate. Equivalence is reported as "within the declared margin", never "faster".

## Needs environment

Each item stays visible and does not hold local completion open.

| Proof | Needed | Owner command |
| --- | --- | --- |
| Final timing gates if the host is busy | Quiet primary host | `cargo xtask bench --suite final --candidate rust --baseline c && cargo xtask compare --policy bench/policy.json` |
| Native x86-64 Linux, AES-NI, musl runtime, performance | x86-64 Linux host with Graviola's baseline CPU features and `CAP_NET_ADMIN` | `cargo xtask lab matrix --rust-target x86_64-unknown-linux-musl && cargo xtask bench --suite final --candidate rust --baseline c` |
| VAES/AVX512 kernel, justified by measurement | AVX512+VAES x86-64 host | `cargo xtask bench --suite final --layer crypto --backend-report`. Implement the kernel only if C's backend beats AES-NI Rust outside the band |
| Bare-metal Linux AArch64 performance | Non-virtualized host | `cargo xtask bench --suite final --candidate rust --baseline c` |
| Native macOS utun, routes, teardown | `sudo` on a dedicated Mac or VM with no production routes | `sudo cargo xtask lab native-macos` |
| FreeBSD, OpenBSD, NetBSD, DragonFly runtime | Dedicated VM for each | `cargo xtask lab native-bsd --os <name>` |

## Execution boundary and non-goals

**Authorized:** local commits in this repo on `master`. Clone and commit in `~/repos/graviola`. Push `twice-hiae` to `laputa-systems/graviola`. Install the pinned toolchain's targets. Pull and run disposable containers with `NET_ADMIN`, `SYS_ADMIN`, `MKNOD`, `/dev/net/tun`, and unconfined seccomp and AppArmor. Change routes, firewall rules, and sysctls only inside namespaces created by that container.

**Forbidden:** pushing this repo, pushing any other Graviola branch, force-pushing, opening PRs or issues upstream, publishing packages, creating remotes, changing either toolchain file, running formatters, changing CI, `--privileged` containers, host-network containers, using `sudo` on the macOS host, touching the operator's routes or firewall, and stopping or altering other containers. Destructive git operations are limited to branches and worktrees this campaign created.

**Non-goals:** protocol redesign, new ciphers, multi-peer or multi-link operation, fixing inherited security weaknesses, an async or multithreaded architecture before measurement requires it, a dashboard or general benchmark platform, rewriting cold code without evidence, and WireGuard as an acceptance oracle. WireGuard may appear only as a labeled informational comparator after O2.

**Contract changes for the owner:** new public `graviola::aead::HiAe` API on `twice-hiae`, and `DEV-001` CPU envelope.

## Final handoff

`docs/report.md` delivers: the working tunnel, HiAE and HiAE-MAC in the fork, pinned dependencies and oracle provenance, deterministic differential tests and minimized regressions, interop coverage, the benchmark suite, raw data under `results/` with a concise per-case comparison, compatibility and security findings, rejected experiments, every gate's state, and the best commit pair with commands to reproduce it.
