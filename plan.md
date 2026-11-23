## Mission

Implement an exact initial Rust port of https://github.com/jedisct1/twice, using my Graviola fork at https://github.com/laputa-systems/graviola for cryptography.

Co-developing the Graviola fork to add the required algorithms, APIs, hardware acceleration, tests, and benchmarks is explicitly in scope.

The goals, in order, are:

1. Establish a reproducible local C reference and benchmark suite.
2. Add byte-compatible HiAE authenticated encryption and HiAE-MAC to my Graviola fork.
3. Implement a Rust Twice with the original wire format and observable behavior.
4. Demonstrate C/Rust interoperability and differential correctness.
5. Match or exceed the original in both performance and memory usage.
6. Pursue measured improvements while retaining compatibility.

Do the implementation. Do not stop after producing a plan, scaffolding, a benchmark harness, or a successful round trip.

Operate autonomously, make small reviewable local commits, and maintain resumable checkpoints. Follow repository instructions and existing authorization for pushing. Do not open upstream PRs or publish packages as part of this campaign.

## 1. Inspect and freeze the inputs

Read applicable repository instructions and inspect existing work before changing anything. Reuse an existing port if present; otherwise establish a small Rust project without creating a remote repository unnecessarily.

The research starting points are:

- Twice: `391c461697c871e542c7beb44631e77e4c5646dd`
- My Graviola fork: `6f7117267119f58a675ec17a1431cb0f0337fac1`
- Potential implementation material: https://github.com/jedisct1/rust-hiae

Check whether the repositories have advanced. Record any difference before selecting the baseline. Do not silently move the reference during optimization.

Pin the chosen Twice revision, the exact hash of its bundled `src/HiAE_amalgamated.c`, and the Graviola revisions used by each result. Preserve licenses and attribution for adapted code.

Keep the original C source available as an immutable oracle. Instrumented test adapters must be separate and their patches recorded. Final performance comparisons must include the ordinary C executable, not only an extracted approximation.

Maintain one authoritative `plan.md` with:

- Scope and compatibility contract.
- Milestones and evidence required.
- Verified, failed, blocked, and unverified gates.
- Current best pair of Twice/Graviola commits.
- Important upstream discrepancies.
- Rejected experiments and their results.
- The next executable action.

Use machine-readable manifests and benchmark results where appropriate. Avoid creating overlapping status documents.

## 2. Define exactness before implementing

Exactness means matching observable behavior for defined upstream operations, including:

- Datagram bytes and cryptographic outputs.
- CLI arguments, defaults, option ordering, and exit behavior.
- Packet acceptance, delivery order, duplication handling, and loss behavior.
- Reordering, timeouts, peer changes, counter handling, and reconnects.
- MTU discovery and configuration.
- Platform-specific TUN framing.
- Routing/firewall setup and cleanup.

It does not require copying C structure layouts, allocation strategies, or undefined behavior.

Normalize only genuinely nondeterministic output, such as generated randomness, assigned interface names, and platform-specific error text. Document each normalization.

Use the source as the behavioral authority. For example, the current key loader accepts trailing bytes beyond the first 32, and `-m`/`-d` ordering affects discovery. Do not accidentally “correct” such behavior while claiming an exact port.

Keep a compatibility discrepancy ledger. Each entry needs:

- A minimal reproducer.
- Observed C behavior.
- Rust behavior.
- Whether the difference is defined behavior, an oracle defect, or an intentional deviation.
- The milestone affected.

Do not reproduce memory corruption or undefined behavior. Record those cases explicitly instead of silently weakening the compatibility claim.

Protocol redesign, new ciphers, multi-peer operation, and multi-link features are outside the initial campaign. Preserve compatibility before considering them.

## 3. Add exact HiAE support to Graviola

The finished tunnel must use the implementation in my Graviola fork. Adding Graviola only for randomness while retaining another production crypto backend does not satisfy this requirement.

Implement the actual HiAE construction used by Twice’s pinned C implementation:

- 32-byte keys.
- 16-byte nonces.
- 16-byte authentication tags.
- Exact encryption, decryption, MAC, and verification semantics.

Twice’s encrypted mode uses the entire 16-byte header as its nonce and empty associated data.

Its MAC mode initializes HiAE, absorbs the payload as associated data, and finalizes with zero plaintext length. Implement that exact construction. It is not HMAC, GMAC, or encryption followed by discarding the ciphertext.

### API and architecture

Fit the existing Graviola architecture:

- A small safe public API.
- Safe construction and validation code in the appropriate layer.
- Architecture-specific unsafe kernels in the low-level layer.
- Existing conventions for CPU checks, constant-time comparison, errors, and secret handling.

Provide allocation-free operations using caller-owned buffers. An explicitly designed safe in-place API is desirable if it materially reduces tunnel copies. Do not manufacture overlapping Rust references to simulate one.

Specify authentication-failure behavior. Unauthenticated plaintext must never be delivered to the tunnel. Preserve or strengthen the library’s output-clearing and secret-handling conventions without changing successful wire output.

HiAE needs AES round operations, not the full AES block-encryption API. Add suitable internal kernels instead of contorting the construction through AES-GCM or keyed full-AES operations.

A narrowly scoped optional feature is acceptable if it fits the fork. Avoid unrelated feature-system or dependency rewrites.

### Reuse and backend development

Inspect `jedisct1/rust-hiae` as potential implementation material, but prove compatibility against Twice’s exact bundled C implementation before adopting it.

Inspect its backend selection and fallback behavior. Do not import a secret-indexed software S-box path into production while claiming constant-time behavior.

Start with a correct construction and the native backend available on the development host. Then implement the backend coverage needed for the declared targets:

- x86-64 AES-NI.
- AArch64 AES/NEON.
- VAES/AVX512 and ARM SHA3 paths where the C reference uses them and measurements justify the work.
- A constant-time software path where needed to preserve the declared support envelope.

Reuse Graviola’s dispatch machinery where appropriate. Check exactly the CPU features each kernel needs. Do not weaken requirements globally for unrelated algorithms or accidentally impose AES-GCM-specific requirements on HiAE.

Verify secret cleanup for every register class used by new kernels.

Temporary C FFI is permitted for bring-up and testing. The completed production cryptographic path must not depend on the C reference or require compiling bundled C crypto.

### Crypto correctness gate

Create fixed vectors and differential tests for:

- Empty messages and empty/nonempty associated data.
- Partial blocks and lengths around every relevant processing boundary.
- Typical packet sizes, jumbo sizes, and larger accepted inputs.
- Unaligned buffers.
- Encrypt/decrypt interoperability in both directions.
- Exact MAC equality.
- Corrupted ciphertext, nonce, associated data, key, and tag.
- Safe buffer boundaries and authentication-failure output behavior.
- Every available backend, including forced backend tests.

Compare bytes, not merely successful self-round-trips.

Use independently published vectors where available in addition to the pinned C oracle. Retain reproducible randomized differential cases and minimize every disagreement.

Run existing Graviola gates for affected functionality. Changes to shared dispatch or secret-handling machinery require relevant existing-algorithm coverage.

Do not describe the new HiAE implementation as formally verified merely because unrelated Graviola routines have verification evidence.

## 4. Build a deterministic behavioral oracle

Create an unprivileged differential harness around the real C implementation.

Inject or control:

- Randomness.
- Monotonic time.
- Incoming datagrams and TUN packets.
- TUN writes.
- Relevant socket/TUN errors and readiness events.
- External configuration commands.

Keep the original state-transition and cryptographic logic intact. A second handwritten interpretation of the README is not an oracle.

Replay identical logical input, time, and error traces through C and Rust. Compare transmitted datagrams, delivered packets, reconnects, configuration actions, and other observable decisions.

Keep deterministic randomness strictly inside test builds.

Cover:

- In-order delivery, duplicates, gaps, reverse bursts, and slot collisions.
- Window boundaries and jumps beyond the window.
- First packets with unexpected counters.
- Peer restarts, old-epoch packets, and counter arithmetic near wrap.
- Timeout boundaries and multiple buffered gaps.
- Truncation, invalid tags, malformed input, and oversized datagrams.
- Send pressure, interrupted calls, TUN write failures, and reconnect errors.
- MTU probes and discovery outcomes.
- CLI and key-file edge cases.

Preserve the current 1,024-packet reorder window and strict greater-than-2,000-ms timeout behavior, including the periodic checking policy. Reducing those values is not an optimization of the exact port.

Characterize security-relevant inherited behavior, including the public zero-key mode, fixed-nonce probes, epoch changes, and peer-address updates. Record concrete findings; do not silently invent a new protocol to remove them.

Use fuzzing and generated state-machine traces to find disagreements, then save minimized regression cases. Tests should assert observable behavior or important invariants, not internal Rust layout.

## 5. Implement a small Rust tunnel

Start with a direct, understandable implementation of the original event-loop architecture.

Prefer:

- A single-threaded loop.
- Explicit packet ownership and reusable buffers.
- A small platform/syscall layer.
- Graviola as the cryptographic dependency.
- Minimal production dependencies.

Do not introduce an async runtime, task-per-packet architecture, or multithreading before measurement identifies a need.

Keep platform behavior explicit. Linux TUN and macOS utun framing are not identical. Preserve the upstream platform surface and track validation separately.

Prioritize:

1. Native Linux development and local integration tests.
2. Linux x86-64 and AArch64 musl builds and native validation.
3. Native macOS AArch64 validation.
4. The original BSD paths, with honest implementation and execution status.

A successful cross-build does not establish runtime compatibility or native performance. Do not silently remove upstream-supported platforms.

Pin Graviola by a reproducible revision for every committed result. Local path overrides are fine during development, but another checkout must be able to reproduce the tested dependency graph.

## 6. Establish real C/Rust interoperability

In both keyed and no-key modes, run:

| Client | Server |
|---|---|
| C | C |
| Rust | C |
| C | Rust |
| Rust | Rust |

Exercise forward, reverse, and simultaneous bidirectional traffic.

Include real TUN operation, routing, MTU discovery, disconnect/reconnect, and teardown. A crypto vector or UDP echo test does not replace this gate.

Use disposable Linux namespaces and veth links for the primary local topology. Add a routed topology when necessary to validate forwarding behavior.

Run the automatic configuration paths inside isolation. The benchmark must not rewrite the operator’s normal default route or firewall.

On macOS/BSD, use a documented isolated or dedicated test arrangement. Do not invent native results from Linux emulation.

If privileges or a native host are unavailable, mark the affected gate BLOCKED, record the precise missing capability, and continue independent work.

## 7. Deliver a usable local benchmarking suite

Provide a small local command interface for:

- Checking prerequisites.
- Building and identifying the C reference.
- Running compatibility checks.
- Running crypto/component benchmarks.
- Running real-tunnel benchmarks.
- Running memory workloads.
- Comparing two recorded results.
- Resuming the campaign.

A Rust `xtask` or small script-based runner is sufficient. Use established local traffic tools where they meet the requirement. Avoid building a dashboard or general benchmarking platform.

Provide a short screening suite and a stronger final validation suite. Both must emit machine-readable data and a readable summary.

### Layer A: crypto

Measure C HiAE versus Graviola HiAE for:

- Encryption.
- Successful decryption.
- Failed verification.
- MAC generation and verification.

Include small packets, representative MTU-sized packets, jumbo packets, and larger diagnostic sizes. Measure fixed per-operation overhead as well as throughput.

Record the actual selected backend. Compare automatic best-backend operation; matched-backend comparisons are additional diagnostics.

Do not disable the C implementation’s fastest supported path to obtain a Rust win.

### Layer B: packet processing and reordering

Measure framing, complete packet processing, buffer insertion/drain, timeout processing, and peer resets.

Use:

- In-order traffic with no buffering.
- Sparse reordering.
- A nearly full reorder window.
- Repeated gaps and recovery.
- Repeated resets.
- Large accepted payloads.

Record time per packet, allocation count, allocation volume, and retained capacity.

The normal packet path should aim for zero allocations after initialization. If uncommon oversized inputs need a different storage path, measure it.

### Layer C: end-to-end tunnels

Measure:

- TCP goodput.
- UDP offered/received rates, loss, duplication, and ordering.
- Small-packet packet rate.
- CPU time per delivered GiB and per delivered packet.
- Latency distributions at fixed offered load and under saturation.
- Forward, reverse, and duplex behavior.

Use a direct/no-tunnel run to identify the testbed ceiling. A saturated generator or underlay cannot establish that the candidate is faster.

Include a compact impairment set: clean transport, delay, isolated/burst loss, reordering/duplication, and constrained MTU.

Measure loaded latency with an independent probe stream or equivalent method that does not hide stalls when the system slows down.

Keep most combinatorial edge cases in deterministic tests. The full benchmark matrix should remain practical to rerun.

### Memory

Measure each endpoint and the combined tunnel endpoints, excluding traffic generators.

Report separately:

- Virtual/reserved address space.
- Requested/live heap and retained capacity.
- Idle resident memory.
- Resident memory under matched useful load.
- Peak resident memory under identical reorder pressure.
- Memory retained after draining that pressure.
- Relevant stack usage.
- Kernel socket-buffer settings and memory where observable.

Use fresh processes when measuring separate peak-memory phases. Document platform-specific accounting; Linux RSS/PSS and macOS physical footprint are not interchangeable.

The C implementation’s roughly 64 MiB reorder capacity is not automatically its resident footprint.

Use identical payload and occupancy traces. Include ordinary packets and large accepted datagrams. Do not obtain a memory win by shrinking the window, rejecting more inputs, shortening the timeout, dropping traffic, or moving buffering into the kernel.

## 8. Make comparisons fair and claims explicit

Freeze a machine-readable case manifest and acceptance policy before optimization.

Record:

- Both repository commits and binary hashes.
- Compiler/toolchain versions and complete build flags.
- Target architecture, libc, CPU model, and crypto backend.
- MTU, socket-buffer values actually granted, and offload settings.
- Traffic-generator version/configuration.
- CPU/core budget and affinity where available.
- Power/thermal state and relevant competing load.
- Test seeds, raw results, and invalid-run reasons.

The C reference already uses optimized native build flags. Compare equivalent release builds and CPU-feature policies. Report portable/distributable builds separately from host-tuned builds.

Use the same number of endpoint cores initially. More cores do not count as a free performance improvement.

Pair C and Rust trials in randomized or ABBA order, with warm-up. Start with a modest screening sample; use enough independent confirmation runs to resolve the claimed difference. Bootstrap across independent runs, not correlated individual packets.

Predefine invalid-run criteria. Retain rejected samples and reasons.

### Required acceptance

Correctness and interoperability must pass before performance results can qualify a candidate.

The target for every required performance and memory case is equal or better than C.

Operationally:

- Establish measurement repeatability first.
- Permit a predeclared timing equivalence band no wider than 3%, and preferably tighter when repeatability allows.
- Report equivalence honestly as “within the declared margin,” not “faster.”
- Set memory tolerances from observed accounting noise; do not use a large arbitrary allowance to excuse a regression.
- A confirmed regression outside the declared band blocks the gate.
- A noisy or underpowered result is INCONCLUSIVE.
- Never widen the band after seeing an unfavorable candidate.

Require per-case results. A geometric mean cannot hide a small-packet, duplex, memory-pressure, loss, or tail-latency regression.

### Stretch goals

After parity, pursue:

- At least 10% improvement in a meaningful CPU-limited throughput, packet-rate, or CPU-per-delivered-byte workload.
- At least 25% lower measured resident/physical memory in representative ordinary workloads.
- Lower allocation overhead and retained memory under reorder pressure.

These are campaign targets, not promised outcomes. Confirm wins with a fresh run or held-out trace.

The meaningful success state is simultaneous performance and memory parity, with demonstrated improvements where achievable. A large memory win does not excuse an unexplained throughput regression.

WireGuard may be an informational comparator later. It is not the acceptance oracle for this port, and its results must not distract from the C-versus-Rust comparison.

## 9. Optimize in evidence-driven order

Once the exact port passes, investigate:

1. Compact reorder metadata and packet-storage layout.
2. Reusable buffers and avoidable copies.
3. Allocation-free crypto integration and safe in-place operations.
4. The in-order fast path.
5. Empty-window and timeout-processing costs.
6. Graviola backend gaps exposed by the crypto benchmarks.
7. Bounded receive/send batching where supported.

Preserve the full upstream accepted-input domain. Replacing every reorder slot with an MTU-sized array is insufficient if the C receiver accepts larger authenticated datagrams.

Use a compact normal-packet pool with an appropriate oversized-packet representation if measurements support it. Worst-case memory must still accommodate the same information.

Batching needs explicit fairness, ordering, latency, and error-handling checks. It must not gain throughput by creating long stalls in another direction.

For each experiment:

1. State the bottleneck and expected mechanism.
2. Make the smallest useful change.
3. Run affected correctness checks.
4. Run the relevant paired benchmarks.
5. Keep or revert based on evidence.
6. Record the result and next action.

Use SIMD and small unsafe kernels where justified. Keep unsafe contracts narrow and reviewable. Do not remove authentication, bounds validation, secret cleanup, or meaningful checks to improve a benchmark.

Do not spend cycles rewriting cold code unless measurements or a concrete correctness issue justify it.

## 10. Run the campaign persistently

Parallelize independent implementation and review work across the tunnel, Graviola, and harness. Serialize performance measurements on each host.

Commit working checkpoints frequently. Every checkpoint must identify the compatible pair of repository commits.

Do not declare completion because:

- The project builds.
- The Rust implementation interoperates only with itself.
- One happy-path transfer succeeds.
- A microbenchmark improves.
- A required privileged test was skipped.
- A target cross-compiles.
- An unsupported backend was never exercised.

Track milestones independently:

- C reference and baseline established.
- Graviola HiAE byte parity established.
- Rust behavioral parity established.
- Real C/Rust interoperability established.
- Performance parity established.
- Memory parity established.
- Native platform gates established.
- Stretch improvements confirmed.

Distinguish primary-host completion from full-platform completion. Missing evidence remains visible.

When blocked, complete all independent work, leave an exact reproduction command and the missing capability, and move to the next actionable item. Do not repeatedly retry an unavailable environment or spend iterations rewriting plans.

When no useful optimization remains, report measured results and remaining limits honestly. Do not invent progress or silently relax goals.

## Final handoff

Deliver:

- The working Rust tunnel.
- HiAE and HiAE-MAC in my Graviola fork.
- Pinned dependencies and oracle provenance.
- Deterministic differential tests and minimized regressions.
- Real interoperability coverage.
- A reproducible local benchmark suite.
- Raw data plus a concise per-case comparison.
- Current compatibility/security findings.
- Exact verified, failed, blocked, and unverified gates.
- Best commit pair and commands to reproduce it.

Begin now by freezing the oracle, establishing the baseline, and implementing the smallest vertical slice: Graviola HiAE produces the C reference’s packet bytes, and the Rust tunnel exchanges real traffic with the original C implementation.