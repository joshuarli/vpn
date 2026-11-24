# Roadmap

This is the single plan for this repository: all current and future work, and the handoff for resuming it. Campaigns are sections below, and their items interleave in **Sequence**. "Resume the roadmap" means continue from **Status**.

## Status

- **Idle:** no local slice is running. The active campaign plan and its Status remain in [plan.md](../plan.md) until `xtask resume` reads the Status here instead.
- **Last accepted pair:** `twice-final`; correctness integration is green. Performance gates are lifted, and memory parity remains unverified.
- **Parked:** O1–O3 until the owner reinstates the parity gates. Native macOS runtime proof needs password-enabled `sudo` on `m1-max`.
- **Next slice:** none locally; switch the resume reader and move the campaign plan here when that work is authorized.

## Campaign: Twice Rust port

The campaign plan, decisions, gate states, and resume instructions remain in [plan.md](../plan.md). [Acceptance evidence](report.md) records the verified pair and remaining gaps.

## Later

- Ticket to file: switch `xtask resume` to read the Status in `docs/roadmap.md`, then move `plan.md` into the roadmap.
