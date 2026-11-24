Prefix: VPN
Next: 2
### VPN-1 · P4 · xtask resume reads plan.md, blocking its move into the roadmap

- **Area:** Tooling
- **Where:** xtask/src/resume.rs:29; plan.md
- **Problem:** `xtask resume` reads plan.md and prints its `## Status`, so the campaign plan must stay at the repository root beside docs/roadmap.md, the single plan. Two plan files contradict the one-roadmap convention.
- **Recommendation:** Make `xtask resume` read the Status section of docs/roadmap.md, then fold plan.md into the roadmap and delete it. Acceptance: `cargo xtask resume` prints the roadmap Status with plan.md removed.
- **Fix with:** none
- **Effort:** S

