Prefix: VPN
Next: 14

### VPN-12 · P3 · Replay protection does not survive a receiver restart

- **Area:** Protocol
- **Where:** src/reorder.rs (RetiredEpochs, first-packet baseline), src/proto.rs (Header)
- **Problem:** Without a handshake, a receiver that restarts, or that has seen more than 64 peer epochs since a capture, accepts any captured authenticated datagram as the start of a new epoch and delivers it. Replay protection is in-memory and bounded.
- **Recommendation:** Decide on a session handshake or a persisted per-peer epoch record in a draft RFC before implementing; until then document the limit.
- **Fix with:** architect
- **Effort:** L

