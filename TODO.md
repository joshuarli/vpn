Prefix: VPN
Next: 14

### VPN-11 · P2 · Keep the peer epoch and counter across a client reconnect reset

- **Area:** Security
- **Where:** src/reorder.rs (Reorder::reset, first-packet baseline in process), src/tunnel.rs (Tunnel::reconnect)
- **Problem:** Tunnel::reconnect calls Reorder::reset, which forgets the current peer random value and expected counter. The first authenticated datagram after the reset becomes the new baseline, so a replayed datagram from the server's current epoch with an old counter is delivered to the TUN again after every client reconnect. Retired-epoch tracking does not cover this because the epoch itself is still current.
- **Recommendation:** Keep the peer random value and the delivered high-water mark across a reconnect reset, clearing only buffered packets and statistics, and add a regression test that replays an old same-epoch counter after reset.
- **Fix with:** none
- **Effort:** S

### VPN-12 · P3 · Replay protection does not survive a receiver restart

- **Area:** Protocol
- **Where:** src/reorder.rs (RetiredEpochs, first-packet baseline), src/proto.rs (Header)
- **Problem:** Without a handshake, a receiver that restarts, or that has seen more than 64 peer epochs since a capture, accepts any captured authenticated datagram as the start of a new epoch and delivers it. Replay protection is in-memory and bounded.
- **Recommendation:** Decide on a session handshake or a persisted per-peer epoch record in a draft RFC before implementing; until then document the limit.
- **Fix with:** architect
- **Effort:** L

### VPN-13 · P3 · Server echoes replayed authenticated probes to any source

- **Area:** Security
- **Where:** src/proto.rs (Codec::server_receive EchoProbe), src/tunnel.rs (Tunnel::server_receive)
- **Problem:** The server authenticates and size-caps probes before echoing, but it does not check probe freshness or the source address. An attacker holding one captured probe can spoof a victim's address and make the server reflect datagrams of up to 8,970 bytes at a 1:1 size ratio.
- **Recommendation:** Echo a probe only when its counter has not been echoed before (for example, a small recent-probe set), or only to the current peer address once a session exists, and add a test that a repeated probe is not echoed twice.
- **Fix with:** none
- **Effort:** S

