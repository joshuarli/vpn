Prefix: VPN
Next: 11

### VPN-10 · P3 · Ignore late authenticated probe replies outside discovery

- **Area:** Protocol
- **Where:** src/mtu.rs (discovery loop), src/proto.rs:39 (is_probe)
- **Problem:** Only the discovery loop treats probe-magic datagrams specially on the client. Outside discovery, a late or replayed authenticated probe reply with random and counter both 2^64-1 is processed as ordinary data: its payload is written to the TUN and it flips the reorder epoch, forcing another reset.
- **Recommendation:** Drop probe-magic datagrams outside discovery instead of feeding them to the reorder stage. Add a test that a late probe reply does not change the epoch.
- **Fix with:** none
- **Effort:** S

