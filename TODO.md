Prefix: VPN
Next: 11

### VPN-4 · P2 · Authenticate before echoing probe-magic datagrams

- **Area:** Security
- **Where:** src/tunnel.rs (server receive path), src/proto.rs:39 (is_probe)
- **Problem:** The server checks the probe magic header before authentication and reflects any datagram of at least 16 bytes beginning with sixteen 0xff bytes back to its source, up to the 65,568-byte receive buffer, with no key, tag, or session. This is an unauthenticated UDP reflection primitive.
- **Recommendation:** Authenticate the datagram before taking the probe path and cap reflected probe size. Add a test that an unauthenticated magic-prefixed datagram is dropped.
- **Fix with:** none
- **Effort:** M

### VPN-7 · P2 · Do not reconnect on a spoofable short or bad-tag datagram

- **Area:** Security
- **Where:** src/proto.rs:12 (TOO_SMALL_MESSAGE), src/tunnel.rs:358-385 (reconnect)
- **Problem:** The client treats a 16-31 byte datagram or a failed tag as fatal: it logs, closes the socket, and reconnects with a sleep ladder and firewall pass. The connected UDP socket accepts any datagram whose source is the server's, so an attacker able to spoof that address can force repeated reconnects.
- **Recommendation:** Ignore short or unauthenticated datagrams during an established session, or rate-limit reconnects. Add a test that one bad datagram does not tear down the session.
- **Fix with:** none
- **Effort:** M

### VPN-8 · P2 · Create the key file atomically with 0600

- **Area:** Security
- **Where:** src/cli.rs (genkey path, GENKEY_CHMOD_FAILED_STDERR at 297)
- **Problem:** genkey checks access(F_OK), creates the file with the process umask, writes the key, closes it, and only then chmods to 0600, so the key is readable under the umask in between and the existence check races with creation.
- **Recommendation:** Create with mode 0600 using OpenOptionsExt::mode with O_CREAT|O_EXCL, then write, with no post-hoc chmod. Add a test asserting the mode at creation.
- **Fix with:** none
- **Effort:** S

### VPN-10 · P3 · Ignore late authenticated probe replies outside discovery

- **Area:** Protocol
- **Where:** src/mtu.rs (discovery loop), src/proto.rs:39 (is_probe)
- **Problem:** Only the discovery loop treats probe-magic datagrams specially on the client. Outside discovery, a late or replayed authenticated probe reply with random and counter both 2^64-1 is processed as ordinary data: its payload is written to the TUN and it flips the reorder epoch, forcing another reset.
- **Recommendation:** Drop probe-magic datagrams outside discovery instead of feeding them to the reorder stage. Add a test that a late probe reply does not change the epoch.
- **Fix with:** none
- **Effort:** S

