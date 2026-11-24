Prefix: VPN
Next: 11

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

