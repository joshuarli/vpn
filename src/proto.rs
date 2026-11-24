use std::fmt;

pub const HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const MAX_PACKET_LEN: usize = 65536;
/// Size of the receive buffer; a longer datagram is truncated to this by the kernel.
pub const MAX_DATAGRAM_LEN: usize = HEADER_LEN + MAX_PACKET_LEN + TAG_LEN;
pub const PROBE_MAGIC: u64 = u64::MAX;
pub const PROBE_FILL: u8 = 0xAA;

pub const TOO_SMALL_MESSAGE: &str = "Packet too small (missing authentication tag)\n";

/// Random value and counter, little-endian on the wire. The 16 encoded bytes are the cipher nonce.
///
/// Data and MTU probes share one key, so their nonces live in disjoint domains: a data header
/// never has `random == PROBE_MAGIC`, and a probe header always does. A probe's counter is the
/// sender's session random plus a per-process probe sequence number, so every probe datagram is
/// sealed under a fresh nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub random: u64,
    pub counter: u64,
}

impl Header {
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(&self.random.to_le_bytes());
        out[8..].copy_from_slice(&self.counter.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; HEADER_LEN]) -> Header {
        Header {
            random: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            counter: u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        }
    }

    pub fn is_probe(&self) -> bool {
        self.random == PROBE_MAGIC
    }
}

/// Maps a random value into the data domain, which excludes `PROBE_MAGIC`.
const fn data_random(random: u64) -> u64 {
    if random == PROBE_MAGIC { 0 } else { random }
}

/// Outgoing data header sequence: the counter starts at 0 and is incremented before each use;
/// after `u64::MAX` the random value is incremented and the counter restarts at 0. The random
/// value skips `PROBE_MAGIC`, which is reserved for probes.
#[derive(Clone, Copy, Debug)]
pub struct Sender {
    random: u64,
    counter: u64,
}

impl Sender {
    pub const fn new(random: u64) -> Sender {
        Sender { random: data_random(random), counter: 0 }
    }

    pub const fn with_state(random: u64, counter: u64) -> Sender {
        Sender { random: data_random(random), counter }
    }

    pub fn next_header(&mut self) -> Header {
        if self.counter == u64::MAX {
            self.random = data_random(self.random.wrapping_add(1));
            self.counter = 0;
        } else {
            self.counter += 1;
        }
        Header { random: self.random, counter: self.counter }
    }

    pub fn random(&self) -> u64 {
        self.random
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// Outgoing probe header sequence: `random` is `PROBE_MAGIC` and the counter is the session
/// random plus the number of probes sent before, so no two probes of one process share a nonce.
#[derive(Clone, Copy, Debug)]
pub struct ProbeSender {
    base: u64,
    sent: u64,
}

impl ProbeSender {
    pub const fn new(session_random: u64) -> ProbeSender {
        ProbeSender { base: session_random, sent: 0 }
    }

    pub fn next_header(&mut self) -> Header {
        let header = Header { random: PROBE_MAGIC, counter: self.base.wrapping_add(self.sent) };
        self.sent += 1;
        header
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthError;

/// The HiAE operations the protocol needs, in place and allocation free. `nonce` is the encoded
/// header and associated data is always empty.
pub trait Cipher {
    fn encrypt(&self, nonce: &[u8; HEADER_LEN], inout: &mut [u8], tag: &mut [u8; TAG_LEN]);
    /// On `Err` the contents of `inout` are unspecified and must not be used.
    fn decrypt(
        &self,
        nonce: &[u8; HEADER_LEN],
        inout: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AuthError>;
}

/// Startup line; every run is keyed, so payloads are always encrypted and authenticated.
pub const ENCRYPTED_BANNER: &str = "Running in encrypted mode with authentication\n";
pub const AUTH_FAILED_MESSAGE: &str = "Decryption or authentication failed\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    TooSmall,
    Auth,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Rejection::TooSmall => TOO_SMALL_MESSAGE,
            Rejection::Auth => AUTH_FAILED_MESSAGE,
        })
    }
}

/// A datagram of at least 32 bytes split into its parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub header: Header,
    pub nonce: [u8; HEADER_LEN],
    pub body: &'a [u8],
    pub tag: [u8; TAG_LEN],
}

impl<'a> Frame<'a> {
    pub fn parse(datagram: &'a [u8]) -> Option<Frame<'a>> {
        if datagram.len() < HEADER_LEN + TAG_LEN {
            return None;
        }
        let nonce: [u8; HEADER_LEN] = datagram[..HEADER_LEN].try_into().unwrap();
        let tag_at = datagram.len() - TAG_LEN;
        Some(Frame {
            header: Header::from_bytes(&nonce),
            nonce,
            body: &datagram[HEADER_LEN..tag_at],
            tag: datagram[tag_at..].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

/// Server handling of one received datagram, before any side effect on peer state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerRx<'a> {
    /// Fewer than 16 bytes, or a probe header on a datagram larger than any probe discovery
    /// sends: nothing happens, nothing is logged.
    Ignored,
    /// An authenticated probe no larger than `MAX_PROBE_DATAGRAM_LEN`: send the whole datagram
    /// back to the sender unchanged.
    EchoProbe,
    /// Log the rejection and drop; the peer address is not updated.
    Rejected(Rejection),
    /// Authenticated: record the sender as the peer, then pass the header and payload to the
    /// reorder stage.
    Accepted(Accepted<'a>),
}

/// Client handling of one received datagram outside MTU discovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRx<'a> {
    /// Fewer than 16 bytes, or a probe header: a late or replayed probe reply is never data and
    /// must not reach the reorder stage.
    Ignored,
    /// Log the rejection and drop the datagram; the session continues. The connected socket
    /// accepts anything whose source address is the server's, so a spoofed datagram must not be
    /// able to tear the session down.
    Rejected(Rejection),
    Accepted(Accepted<'a>),
}

pub struct Codec<C> {
    cipher: C,
}

impl<C: Cipher> Codec<C> {
    pub fn new(cipher: C) -> Self {
        Codec { cipher }
    }

    /// Writes `header | ciphertext | tag` into `out` and returns the datagram length.
    /// `out` must hold at least `HEADER_LEN + payload.len() + TAG_LEN` bytes.
    pub fn seal(&self, header: &Header, payload: &[u8], out: &mut [u8]) -> usize {
        out[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
        self.seal_in_place(header, out, payload.len())
    }

    /// Seals an MTU probe whose payload is `data_len` bytes of `0xAA`. `header` must come from a
    /// `ProbeSender`.
    pub fn seal_probe(&self, header: &Header, data_len: usize, out: &mut [u8]) -> usize {
        debug_assert!(header.is_probe());
        out[HEADER_LEN..HEADER_LEN + data_len].fill(PROBE_FILL);
        self.seal_in_place(header, out, data_len)
    }

    fn seal_in_place(&self, header: &Header, out: &mut [u8], len: usize) -> usize {
        let nonce = header.to_bytes();
        out[..HEADER_LEN].copy_from_slice(&nonce);
        let mut tag = [0u8; TAG_LEN];
        self.cipher.encrypt(&nonce, &mut out[HEADER_LEN..HEADER_LEN + len], &mut tag);
        out[HEADER_LEN + len..HEADER_LEN + len + TAG_LEN].copy_from_slice(&tag);
        HEADER_LEN + len + TAG_LEN
    }

    /// Verifies the frame and decrypts it into `scratch` (at least `frame.body.len()` bytes).
    pub fn open<'a>(&self, frame: &Frame<'a>, scratch: &'a mut [u8]) -> Result<&'a [u8], AuthError> {
        let buf = &mut scratch[..frame.body.len()];
        buf.copy_from_slice(frame.body);
        self.cipher.decrypt(&frame.nonce, buf, &frame.tag)?;
        Ok(buf)
    }

    pub fn server_receive<'a>(&self, datagram: &'a [u8], scratch: &'a mut [u8]) -> ServerRx<'a> {
        if datagram.len() < HEADER_LEN {
            return ServerRx::Ignored;
        }
        let Some(frame) = Frame::parse(datagram) else {
            return ServerRx::Rejected(Rejection::TooSmall);
        };
        let probe = frame.header.is_probe();
        if probe && datagram.len() > crate::mtu::MAX_PROBE_DATAGRAM_LEN {
            return ServerRx::Ignored;
        }
        match self.open(&frame, scratch) {
            Ok(_) if probe => ServerRx::EchoProbe,
            Ok(payload) => ServerRx::Accepted(Accepted { header: frame.header, payload }),
            Err(AuthError) => ServerRx::Rejected(Rejection::Auth),
        }
    }

    pub fn client_receive<'a>(&self, datagram: &'a [u8], scratch: &'a mut [u8]) -> ClientRx<'a> {
        if datagram.len() < HEADER_LEN {
            return ClientRx::Ignored;
        }
        let Some(frame) = Frame::parse(datagram) else {
            return ClientRx::Rejected(Rejection::TooSmall);
        };
        if frame.header.is_probe() {
            return ClientRx::Ignored;
        }
        match self.open(&frame, scratch) {
            Ok(payload) => ClientRx::Accepted(Accepted { header: frame.header, payload }),
            Err(AuthError) => ClientRx::Rejected(Rejection::Auth),
        }
    }

    /// True when `datagram` is the authenticated echo of the probe sealed with `probe` and
    /// carrying exactly `expected_len` payload bytes. Any other datagram, including a reply to an
    /// earlier probe, is false.
    pub fn is_probe_reply(
        &self,
        datagram: &[u8],
        probe: &Header,
        expected_len: usize,
        scratch: &mut [u8],
    ) -> bool {
        let Some(frame) = Frame::parse(datagram) else {
            return false;
        };
        if !frame.header.is_probe() || frame.header != *probe {
            return false;
        }
        match self.open(&frame, scratch) {
            Ok(payload) => payload.len() == expected_len,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Deterministic stand-in cipher: keystream and tag are simple functions of key and nonce.
    pub struct FakeCipher {
        pub key: [u8; KEY_LEN],
    }

    impl FakeCipher {
        fn stream(&self, nonce: &[u8; HEADER_LEN], i: usize) -> u8 {
            self.key[i % KEY_LEN] ^ nonce[i % HEADER_LEN] ^ (i as u8).wrapping_mul(31)
        }

        fn tag_of(&self, nonce: &[u8; HEADER_LEN], data: &[u8]) -> [u8; TAG_LEN] {
            let mut t = [0u8; TAG_LEN];
            for (i, b) in t.iter_mut().enumerate() {
                *b = self.key[(i * 3) % KEY_LEN] ^ nonce[i];
            }
            for (i, d) in data.iter().enumerate() {
                t[i % TAG_LEN] = t[i % TAG_LEN].rotate_left(1) ^ d ^ (i as u8);
            }
            t[0] ^= data.len() as u8;
            t
        }
    }

    impl Cipher for FakeCipher {
        fn encrypt(&self, nonce: &[u8; HEADER_LEN], inout: &mut [u8], tag: &mut [u8; TAG_LEN]) {
            for (i, b) in inout.iter_mut().enumerate() {
                *b ^= self.stream(nonce, i);
            }
            *tag = self.tag_of(nonce, inout);
        }

        fn decrypt(
            &self,
            nonce: &[u8; HEADER_LEN],
            inout: &mut [u8],
            tag: &[u8; TAG_LEN],
        ) -> Result<(), AuthError> {
            if self.tag_of(nonce, inout) != *tag {
                inout.fill(0);
                return Err(AuthError);
            }
            for (i, b) in inout.iter_mut().enumerate() {
                *b ^= self.stream(nonce, i);
            }
            Ok(())
        }
    }

    pub fn codec() -> Codec<FakeCipher> {
        Codec::new(FakeCipher { key: [7u8; KEY_LEN] })
    }
}

#[cfg(test)]
mod tests {
    use super::testing::codec;
    use super::*;

    fn sealed(c: &Codec<testing::FakeCipher>, h: Header, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_LEN + payload.len() + TAG_LEN];
        let n = c.seal(&h, payload, &mut out);
        assert_eq!(n, out.len());
        out
    }

    const H: Header = Header { random: 0x0102_0304_0506_0708, counter: 0x1112_1314_1516_1718 };
    const P: Header = Header { random: PROBE_MAGIC, counter: 0x2122_2324_2526_2728 };

    #[test]
    fn header_bytes_are_two_little_endian_u64() {
        assert_eq!(
            H.to_bytes(),
            [8, 7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_eq!(Header::from_bytes(&H.to_bytes()), H);
    }

    #[test]
    fn probe_headers_carry_magic_random_and_count_from_the_session_random() {
        let mut p = ProbeSender::new(u64::MAX - 1);
        let a = p.next_header();
        assert_eq!(a, Header { random: PROBE_MAGIC, counter: u64::MAX - 1 });
        assert_eq!(&a.to_bytes()[..8], &[0xFF; 8]);
        assert_eq!(p.next_header(), Header { random: PROBE_MAGIC, counter: u64::MAX });
        assert_eq!(p.next_header(), Header { random: PROBE_MAGIC, counter: 0 });
        assert!(a.is_probe());
        assert!(Header { random: u64::MAX, counter: 0 }.is_probe());
        assert!(!Header { random: u64::MAX - 1, counter: u64::MAX }.is_probe());
    }

    #[test]
    fn data_headers_never_use_the_probe_random() {
        let mut s = Sender::new(PROBE_MAGIC);
        assert_eq!(s.next_header(), Header { random: 0, counter: 1 });
        let mut s = Sender::with_state(PROBE_MAGIC - 1, u64::MAX);
        assert_eq!(s.next_header(), Header { random: 0, counter: 0 });
        let mut s = Sender::with_state(PROBE_MAGIC, 5);
        assert!(!s.next_header().is_probe());
    }

    #[test]
    fn two_same_size_probes_differ_on_the_wire() {
        let c = codec();
        let mut p = ProbeSender::new(0x1234);
        let (mut a, mut b) = (vec![0u8; 132], vec![0u8; 132]);
        c.seal_probe(&p.next_header(), 100, &mut a);
        c.seal_probe(&p.next_header(), 100, &mut b);
        assert_ne!(a[..16], b[..16]);
        assert_ne!(a[16..], b[16..]);
    }

    #[test]
    fn sender_counts_from_one_and_increments_random_after_counter_max() {
        let mut s = Sender::new(41);
        assert_eq!(s.next_header(), Header { random: 41, counter: 1 });
        assert_eq!(s.next_header(), Header { random: 41, counter: 2 });
        let mut s = Sender::with_state(41, u64::MAX - 1);
        assert_eq!(s.next_header(), Header { random: 41, counter: u64::MAX });
        assert_eq!(s.next_header(), Header { random: 42, counter: 0 });
        assert_eq!(s.next_header(), Header { random: 42, counter: 1 });
    }

    #[test]
    fn sender_random_wraps_past_the_probe_random() {
        let mut s = Sender::with_state(u64::MAX - 1, u64::MAX);
        assert_eq!(s.next_header(), Header { random: 0, counter: 0 });
    }

    #[test]
    fn keyed_datagram_layout_is_header_ciphertext_tag() {
        let c = codec();
        let d = sealed(&c, H, b"hello world");
        assert_eq!(&d[..16], &H.to_bytes());
        assert_eq!(d.len(), 16 + 11 + 16);
        assert_ne!(&d[16..27], b"hello world");
    }

    #[test]
    fn seal_then_open_round_trips() {
        let c = codec();
        let payload: Vec<u8> = (0..1500u32).map(|i| (i * 7) as u8).collect();
        let d = sealed(&c, H, &payload);
        let mut scratch = vec![0u8; MAX_PACKET_LEN];
        let frame = Frame::parse(&d).unwrap();
        assert_eq!(frame.header, H);
        assert_eq!(c.open(&frame, &mut scratch).unwrap(), &payload[..]);
    }

    #[test]
    fn empty_payload_is_a_valid_32_byte_datagram() {
        let c = codec();
        let d = sealed(&c, H, b"");
        assert_eq!(d.len(), 32);
        let mut scratch = [0u8; 8];
        match c.server_receive(&d, &mut scratch) {
            ServerRx::Accepted(a) => assert!(a.payload.is_empty() && a.header == H),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tampering_any_part_fails_authentication() {
        let c = codec();
        let d = sealed(&c, H, b"payload bytes");
        let mut scratch = vec![0u8; 64];
        for i in [0, 9, 16, 20, d.len() - 1] {
            let mut bad = d.clone();
            bad[i] ^= 1;
            let r = c.server_receive(&bad, &mut scratch);
            assert!(matches!(r, ServerRx::Rejected(Rejection::Auth)), "byte {i}: {r:?}");
        }
    }

    #[test]
    fn rejection_texts_are_exact() {
        let mut scratch = vec![0u8; 64];
        let k = codec();
        let mut d = sealed(&k, H, b"x");
        d[16] ^= 1;
        match k.server_receive(&d, &mut scratch) {
            ServerRx::Rejected(r) => assert_eq!(r.to_string(), "Decryption or authentication failed\n"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            Rejection::TooSmall.to_string(),
            "Packet too small (missing authentication tag)\n"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = codec();
        let mut b = codec();
        b.cipher.key[0] ^= 1;
        let d = sealed(&a, H, b"secret");
        let mut scratch = vec![0u8; 64];
        assert!(matches!(
            b.client_receive(&d, &mut scratch),
            ClientRx::Rejected(Rejection::Auth)
        ));
    }

    #[test]
    fn server_ignores_datagrams_under_16_bytes_even_with_probe_prefix() {
        let c = codec();
        let mut scratch = [0u8; 8];
        assert_eq!(c.server_receive(&[], &mut scratch), ServerRx::Ignored);
        assert_eq!(c.server_receive(&[0xFF; 15], &mut scratch), ServerRx::Ignored);
    }

    #[test]
    fn server_echoes_only_authenticated_probes_up_to_the_largest_probe() {
        let c = codec();
        let mut scratch = vec![0u8; MAX_PACKET_LEN];
        let mut junk = vec![0xFFu8; 16];
        junk.extend_from_slice(b"not authenticated at all, any length");
        assert_eq!(c.server_receive(&junk, &mut scratch), ServerRx::Rejected(Rejection::Auth));
        assert_eq!(c.server_receive(&[0xFF; 16], &mut scratch), ServerRx::Rejected(Rejection::TooSmall));

        let largest = crate::mtu::MAX_PROBE_DATAGRAM_LEN - HEADER_LEN - TAG_LEN;
        let mut d = vec![0u8; crate::mtu::MAX_PROBE_DATAGRAM_LEN + 1];
        let n = c.seal_probe(&P, largest, &mut d);
        assert_eq!(c.server_receive(&d[..n], &mut scratch), ServerRx::EchoProbe);
        let n = c.seal_probe(&P, largest + 1, &mut d);
        assert_eq!(c.server_receive(&d[..n], &mut scratch), ServerRx::Ignored);
    }

    #[test]
    fn server_rejects_16_to_31_bytes_as_too_small_without_reconnect_semantics() {
        let c = codec();
        let mut scratch = [0u8; 8];
        for len in 16..32 {
            assert_eq!(
                c.server_receive(&vec![1u8; len], &mut scratch),
                ServerRx::Rejected(Rejection::TooSmall),
                "len {len}"
            );
        }
    }

    #[test]
    fn client_ignores_under_16_and_rejects_16_to_31_bytes() {
        let c = codec();
        let mut scratch = [0u8; 8];
        assert_eq!(c.client_receive(&[1u8; 15], &mut scratch), ClientRx::Ignored);
        for len in 16..32 {
            assert_eq!(
                c.client_receive(&vec![1u8; len], &mut scratch),
                ClientRx::Rejected(Rejection::TooSmall),
                "len {len}"
            );
        }
    }

    #[test]
    fn client_rejects_failed_authentication_without_reconnecting() {
        let c = codec();
        let good = sealed(&c, H, b"abc");
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 0xFF;
        let mut scratch = [0u8; 8];
        assert_eq!(c.client_receive(&bad, &mut scratch), ClientRx::Rejected(Rejection::Auth));
        match c.client_receive(&good, &mut scratch) {
            ClientRx::Accepted(a) => assert_eq!(a.payload, b"abc"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn client_ignores_a_late_probe_reply_outside_discovery() {
        let c = codec();
        let mut d = vec![0u8; 16 + 40 + 16];
        c.seal_probe(&P, 40, &mut d);
        let mut scratch = [0u8; 64];
        assert_eq!(c.client_receive(&d, &mut scratch), ClientRx::Ignored);
    }

    #[test]
    fn server_accepts_authenticated_data_and_exposes_header_and_payload() {
        let c = codec();
        let d = sealed(&c, H, b"ip packet");
        let mut scratch = [0u8; 64];
        match c.server_receive(&d, &mut scratch) {
            ServerRx::Accepted(a) => {
                assert_eq!(a.header, H);
                assert_eq!(a.payload, b"ip packet");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn probe_seal_uses_magic_header_and_encrypts_aa_fill() {
        let c = codec();
        let mut d = vec![0u8; 16 + 100 + 16];
        assert_eq!(c.seal_probe(&P, 100, &mut d), 132);
        assert_eq!(&d[..16], &P.to_bytes());
        let mut s = vec![0u8; 128];
        let frame = Frame::parse(&d).unwrap();
        assert_eq!(c.open(&frame, &mut s).unwrap(), &[0xAA; 100][..]);
    }

    #[test]
    fn probe_reply_requires_the_sent_header_valid_tag_and_exact_size() {
        let c = codec();
        let mut d = vec![0u8; 16 + 100 + 16];
        c.seal_probe(&P, 100, &mut d);
        let mut s = vec![0u8; 256];
        assert!(c.is_probe_reply(&d, &P, 100, &mut s));
        assert!(!c.is_probe_reply(&d, &P, 99, &mut s));
        assert!(!c.is_probe_reply(&d, &P, 101, &mut s));
        let next = Header { random: PROBE_MAGIC, counter: P.counter + 1 };
        assert!(!c.is_probe_reply(&d, &next, 100, &mut s));
        let mut bad = d.clone();
        bad[40] ^= 1;
        assert!(!c.is_probe_reply(&bad, &P, 100, &mut s));
        assert!(!c.is_probe_reply(&d[..31], &P, 0, &mut s));
        let data = sealed(&c, H, &[0xAA; 100]);
        assert!(!c.is_probe_reply(&data, &H, 100, &mut s));
    }

    #[test]
    fn max_size_payload_round_trips() {
        let c = codec();
        let payload = vec![0x5Au8; MAX_PACKET_LEN];
        let d = sealed(&c, H, &payload);
        assert_eq!(d.len(), MAX_DATAGRAM_LEN);
        let mut scratch = vec![0u8; MAX_PACKET_LEN];
        match c.client_receive(&d, &mut scratch) {
            ClientRx::Accepted(a) => assert_eq!(a.payload.len(), MAX_PACKET_LEN),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn startup_banner_announces_encryption() {
        assert_eq!(ENCRYPTED_BANNER, "Running in encrypted mode with authentication\n");
    }
}

