use graviola::aead::HiAe;

use crate::proto::{AuthError, Cipher, HEADER_LEN, KEY_LEN, TAG_LEN};

#[cfg(target_arch = "x86_64")]
pub const REQUIRED_CPU_FEATURES: &str = "adx, aes, avx, avx2, bmi1, bmi2, pclmulqdq, and popcnt";
#[cfg(target_arch = "aarch64")]
pub const REQUIRED_CPU_FEATURES: &str = "aes, neon, pmull, and sha2";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const REQUIRED_CPU_FEATURES: &str = "a supported x86-64 or AArch64 feature set";

/// Overwrites `buf` with zeros in a way the optimiser may not remove.
pub fn wipe(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// The CPU lacks the features Graviola needs to run HiAE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedCpu;

impl UnsupportedCpu {
    pub fn message() -> String {
        format!(
            "twice: this CPU is not supported: HiAE needs {REQUIRED_CPU_FEATURES} CPU support\n"
        )
    }
}

/// HiAE from Graviola behind the protocol's `Cipher` trait.
pub struct HiAeCipher {
    inner: HiAe,
}

impl HiAeCipher {
    /// Checks the CPU first so an unsupported machine gets an error instead of a panic.
    pub fn new(key: [u8; KEY_LEN]) -> Result<Self, UnsupportedCpu> {
        if !graviola::util::is_cpu_supported() {
            return Err(UnsupportedCpu);
        }
        Ok(HiAeCipher { inner: HiAe::new(key) })
    }
}

impl Cipher for HiAeCipher {
    fn encrypt(&self, nonce: &[u8; HEADER_LEN], inout: &mut [u8], tag: &mut [u8; TAG_LEN]) {
        self.inner.encrypt(nonce, &[], inout, tag);
    }

    fn decrypt(
        &self,
        nonce: &[u8; HEADER_LEN],
        inout: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AuthError> {
        self.inner.decrypt(nonce, &[], inout, tag).map_err(|_| AuthError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Codec, Header, ProbeEchoes, ServerRx};

    #[test]
    fn datagrams_round_trip_through_the_codec() {
        let codec = Codec::new(HiAeCipher::new([9u8; KEY_LEN]).unwrap());
        let header = Header { random: 7, counter: 3 };
        let payload = [0x45u8; 100];
        let mut out = vec![0u8; 16 + payload.len() + 16];
        let n = codec.seal(&header, &payload, &mut out);
        assert_eq!(n, out.len());
        let mut scratch = vec![0u8; 128];
        match codec.server_receive(&out, &mut scratch, &mut ProbeEchoes::new()) {
            ServerRx::Accepted(a) => {
                assert_eq!(a.header, header);
                assert_eq!(a.payload, &payload[..]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_different_key_is_rejected() {
        let a = Codec::new(HiAeCipher::new([1; KEY_LEN]).unwrap());
        let b = Codec::new(HiAeCipher::new([2; KEY_LEN]).unwrap());
        let mut out = vec![0u8; 16 + 10 + 16];
        a.seal(&Header { random: 1, counter: 1 }, &[1u8; 10], &mut out);
        let mut scratch = vec![0u8; 64];
        assert!(matches!(b.server_receive(&out, &mut scratch, &mut ProbeEchoes::new()), ServerRx::Rejected(_)));
    }
}
