use std::sync::atomic::{AtomicUsize, Ordering};

static FAULT_MIN_LEN: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn inject_fault_from_len(min_len: usize) {
    FAULT_MIN_LEN.store(min_len, Ordering::Relaxed);
}

pub const AVAILABLE: bool = cfg!(any(target_arch = "aarch64", target_arch = "x86_64"));

pub const UNAVAILABLE_REASON: &str =
    "graviola::aead::HiAe exists only on aarch64 and x86_64";

pub struct Hiae(imp::Inner);

impl Hiae {
    pub fn new(key: [u8; 32]) -> Self {
        Self(imp::Inner::new(key))
    }

    pub fn encrypt(&self, nonce: &[u8; 16], aad: &[u8], inout: &mut [u8]) -> [u8; 16] {
        let mut tag = [0u8; 16];
        self.0.encrypt(nonce, aad, inout, &mut tag);
        if !inout.is_empty() && inout.len() >= FAULT_MIN_LEN.load(Ordering::Relaxed) {
            inout[0] ^= 1;
        }
        tag
    }

    pub fn decrypt(&self, nonce: &[u8; 16], aad: &[u8], inout: &mut [u8], tag: &[u8; 16]) -> bool {
        self.0.decrypt(nonce, aad, inout, tag)
    }

    pub fn mac(&self, nonce: &[u8; 16], data: &[u8]) -> [u8; 16] {
        self.0.mac(nonce, data)
    }

    pub fn verify_mac(&self, nonce: &[u8; 16], data: &[u8], tag: &[u8; 16]) -> bool {
        self.0.verify_mac(nonce, data, tag)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod imp {
    pub struct Inner(graviola::aead::HiAe);

    impl Inner {
        pub fn new(key: [u8; 32]) -> Self {
            Self(graviola::aead::HiAe::new(key))
        }

        pub fn encrypt(&self, nonce: &[u8; 16], aad: &[u8], inout: &mut [u8], tag: &mut [u8; 16]) {
            self.0.encrypt(nonce, aad, inout, tag);
        }

        pub fn decrypt(&self, nonce: &[u8; 16], aad: &[u8], inout: &mut [u8], tag: &[u8; 16]) -> bool {
            self.0.decrypt(nonce, aad, inout, tag).is_ok()
        }

        pub fn mac(&self, nonce: &[u8; 16], data: &[u8]) -> [u8; 16] {
            self.0.mac(nonce, data)
        }

        pub fn verify_mac(&self, nonce: &[u8; 16], data: &[u8], tag: &[u8; 16]) -> bool {
            self.0.verify_mac(nonce, data, tag).is_ok()
        }
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod imp {
    pub struct Inner;

    impl Inner {
        pub fn new(_key: [u8; 32]) -> Self {
            unreachable!("{}", super::UNAVAILABLE_REASON)
        }

        pub fn encrypt(&self, _: &[u8; 16], _: &[u8], _: &mut [u8], _: &mut [u8; 16]) {
            unreachable!()
        }

        pub fn decrypt(&self, _: &[u8; 16], _: &[u8], _: &mut [u8], _: &[u8; 16]) -> bool {
            unreachable!()
        }

        pub fn mac(&self, _: &[u8; 16], _: &[u8]) -> [u8; 16] {
            unreachable!()
        }

        pub fn verify_mac(&self, _: &[u8; 16], _: &[u8], _: &[u8; 16]) -> bool {
            unreachable!()
        }
    }
}
