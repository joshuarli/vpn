use std::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    fn HiAE_encrypt(
        key: *const u8,
        nonce: *const u8,
        msg: *const u8,
        ct: *mut u8,
        msg_len: usize,
        ad: *const u8,
        ad_len: usize,
        tag: *mut u8,
    ) -> c_int;
    fn HiAE_decrypt(
        key: *const u8,
        nonce: *const u8,
        msg: *mut u8,
        ct: *const u8,
        ct_len: usize,
        ad: *const u8,
        ad_len: usize,
        tag: *const u8,
    ) -> c_int;
    fn HiAE_mac(
        key: *const u8,
        nonce: *const u8,
        data: *const u8,
        data_len: usize,
        tag: *mut u8,
    ) -> c_int;
    fn HiAE_force_implementation(name: *const c_char) -> c_int;
    fn HiAE_get_implementation_name() -> *const c_char;
}

pub fn force_implementation(name: &'static CStr) -> Result<(), String> {
    // SAFETY: `name` is 'static and NUL-terminated; the C side keeps the pointer.
    match unsafe { HiAE_force_implementation(name.as_ptr()) } {
        0 => Ok(()),
        rc => Err(format!(
            "C oracle cannot provide implementation {name:?} (returned {rc})"
        )),
    }
}

pub fn implementation_name() -> String {
    // SAFETY: the C side returns a pointer to a static NUL-terminated string.
    unsafe { CStr::from_ptr(HiAE_get_implementation_name()) }
        .to_string_lossy()
        .into_owned()
}

pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    msg: &[u8],
    ct: &mut [u8],
    ad: &[u8],
) -> [u8; 16] {
    assert_eq!(msg.len(), ct.len());
    let mut tag = [0u8; 16];
    // SAFETY: every pointer is valid for the length passed alongside it.
    let rc = unsafe {
        HiAE_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            msg.as_ptr(),
            ct.as_mut_ptr(),
            msg.len(),
            ad.as_ptr(),
            ad.len(),
            tag.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0, "HiAE_encrypt failed");
    tag
}

pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 16],
    msg: &mut [u8],
    ct: &[u8],
    ad: &[u8],
    tag: &[u8; 16],
) -> bool {
    assert_eq!(msg.len(), ct.len());
    // SAFETY: every pointer is valid for the length passed alongside it.
    let rc = unsafe {
        HiAE_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            msg.as_mut_ptr(),
            ct.as_ptr(),
            ct.len(),
            ad.as_ptr(),
            ad.len(),
            tag.as_ptr(),
        )
    };
    rc == 0
}

pub fn mac(key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    // SAFETY: every pointer is valid for the length passed alongside it.
    let rc = unsafe {
        HiAE_mac(
            key.as_ptr(),
            nonce.as_ptr(),
            data.as_ptr(),
            data.len(),
            tag.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0, "HiAE_mac failed");
    tag
}
