use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::c;
use crate::rng::derive;
use crate::rs::Hiae;

#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub seed: u64,
    pub msg_len: usize,
    pub ad_len: usize,
    pub msg_off: usize,
    pub ad_off: usize,
}

impl Case {
    pub fn describe(&self) -> String {
        format!(
            "seed={:#x} msg_len={} ad_len={} msg_off={} ad_off={}",
            self.seed, self.msg_len, self.ad_len, self.msg_off, self.ad_off
        )
    }

    pub fn flag(&self) -> String {
        format!(
            "--case {:#x}:{}:{}:{}:{}",
            self.seed, self.msg_len, self.ad_len, self.msg_off, self.ad_off
        )
    }
}

const CANARY: u8 = 0xa5;
const TAIL: usize = 32;

struct Buf {
    v: Vec<u8>,
    off: usize,
    len: usize,
}

impl Buf {
    fn new(data: &[u8], off: usize) -> Self {
        let mut v = vec![CANARY; off + data.len() + TAIL];
        v[off..off + data.len()].copy_from_slice(data);
        Self { v, off, len: data.len() }
    }

    fn zeroed(len: usize, off: usize) -> Self {
        Self::new(&vec![0u8; len], off)
    }

    fn s(&self) -> &[u8] {
        &self.v[self.off..self.off + self.len]
    }

    fn m(&mut self) -> &mut [u8] {
        &mut self.v[self.off..self.off + self.len]
    }

    fn check_canary(&self, who: &str) -> Result<(), String> {
        let bad = self.v[..self.off]
            .iter()
            .chain(&self.v[self.off + self.len..])
            .any(|b| *b != CANARY);
        if bad {
            Err(format!("{who} wrote outside its buffer"))
        } else {
            Ok(())
        }
    }
}

fn same(what: &str, rust: &[u8], c: &[u8]) -> Result<(), String> {
    if rust == c {
        return Ok(());
    }
    let at = rust.iter().zip(c).position(|(a, b)| a != b);
    Err(match at {
        Some(i) => format!(
            "{what} differs at byte {i}: rust={:02x} c={:02x}",
            rust[i], c[i]
        ),
        None => format!("{what} length differs: rust={} c={}", rust.len(), c.len()),
    })
}

fn flip(data: &[u8], index: usize, bit: u8) -> Vec<u8> {
    let mut out = data.to_vec();
    out[index] ^= 1 << bit;
    out
}

struct Inputs<'a> {
    case: &'a Case,
    key: [u8; 32],
    nonce: [u8; 16],
    ct: &'a [u8],
    ad: &'a [u8],
    tag: [u8; 16],
}

fn expect_rejected(label: &str, i: &Inputs<'_>) -> Result<(), String> {
    let ad = Buf::new(i.ad, i.case.ad_off);
    let mut rs = Buf::new(i.ct, i.case.msg_off);
    if Hiae::new(i.key).decrypt(&i.nonce, ad.s(), rs.m(), &i.tag) {
        return Err(format!("{label}: Rust accepted corrupted input"));
    }
    if rs.s().iter().any(|b| *b != 0) {
        return Err(format!("{label}: Rust left output unzeroised after failure"));
    }
    rs.check_canary("rust decrypt")?;

    let c_in = Buf::new(i.ct, i.case.msg_off);
    let mut c_out = Buf::zeroed(i.ct.len(), i.case.msg_off);
    if c::decrypt(&i.key, &i.nonce, c_out.m(), c_in.s(), ad.s(), &i.tag) {
        return Err(format!("{label}: C oracle accepted corrupted input"));
    }
    Ok(())
}

fn run(c: &Case) -> Result<u32, String> {
    let mut kr = derive(c.seed, 1);
    let key: [u8; 32] = kr.bytes();
    let nonce: [u8; 16] = kr.bytes();
    let mut msg = vec![0u8; c.msg_len];
    derive(c.seed, 2).fill(&mut msg);
    let mut ad = vec![0u8; c.ad_len];
    derive(c.seed, 3).fill(&mut ad);
    let mut cr = derive(c.seed, 4);
    let hiae = Hiae::new(key);
    let ad_b = Buf::new(&ad, c.ad_off);
    let msg_b = Buf::new(&msg, c.msg_off);
    let mut n = 0;

    let mut rs_ct = Buf::new(&msg, c.msg_off);
    let rs_tag = hiae.encrypt(&nonce, ad_b.s(), rs_ct.m());
    let mut c_ct = Buf::zeroed(c.msg_len, c.msg_off);
    let c_tag = c::encrypt(&key, &nonce, msg_b.s(), c_ct.m(), ad_b.s());
    rs_ct.check_canary("rust encrypt")?;
    c_ct.check_canary("C encrypt")?;
    same("encrypt ciphertext", rs_ct.s(), c_ct.s())?;
    same("encrypt tag", &rs_tag, &c_tag)?;
    n += 2;

    let mut c_pt = Buf::zeroed(c.msg_len, c.msg_off);
    if !c::decrypt(&key, &nonce, c_pt.m(), rs_ct.s(), ad_b.s(), &rs_tag) {
        return Err("C oracle rejected a ciphertext Rust produced".into());
    }
    same("C decrypt of Rust ciphertext", &msg, c_pt.s())?;
    c_pt.check_canary("C decrypt")?;

    let mut rs_pt = Buf::new(c_ct.s(), (c.msg_off + 5) % 64);
    if !hiae.decrypt(&nonce, ad_b.s(), rs_pt.m(), &c_tag) {
        return Err("Rust rejected a ciphertext the C oracle produced".into());
    }
    same("Rust decrypt of C ciphertext", rs_pt.s(), &msg)?;
    rs_pt.check_canary("rust decrypt")?;
    n += 2;

    for (what, data) in [("ad", ad_b.s()), ("msg", msg_b.s())] {
        let rs_mac = hiae.mac(&nonce, data);
        let c_mac = c::mac(&key, &nonce, data);
        same(&format!("mac over {what}"), &rs_mac, &c_mac)?;
        if !hiae.verify_mac(&nonce, data, &c_mac) {
            return Err(format!("Rust verify_mac rejected the C mac over {what}"));
        }
        let mut bad = c_mac;
        bad[cr.below(16)] ^= 1 << cr.below(8);
        if hiae.verify_mac(&nonce, data, &bad) {
            return Err(format!("Rust verify_mac accepted a corrupted mac over {what}"));
        }
        n += 3;
    }

    let base = Inputs { case: c, key, nonce, ct: rs_ct.s(), ad: &ad, tag: rs_tag };
    let ct = rs_ct.s().to_vec();

    if c.msg_len > 0 {
        let bad = flip(&ct, cr.below(c.msg_len), cr.below(8) as u8);
        expect_rejected("corrupt ciphertext", &Inputs { ct: &bad, ..base })?;
        expect_rejected("truncated ciphertext", &Inputs { ct: &ct[..c.msg_len - 1], ..base })?;
        n += 2;
    }
    if c.ad_len > 0 {
        let bad = flip(&ad, cr.below(c.ad_len), cr.below(8) as u8);
        expect_rejected("corrupt aad", &Inputs { ad: &bad, ..base })?;
        expect_rejected("truncated aad", &Inputs { ad: &ad[..c.ad_len - 1], ..base })?;
        n += 2;
    }
    let bad = flip(&nonce, cr.below(16), cr.below(8) as u8);
    expect_rejected("corrupt nonce", &Inputs { nonce: bad.try_into().unwrap(), ..base })?;
    let bad = flip(&key, cr.below(32), cr.below(8) as u8);
    expect_rejected("corrupt key", &Inputs { key: bad.try_into().unwrap(), ..base })?;
    let bad = flip(&rs_tag, cr.below(16), cr.below(8) as u8);
    expect_rejected("corrupt tag", &Inputs { tag: bad.try_into().unwrap(), ..base })?;
    n += 3;

    Ok(n)
}

pub fn check(case: &Case) -> Result<u32, String> {
    match catch_unwind(AssertUnwindSafe(|| run(case))) {
        Ok(result) => result,
        Err(payload) => {
            let text = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic".to_owned());
            Err(format!("panic: {text}"))
        }
    }
}

pub fn minimize(failing: Case) -> (Case, String) {
    let mut best = failing;
    let mut message = check(&best).expect_err("case must fail to be minimized");
    let mut budget = 400;
    loop {
        let mut improved = false;
        for field in 0..4 {
            let value = |c: &Case| match field {
                0 => c.msg_len,
                1 => c.ad_len,
                2 => c.msg_off,
                _ => c.ad_off,
            };
            let v = value(&best);
            let mut candidates = vec![0, 1, v / 2, v.saturating_sub(1)];
            candidates.retain(|x| *x < v);
            candidates.dedup();
            for x in candidates {
                if budget == 0 {
                    return (best, message);
                }
                budget -= 1;
                let mut trial = best;
                match field {
                    0 => trial.msg_len = x,
                    1 => trial.ad_len = x,
                    2 => trial.msg_off = x,
                    _ => trial.ad_off = x,
                }
                if let Err(m) = check(&trial) {
                    best = trial;
                    message = m;
                    improved = true;
                    break;
                }
            }
        }
        if !improved {
            return (best, message);
        }
    }
}
