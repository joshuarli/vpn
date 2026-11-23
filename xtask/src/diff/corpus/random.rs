use super::spec::*;
use serde_json::json;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

const RANDOMS: [&str; 5] = [RA, RB, "c1c2c3c4c5c6c7c8", "0000000000000001", "d1d2d3d4d5d6d7d8"];
const FIRST_COUNTERS: [u64; 8] = [1, 1, 1, 0, 5, 1000, u64::MAX - 6, 1 << 40];

fn step_delay(rng: &mut Rng) -> u64 {
    match rng.below(100) {
        0..=69 => rng.range(1, 20),
        70..=84 => rng.range(21, 120),
        85..=94 => rng.range(1900, 2150),
        _ => rng.range(2500, 5000),
    }
}

pub fn trace(seed: u64, index: u64) -> Spec {
    let mut rng = Rng(seed.wrapping_mul(0x2545F4914F6CDD1D).wrapping_add(index));
    let name = format!("gen_s{seed}_{index:03}");
    let client = rng.chance(35);
    let keyed = rng.chance(70);
    let mut s = match (client, keyed) {
        (false, true) => Spec::server(&name),
        (false, false) => Spec::server_nokey(&name),
        (true, true) => Spec::client(&name),
        (true, false) => Spec::client_nokey(&name),
    };
    let home = s.peer().to_owned();
    let alt_peers = ["10.9.0.3:2000", "[2001:db8::9]:2002", "10.9.0.2:41195"];
    let mut random_idx = 0usize;
    let mut previous_random = RANDOMS[1];
    let mut next = *rng.pick(&FIRST_COUNTERS);
    let mut sent: Vec<u64> = Vec::new();
    let mut t = rng.range(0, 200);
    let events = rng.range(12, 60);
    let mut tun_in = 0;
    for _ in 0..events {
        t += step_delay(&mut rng);
        let random = RANDOMS[random_idx];
        match rng.below(100) {
            0..=34 => {
                s = s.udp_r(t, random, next);
                sent.push(next);
                next = next.wrapping_add(1);
            }
            35..=46 => {
                next = next.wrapping_add(rng.range(1, 4));
                s = s.udp_r(t, random, next);
                sent.push(next);
                next = next.wrapping_add(1);
            }
            47..=56 => {
                let lo = sent.len().saturating_sub(12);
                if sent.is_empty() {
                    continue;
                }
                let c = sent[lo + rng.below((sent.len() - lo) as u64) as usize].wrapping_sub(rng.below(3));
                s = s.udp_r(t, random, c);
            }
            57..=62 => {
                let c = next.wrapping_add(rng.range(1020, 1030));
                s = s.udp_r(t, random, c);
                next = c.wrapping_add(1);
                sent.push(c);
            }
            63..=66 => {
                previous_random = random;
                random_idx = (random_idx + 1) % RANDOMS.len();
                next = rng.range(0, 6);
                s = s.udp_r(t, RANDOMS[random_idx], next);
                next += 1;
                sent.clear();
            }
            67..=69 => {
                let c = sent.last().copied().unwrap_or(1);
                s = s.udp_r(t, previous_random, c);
            }
            70..=75 => {
                let auth = match rng.below(4) {
                    0 => "bad_tag".to_owned(),
                    1 => format!("flip:{}", rng.range(0, 35)),
                    2 => format!("truncate:{}", rng.range(14, 40)),
                    _ => "flip:20".to_owned(),
                };
                s = s.udp_full(t, None, random, next, &pl(next), &auth);
            }
            76..=78 => {
                let n = rng.range(0, 40) as usize;
                s = s.raw(t, &pattern(n, rng.below(256) as u8));
            }
            79..=80 => {
                let n = rng.range(0, 60) as usize;
                s = s.raw(t, &format!("{}{}", "ff".repeat(16), pattern(n, 7)));
            }
            81..=90 => {
                let size = *rng.pick(&[20usize, 1, 100, 1000, 1481, 1482, 1483, 1600]);
                tun_in += 1;
                s = s.tun(t, &pattern(size, tun_in as u8));
            }
            91..=93 if !client => {
                let from = rng.pick(&alt_peers).to_string();
                s = s.udp_full(t, Some(&from), random, next, &pl(next), "valid");
                sent.push(next);
                next = next.wrapping_add(1);
            }
            94..=95 => {
                s = s.perr(t, "udp", &["POLLERR"]);
            }
            96..=97 => {
                let size = rng.range(0, 3000) as usize;
                s = s.udp_full(t, Some(&home), random, next, &pattern(size, 3), "valid");
                sent.push(next);
                next = next.wrapping_add(1);
            }
            _ => {
                s = s.tun(t, &pl(1));
            }
        }
    }
    if rng.chance(15) {
        s = s.err(rule_err("write", Some("tun"), rng.range(1, 6) as u32, 1, *rng.pick(&["EIO", "EAGAIN", "EINTR", "ENOSPC"])));
    }
    if rng.chance(10) {
        let call = if client { "writev" } else { "sendmsg" };
        s = s.err(rule_err(call, Some("udp"), rng.range(1, 5) as u32, 1, *rng.pick(&["EAGAIN", "ENOBUFS", "EPERM"])));
    }
    if client && rng.chance(10) {
        s = s.err(rule_err("connect", Some("udp"), 2, rng.range(1, 3) as u32, "ECONNREFUSED"));
    }
    if rng.chance(8) {
        s = s.err(rule_short("write", "tun", rng.range(1, 5) as u32, 1, rng.range(0, 19) as i64));
    }
    s.set("seed", json!(seed * 1000 + index)).end(t + 3500)
}

pub fn traces(seed: u64, count: u64) -> Vec<Spec> {
    (0..count).map(|i| trace(seed, i)).collect()
}
