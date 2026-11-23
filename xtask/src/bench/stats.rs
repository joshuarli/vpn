pub const RESAMPLES: usize = 10_000;

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

pub fn fnv(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

pub fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n == 0 {
        f64::NAN
    } else if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

pub fn spread(xs: &[f64]) -> f64 {
    let lo = xs.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if xs.is_empty() { 0.0 } else { hi - lo }
}

pub fn stdev(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = mean(xs);
    (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (xs.len() - 1) as f64).sqrt()
}

pub struct Interval {
    pub mean: f64,
    pub lo: f64,
    pub hi: f64,
}

pub fn bootstrap_mean(xs: &[f64], seed: u64) -> Interval {
    let m = mean(xs);
    let mut rng = Rng::new(seed);
    let mut means = Vec::with_capacity(RESAMPLES);
    for _ in 0..RESAMPLES {
        let mut sum = 0.0;
        for _ in 0..xs.len() {
            sum += xs[rng.below(xs.len())];
        }
        means.push(sum / xs.len() as f64);
    }
    means.sort_by(|a, b| a.total_cmp(b));
    let pick = |q: f64| means[((RESAMPLES - 1) as f64 * q).round() as usize];
    Interval { mean: m, lo: pick(0.025), hi: pick(0.975) }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Faster,
    WithinMargin,
    Regression,
    Inconclusive,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Faster => "FASTER",
            Verdict::WithinMargin => "WITHIN MARGIN",
            Verdict::Regression => "REGRESSION",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

pub fn verdict(lo: f64, hi: f64, band: f64) -> Verdict {
    if lo > 0.0 {
        Verdict::Faster
    } else if lo >= -band {
        Verdict::WithinMargin
    } else if hi < -band {
        Verdict::Regression
    } else {
        Verdict::Inconclusive
    }
}
