use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use twice::crypto::HiAeCipher;
use twice::os;
use twice::proto::{Codec, Header, KEY_LEN, KeyMode, ServerRx};
use twice::reorder::{Delivery, Diag, MAX_PACKET_LEN, Reorder, Sink, Timespec, WINDOW_SIZE};

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

struct Counting;

fn note(bytes: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to `System` unchanged after bumping the counters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn status_kb(field: &str) -> i64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else { return -1 };
    text.lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1)
}

#[derive(Default)]
struct Counts {
    packets: u64,
    bytes: u64,
}

impl Sink for Counts {
    fn deliver(&mut self, _kind: Delivery, packet: &[u8]) {
        self.bytes += packet.len() as u64;
        self.packets += 1;
    }

    fn diag(&mut self, diag: &Diag) {
        os::err_display(diag);
    }
}

type Trace = Vec<(u64, u64)>;

fn gen_in_order(trace: &mut Trace, n: usize) {
    for i in 0..n {
        trace.push((7, 1 + i as u64));
    }
}

fn gen_sparse(trace: &mut Trace, n: usize, seed: &mut u64) {
    let mut base = 1u64;
    while trace.len() + 8 <= n {
        let mut order = [0u64, 1, 2, 3, 4, 5, 6, 7];
        if splitmix(seed) % 4 == 0 {
            let k = (splitmix(seed) % 7) as usize;
            order.swap(k, k + 1);
        }
        for o in order {
            trace.push((7, base + o));
        }
        base += 8;
    }
}

fn gen_near_full(trace: &mut Trace, n: usize) {
    let w = WINDOW_SIZE as u64;
    let mut k = 1u64;
    while trace.len() + WINDOW_SIZE <= n {
        for i in 1..w {
            trace.push((7, k + i));
        }
        trace.push((7, k));
        k += w;
    }
}

fn gen_gaps(trace: &mut Trace, n: usize, seed: &mut u64) {
    let mut k = 1u64;
    loop {
        let depth = 1 + splitmix(seed) % 64;
        if trace.len() as u64 + depth + 1 > n as u64 {
            break;
        }
        for i in 1..=depth {
            trace.push((7, k + i));
        }
        trace.push((7, k));
        k += depth + 1;
    }
}

fn gen_resets(trace: &mut Trace, n: usize) {
    let (mut rv, mut c) = (7u64, 1u64);
    for i in 0..n {
        if i % 64 == 0 && i != 0 {
            rv += 1;
            c = 1;
        }
        trace.push((rv, c));
        c += 1;
    }
}

fn fail(message: &str, code: i32) -> ! {
    println!("{{\"error\":\"{message}\"}}");
    std::process::exit(code);
}

fn main() {
    let mut scenario = String::from("in_order");
    let (mut packets, mut payload, mut reps, mut seed) = (200000usize, 1400usize, 1usize, 1u64);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i + 1 < args.len() {
        let v = &args[i + 1];
        match args[i].as_str() {
            "--scenario" => scenario = v.clone(),
            "--packets" => packets = v.parse().expect("packets"),
            "--reps" => reps = v.parse().expect("reps"),
            "--payload" => payload = v.parse().expect("payload"),
            "--seed" => seed = v.parse().expect("seed"),
            _ => {}
        }
        i += 2;
    }
    if payload > MAX_PACKET_LEN {
        std::process::exit(2);
    }
    // SAFETY: plain libc calls on constant arguments; fd 2 is replaced by /dev/null so
    // diagnostics from the reorder sink cost a write but print nothing.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if null < 0 || libc::dup2(null, 2) < 0 {
            std::process::exit(2);
        }
    }

    let mut trace: Trace = Vec::with_capacity(packets + 2 * WINDOW_SIZE + 16);
    let mut gseed = seed;
    let timeout_mode = scenario == "timeout_drain";
    let keyed = scenario.starts_with("full_packet");
    match scenario.as_str() {
        "in_order" | "full_packet_in_order" => gen_in_order(&mut trace, packets),
        "sparse_reorder" | "full_packet_sparse" => gen_sparse(&mut trace, packets, &mut gseed),
        "near_full_window" => gen_near_full(&mut trace, packets),
        "repeated_gaps" | "large_payload" => gen_gaps(&mut trace, packets, &mut gseed),
        "repeated_resets" => gen_resets(&mut trace, packets),
        "timeout_drain" => {}
        other => fail(&format!("unknown scenario {other}"), 2),
    }

    let span = trace.iter().map(|t| t.1).max().unwrap_or(0);
    let resets = scenario == "repeated_resets";
    let mut pseed = seed + 99;
    let data: Vec<u8> = (0..MAX_PACKET_LEN).map(|_| splitmix(&mut pseed) as u8).collect();
    let mut key = [0u8; KEY_LEN];
    for b in key.iter_mut() {
        *b = splitmix(&mut pseed) as u8;
    }
    let mut frame = vec![0u8; twice::proto::MAX_DATAGRAM_LEN];
    let mut scratch = vec![0u8; MAX_PACKET_LEN];
    let codec = Codec::new(HiAeCipher::new(key).expect("cpu supported"), KeyMode::Keyed);

    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let mut reorder = Reorder::new(Timespec::default());
    COUNTING.store(false, Ordering::Relaxed);
    let state_bytes = ALLOC_BYTES.load(Ordering::Relaxed) as usize + std::mem::size_of::<Reorder>();

    let rss_before = status_kb("VmRSS:");
    let vsz_before = status_kb("VmSize:");
    let mut sink = Counts::default();
    let (mut elapsed, mut counted) = (0u64, 0u64);
    let (mut alloc_count, mut alloc_bytes) = (0u64, 0u64);

    for pass in 0..2 {
        reorder.reset();
        // A zero-counter packet from peer 7 leaves expected_counter 1 with the peer initialised,
        // the state the C bench sets directly.
        reorder.process(Timespec::default(), 7, 0, &data[..1], &mut sink);
        sink = Counts::default();
        if pass == 1 {
            ALLOC_COUNT.store(0, Ordering::Relaxed);
            ALLOC_BYTES.store(0, Ordering::Relaxed);
            COUNTING.store(true, Ordering::Relaxed);
        }
        let nreps = if pass == 1 { reps } else { 1 };
        let mut t_acc = 0u64;
        if timeout_mode {
            let cycles = packets / 512 * nreps;
            let aged = Timespec::default();
            for _ in 0..cycles {
                let t1 = Instant::now();
                let k = reorder.expected_counter();
                for i in 1..=512u64 {
                    black_box(os::monotonic());
                    reorder.process(aged, 7, k + i, &data[..payload], &mut sink);
                }
                t_acc += t1.elapsed().as_nanos() as u64;
                let t1 = Instant::now();
                reorder.check_timeouts(os::monotonic(), &mut sink);
                t_acc += t1.elapsed().as_nanos() as u64;
            }
            counted = cycles as u64 * 512;
        } else if keyed {
            let t1 = Instant::now();
            for r in 0..nreps as u64 {
                for &(rv, ctr) in &trace {
                    let header = Header { random: rv, counter: ctr + r * span };
                    let n = codec.seal(&header, &data[..payload], &mut frame);
                    match codec.server_receive(&frame[..n], &mut scratch) {
                        ServerRx::Accepted(a) => {
                            reorder.process(os::monotonic(), a.header.random, a.header.counter, a.payload, &mut sink);
                        }
                        _ => fail("decrypt failed", 1),
                    }
                }
            }
            t_acc = t1.elapsed().as_nanos() as u64;
            counted = (trace.len() * nreps) as u64;
        } else {
            let t1 = Instant::now();
            for r in 0..nreps as u64 {
                let (rv_add, ctr_add) = if resets { (r * 1000, 0) } else { (0, r * span) };
                for &(rv, ctr) in &trace {
                    reorder.process(os::monotonic(), rv + rv_add, ctr + ctr_add, &data[..payload], &mut sink);
                }
            }
            t_acc = t1.elapsed().as_nanos() as u64;
            counted = (trace.len() * nreps) as u64;
        }
        if pass == 1 {
            COUNTING.store(false, Ordering::Relaxed);
            elapsed = t_acc;
            alloc_count = ALLOC_COUNT.load(Ordering::Relaxed);
            alloc_bytes = ALLOC_BYTES.load(Ordering::Relaxed);
        }
    }
    let rss_after = status_kb("VmRSS:");
    let hwm = status_kb("VmHWM:");
    println!(
        "{{\"tool\":\"packet_bench\",\"lang\":\"rust\",\"scenario\":\"{}\",\"packets\":{},\"payload\":{},\"elapsed_ns\":{},\"ns_per_packet\":{:.4},\"delivered\":{},\"delivered_bytes\":{},\"alloc_count\":{},\"alloc_bytes\":{},\"vmsize_kb_before\":{},\"rss_kb_before\":{},\"rss_kb_after\":{},\"hwm_kb\":{},\"retained_kb\":{},\"state_bytes\":{},\"window_slots\":{},\"seed\":{}}}",
        scenario,
        counted,
        payload,
        elapsed,
        elapsed as f64 / counted as f64,
        sink.packets,
        sink.bytes,
        alloc_count,
        alloc_bytes,
        vsz_before,
        rss_before,
        rss_after,
        hwm,
        rss_after - rss_before,
        state_bytes,
        WINDOW_SIZE,
        seed
    );
}
