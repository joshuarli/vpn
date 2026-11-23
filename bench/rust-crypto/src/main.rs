use graviola::aead::HiAe;
use std::hint::black_box;
use std::time::Instant;

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn main() {
    let mut op = String::new();
    let (mut size, mut ms, mut warm_ms, mut seed) = (1420usize, 100u64, 50u64, 1u64);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--op" => op = args[i + 1].clone(),
            "--size" => size = args[i + 1].parse().expect("size"),
            "--ms" => ms = args[i + 1].parse().expect("ms"),
            "--warmup-ms" => warm_ms = args[i + 1].parse().expect("warmup-ms"),
            "--seed" => seed = args[i + 1].parse().expect("seed"),
            _ => {}
        }
        i += 2;
    }
    if !["encrypt", "decrypt", "decrypt_fail", "mac", "mac_verify"].contains(&op.as_str()) {
        eprintln!("usage: twice-crypto-bench --op encrypt|decrypt|decrypt_fail|mac|mac_verify --size N [--ms M] [--warmup-ms W] [--seed S]");
        std::process::exit(2);
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 16];
    for b in key.iter_mut() {
        *b = splitmix(&mut seed) as u8;
    }
    for b in nonce.iter_mut() {
        *b = splitmix(&mut seed) as u8;
    }
    let mut src = vec![0u8; size];
    for b in src.iter_mut() {
        *b = splitmix(&mut seed) as u8;
    }
    let cipher = HiAe::new(key);
    let mut ct = src.clone();
    let mut good_tag = [0u8; 16];
    cipher.encrypt(&nonce, &[], &mut ct, &mut good_tag);
    let mut bad_tag = good_tag;
    bad_tag[0] ^= 1;
    let mut work = vec![0u8; size];

    let batch = 1 + 65536 / size.max(1);
    let (mut ctr, mut sink, mut ops) = (0u64, 0u64, 0u64);
    let start = Instant::now();
    let warm_end = warm_ms as f64 * 1e6;
    let mut measure_start: Option<Instant> = None;
    let elapsed_ns;
    loop {
        let now = Instant::now();
        match measure_start {
            None => {
                if now.duration_since(start).as_nanos() as f64 >= warm_end {
                    measure_start = Some(now);
                    ops = 0;
                }
            }
            Some(t0) => {
                let e = now.duration_since(t0).as_nanos() as u64;
                if e >= ms * 1_000_000 {
                    elapsed_ns = e;
                    break;
                }
            }
        }
        for _ in 0..batch {
            match op.as_str() {
                "encrypt" => {
                    nonce[..8].copy_from_slice(&ctr.to_le_bytes());
                    ctr += 1;
                    work.copy_from_slice(&src);
                    let mut tag = [0u8; 16];
                    cipher.encrypt(&nonce, &[], black_box(&mut work), &mut tag);
                    sink += u64::from(tag[0]);
                }
                "decrypt" => {
                    work.copy_from_slice(&ct);
                    sink += u64::from(cipher.decrypt(&nonce, &[], black_box(&mut work), &good_tag).is_err());
                }
                "decrypt_fail" => {
                    work.copy_from_slice(&ct);
                    sink += u64::from(cipher.decrypt(&nonce, &[], black_box(&mut work), &bad_tag).is_err());
                }
                "mac" => {
                    nonce[..8].copy_from_slice(&ctr.to_le_bytes());
                    ctr += 1;
                    sink += u64::from(cipher.mac(&nonce, black_box(&src))[0]);
                }
                _ => {
                    let tag = cipher.mac(&nonce, black_box(&src));
                    sink += u64::from(cipher.verify_mac(&nonce, black_box(&src), &tag).is_err());
                }
            }
        }
        ops += batch as u64;
    }
    let ns_op = elapsed_ns as f64 / ops as f64;
    println!(
        "{{\"tool\":\"crypto_bench\",\"lang\":\"rust\",\"backend\":\"graviola HiAe automatic ({})\",\"op\":\"{}\",\"size\":{},\"ops\":{},\"elapsed_ns\":{},\"ns_per_op\":{:.4},\"mib_per_s\":{:.3},\"sink\":{}}}",
        std::env::consts::ARCH,
        op,
        size,
        ops,
        elapsed_ns,
        ns_op,
        size as f64 / ns_op * 1e9 / 1_048_576.0,
        sink
    );
}
