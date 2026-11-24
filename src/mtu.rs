use std::collections::VecDeque;

use crate::proto::{HEADER_LEN, TAG_LEN};

pub const DEFAULT_MTU: i32 = 1420;
pub const MIN_ARG_MTU: i32 = 68;
pub const MAX_ARG_MTU: i32 = 9000;
pub const PROBE_MIN: i32 = 576;
pub const PROBE_MAX: i32 = 9000;
pub const PROBE_TIMEOUT_MS: i32 = 500;
pub const PROBE_RETRIES: u32 = 2;
pub const OVERHEAD: i32 = 46;
const MAC_OVERHEAD: i32 = TAG_LEN as i32;
const DATAGRAM_OVERHEAD: usize = 46 + TAG_LEN;
/// Largest probe datagram discovery sends: a `PROBE_MAX` path MTU minus IP/UDP overhead. The
/// server echoes nothing larger, which bounds what it reflects.
pub const MAX_PROBE_DATAGRAM_LEN: usize =
    (PROBE_MAX - OVERHEAD - MAC_OVERHEAD) as usize + HEADER_LEN + TAG_LEN;

/// Interface MTU for a configured TUN MTU: the authentication tag is always subtracted.
pub const fn effective_tun_mtu(base_mtu: i32) -> i32 {
    base_mtu.wrapping_sub(MAC_OVERHEAD)
}

pub const OVERSIZED_PACKET_PREFIX: &str = "Dropping oversized packet";

/// True when a TUN read of `packet_len` bytes exceeds `tun_mtu + 62` and must be dropped.
pub fn exceeds_safe_size(packet_len: usize, tun_mtu: i32) -> bool {
    packet_len > (tun_mtu as isize as usize).wrapping_add(DATAGRAM_OVERHEAD)
}

pub fn oversized_message(packet_len: usize) -> String {
    format!("{OVERSIZED_PACKET_PREFIX} ({packet_len} bytes)\n")
}

pub fn mtu_banner(tun_mtu: i32) -> String {
    format!(
        "MTU: {} bytes (effective: {} bytes, with authentication)\n",
        tun_mtu,
        effective_tun_mtu(tun_mtu)
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adopted {
    pub tun_mtu: i32,
    pub effective: i32,
    pub message: String,
}

/// Decision after discovery finishes: adopt `discovered` when positive and different from the
/// current TUN MTU, then set the interface to `effective`.
pub fn adopt_discovered(current_tun_mtu: i32, discovered: i32) -> Option<Adopted> {
    if discovered > 0 && discovered != current_tun_mtu {
        let effective = effective_tun_mtu(discovered);
        Some(Adopted {
            tun_mtu: discovered,
            effective,
            message: format!(
                "Setting TUN MTU to discovered value: {discovered} bytes (effective: {effective} bytes, with authentication)\n"
            ),
        })
    } else {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Write to stdout; flush it only when `flush` is set.
    Print { text: String, flush: bool },
    /// Send one probe whose payload is `data_len` bytes, then report `sent`.
    SendProbe { data_len: usize },
    /// Poll the UDP socket for readability for `timeout_ms`; when readable, receive exactly one
    /// datagram and report `replied` with whether it is a valid probe reply of the size being
    /// tested. A poll timeout or error reports `replied(false)`.
    AwaitReply { timeout_ms: i32 },
    /// Discovery finished with this TUN MTU.
    Done { tun_mtu: i32 },
}

/// Client MTU discovery as a sans-io state machine. Call `step` for the next effect, perform
/// it, and feed `sent` or `replied` after `SendProbe` or `AwaitReply`.
#[derive(Debug)]
pub struct Discovery {
    min: i32,
    max: i32,
    best: i32,
    test_mtu: i32,
    retry: u32,
    probe_len: i32,
    queue: VecDeque<Effect>,
}

impl Discovery {
    pub fn new(is_server: bool) -> Discovery {
        let mut d = Discovery {
            min: PROBE_MIN,
            max: PROBE_MAX,
            best: PROBE_MIN,
            test_mtu: 0,
            retry: 0,
            probe_len: 0,
            queue: VecDeque::new(),
        };
        if is_server {
            d.queue.push_back(Effect::Done { tun_mtu: DEFAULT_MTU });
            return d;
        }
        d.print("Starting MTU discovery...\n", false);
        d.begin_size();
        d
    }

    pub fn step(&mut self) -> Effect {
        self.queue.pop_front().expect("discovery driven past completion")
    }

    pub fn sent(&mut self, ok: bool) {
        if ok {
            self.queue.push_back(Effect::AwaitReply { timeout_ms: PROBE_TIMEOUT_MS });
        } else {
            self.attempt_failed();
        }
    }

    pub fn replied(&mut self, valid: bool) {
        if valid {
            self.size_resolved(true);
        } else {
            self.attempt_failed();
        }
    }

    fn print(&mut self, text: &str, flush: bool) {
        self.queue.push_back(Effect::Print { text: text.to_string(), flush });
    }

    fn begin_size(&mut self) {
        if self.min > self.max {
            self.finish();
            return;
        }
        self.test_mtu = (self.min + self.max) / 2;
        let text = format!("Testing MTU {}... ", self.test_mtu);
        self.print(&text, true);
        self.probe_len = self.test_mtu - OVERHEAD - MAC_OVERHEAD;
        self.retry = 0;
        if self.probe_len > 0 {
            self.queue.push_back(Effect::SendProbe { data_len: self.probe_len as usize });
        } else {
            self.size_resolved(false);
        }
    }

    fn attempt_failed(&mut self) {
        self.retry += 1;
        if self.retry < PROBE_RETRIES {
            self.queue.push_back(Effect::SendProbe { data_len: self.probe_len as usize });
        } else {
            self.size_resolved(false);
        }
    }

    fn size_resolved(&mut self, ok: bool) {
        if ok {
            self.print("OK\n", false);
            self.best = self.test_mtu;
            self.min = self.test_mtu + 1;
        } else {
            self.print("Failed\n", false);
            self.max = self.test_mtu - 1;
        }
        self.begin_size();
    }

    fn finish(&mut self) {
        let mut tun_mtu = self.best - OVERHEAD - MAC_OVERHEAD;
        if tun_mtu < PROBE_MIN {
            tun_mtu = PROBE_MIN;
        }
        let text = format!("MTU discovery complete: {} bytes (TUN MTU: {})\n", self.best, tun_mtu);
        self.print(&text, false);
        self.queue.push_back(Effect::Done { tun_mtu });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Run {
        stdout: String,
        probes: Vec<usize>,
        awaits: usize,
        tun_mtu: i32,
        flushes: usize,
    }

    /// `oracle(data_len)` decides whether a probe of that payload size is answered.
    fn drive(mut d: Discovery, mut sent_ok: impl FnMut(usize) -> bool, mut oracle: impl FnMut(usize) -> bool) -> Run {
        let mut run = Run { stdout: String::new(), probes: vec![], awaits: 0, tun_mtu: 0, flushes: 0 };
        let mut last = 0;
        loop {
            match d.step() {
                Effect::Print { text, flush } => {
                    run.stdout.push_str(&text);
                    run.flushes += flush as usize;
                }
                Effect::SendProbe { data_len } => {
                    run.probes.push(data_len);
                    last = data_len;
                    d.sent(sent_ok(data_len));
                }
                Effect::AwaitReply { timeout_ms } => {
                    assert_eq!(timeout_ms, 500);
                    run.awaits += 1;
                    d.replied(oracle(last));
                }
                Effect::Done { tun_mtu } => {
                    run.tun_mtu = tun_mtu;
                    return run;
                }
            }
        }
    }

    fn path_limit(limit_mtu: i32) -> impl FnMut(usize) -> bool {
        move |len| len as i32 + 62 <= limit_mtu
    }

    #[test]
    fn full_path_to_9000_yields_tun_mtu_8938_and_interface_8922() {
        let run = drive(Discovery::new(false), |_| true, path_limit(9000));
        assert_eq!(run.tun_mtu, 8938);
        assert_eq!(effective_tun_mtu(run.tun_mtu), 8922);
        assert!(run.stdout.ends_with("MTU discovery complete: 9000 bytes (TUN MTU: 8938)\n"));
        assert!(run.stdout.starts_with("Starting MTU discovery...\nTesting MTU 4788... OK\n"));
    }

    #[test]
    fn no_reply_at_all_yields_576_after_two_tries_per_size() {
        let run = drive(Discovery::new(false), |_| true, |_| false);
        assert_eq!(run.tun_mtu, 576);
        assert!(run.stdout.ends_with("MTU discovery complete: 576 bytes (TUN MTU: 576)\n"));
        assert_eq!(run.probes.len(), run.awaits);
        assert_eq!(run.probes.len() % 2, 0);
        assert_eq!(run.stdout.matches("Failed\n").count(), run.probes.len() / 2);
    }

    #[test]
    fn failing_path_tests_the_expected_binary_search_sequence() {
        let run = drive(Discovery::new(false), |_| true, |_| false);
        let tested: Vec<i32> = run.probes.iter().step_by(2).map(|l| *l as i32 + 62).collect();
        assert_eq!(tested, [4788, 2681, 1628, 1101, 838, 706, 640, 607, 591, 583, 579, 577, 576]);
    }

    #[test]
    fn path_limit_of_1500_is_found_exactly() {
        let run = drive(Discovery::new(false), |_| true, path_limit(1500));
        assert!(run.stdout.ends_with("MTU discovery complete: 1500 bytes (TUN MTU: 1438)\n"));
        assert_eq!(run.tun_mtu, 1438);
    }

    #[test]
    fn path_limit_just_above_minimum_finds_it_and_at_minimum_clamps_tun_mtu() {
        let run = drive(Discovery::new(false), |_| true, path_limit(700));
        assert_eq!(run.tun_mtu, 638);
        let run = drive(Discovery::new(false), |_| true, path_limit(576));
        assert!(run.stdout.ends_with("MTU discovery complete: 576 bytes (TUN MTU: 576)\n"));
        assert_eq!(run.tun_mtu, 576);
    }

    #[test]
    fn unanswered_probe_is_retried_once_at_the_same_size() {
        let run = drive(Discovery::new(false), |_| true, path_limit(1000));
        assert_eq!(run.probes[0], run.probes[1]);
        assert!(run.stdout.contains("Testing MTU 4788... Failed\n"));
        assert_eq!(run.tun_mtu, 938);
    }

    #[test]
    fn answered_probe_is_not_retried() {
        let run = drive(Discovery::new(false), |_| true, path_limit(9000));
        assert_eq!(run.probes.len(), run.awaits);
        assert_ne!(run.probes[0], run.probes[1]);
    }

    #[test]
    fn send_failure_consumes_a_try_without_waiting() {
        let run = drive(Discovery::new(false), |_| false, |_| true);
        assert_eq!(run.awaits, 0);
        assert_eq!(run.tun_mtu, 576);
        assert_eq!(run.probes.len(), 26);
    }

    #[test]
    fn one_failed_send_still_allows_the_retry_to_succeed() {
        let mut first = true;
        let run = drive(
            Discovery::new(false),
            |_| !std::mem::replace(&mut first, false),
            path_limit(9000),
        );
        assert_eq!(run.tun_mtu, 8938);
        assert_eq!(run.probes[0], run.probes[1]);
    }

    #[test]
    fn announcement_lines_are_flushed_only_for_each_tested_size() {
        let run = drive(Discovery::new(false), |_| true, path_limit(1500));
        assert_eq!(run.flushes, run.stdout.matches("Testing MTU ").count());
        assert!(run.stdout.starts_with("Starting MTU discovery...\nTesting MTU 4788... Failed\n"));
    }

    #[test]
    fn server_returns_default_mtu_without_output_or_probes() {
        let run = drive(Discovery::new(true), |_| true, |_| true);
        assert_eq!(run.tun_mtu, 1420);
        assert!(run.stdout.is_empty());
        assert!(run.probes.is_empty());
    }

    #[test]
    fn adoption_requires_a_positive_changed_value() {
        assert_eq!(adopt_discovered(1420, 1420), None);
        assert_eq!(adopt_discovered(1420, 0), None);
        let a = adopt_discovered(1420, 8938).unwrap();
        assert_eq!((a.tun_mtu, a.effective), (8938, 8922));
        assert_eq!(
            a.message,
            "Setting TUN MTU to discovered value: 8938 bytes (effective: 8922 bytes, with authentication)\n"
        );
        assert_eq!(adopt_discovered(1380, 576).unwrap().effective, 560);
    }

    #[test]
    fn interface_mtu_always_subtracts_the_tag() {
        assert_eq!(effective_tun_mtu(1420), 1404);
        assert_eq!(effective_tun_mtu(68), 52);
        assert_eq!(mtu_banner(1420), "MTU: 1420 bytes (effective: 1404 bytes, with authentication)\n");
    }

    #[test]
    fn oversize_threshold_is_tun_mtu_plus_62() {
        assert!(!exceeds_safe_size(1420 + 62, 1420));
        assert!(exceeds_safe_size(1420 + 63, 1420));
        assert!(exceeds_safe_size(131, 68));
        assert!(!exceeds_safe_size(130, 68));
        assert_eq!(oversized_message(1500), "Dropping oversized packet (1500 bytes)\n");
    }
}
