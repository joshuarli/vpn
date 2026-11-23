use std::fmt;

pub const WINDOW_SIZE: usize = 1024;
pub const TIMEOUT_MS: u64 = 2000;
pub const CHECK_INTERVAL_MS: u64 = 50;
pub const MAX_PACKET_LEN: usize = crate::proto::MAX_PACKET_LEN;

/// Monotonic clock reading with the same fields and arithmetic as the C `struct timespec`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

impl Timespec {
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Timespec { sec, nsec }
    }

    pub const fn from_millis(ms: u64) -> Self {
        Timespec { sec: (ms / 1000) as i64, nsec: ((ms % 1000) * 1_000_000) as i64 }
    }

    pub const fn millis(self) -> u64 {
        (self.sec as u64).wrapping_mul(1000).wrapping_add((self.nsec / 1_000_000) as u64)
    }

    /// Milliseconds from `earlier` to `self` computed as the event loop does: whole seconds
    /// times 1000 plus the truncated millisecond difference of the nanosecond fields.
    pub const fn since(self, earlier: Timespec) -> u64 {
        self.sec
            .wrapping_sub(earlier.sec)
            .wrapping_mul(1000)
            .wrapping_add(self.nsec.wrapping_sub(earlier.nsec) / 1_000_000) as u64
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub received: u64,
    pub duplicated: u64,
    pub reordered: u64,
    pub lost: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Immediate,
    Buffered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    Buffered,
    Dropped,
}

/// A diagnostic line; `Display` renders the exact stderr bytes including the trailing newline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Diag {
    PeerRestarted,
    TooFarAhead { expected: u64, got: u64 },
    SlotCollision { slot: usize, held: u64, wanted: u64 },
    TimeoutSkip { from: u64, to: u64 },
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Diag::PeerRestarted => {
                f.write_str("Random value mismatch - peer restarted. Resetting reorder state.\n")
            }
            Diag::TooFarAhead { expected, got } => writeln!(
                f,
                "Packet too far ahead: expected {expected}, got {got}. Advancing window."
            ),
            Diag::SlotCollision { slot, held, wanted } => writeln!(
                f,
                "Buffer slot collision: slot {slot} has counter {held}, trying to store {wanted}"
            ),
            Diag::TimeoutSkip { from, to } => writeln!(
                f,
                "Timeout: skipping from counter {from} to {to} (lost {} packets)",
                to.wrapping_sub(from)
            ),
        }
    }
}

/// Receives delivered packets, in delivery order, and diagnostics, in emission order.
pub trait Sink {
    fn deliver(&mut self, kind: Delivery, packet: &[u8]);
    fn diag(&mut self, diag: &Diag);
}

#[derive(Clone, Copy)]
struct Slot {
    occupied: bool,
    counter: u64,
    len: usize,
    timestamp: Timespec,
}

const EMPTY_SLOT: Slot = Slot { occupied: false, counter: 0, len: 0, timestamp: Timespec::new(0, 0) };

pub struct Reorder {
    expected_counter: u64,
    highest_processed: u64,
    random_value: u64,
    random_initialized: bool,
    window_base: u64,
    stats: Stats,
    slots: Box<[Slot]>,
    payloads: Box<[u8]>,
    last_check: Timespec,
}

impl Reorder {
    /// Allocates the full 1,024 by 65,536 byte payload store once; the pages are zeroed lazily.
    pub fn new(now: Timespec) -> Self {
        Reorder {
            expected_counter: 1,
            highest_processed: 0,
            random_value: 0,
            random_initialized: false,
            window_base: 1,
            stats: Stats::default(),
            slots: vec![EMPTY_SLOT; WINDOW_SIZE].into_boxed_slice(),
            payloads: vec![0u8; WINDOW_SIZE * MAX_PACKET_LEN].into_boxed_slice(),
            last_check: now,
        }
    }

    /// Reconnect reset: forgets the peer, buffered packets and statistics. The periodic check
    /// timestamp is kept.
    pub fn reset(&mut self) {
        self.expected_counter = 1;
        self.highest_processed = 0;
        self.random_value = 0;
        self.random_initialized = false;
        self.window_base = 1;
        self.stats = Stats::default();
        for slot in self.slots.iter_mut() {
            slot.occupied = false;
        }
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn expected_counter(&self) -> u64 {
        self.expected_counter
    }

    pub fn highest_processed(&self) -> u64 {
        self.highest_processed
    }

    pub fn window_base(&self) -> u64 {
        self.window_base
    }

    pub fn peer_random(&self) -> Option<u64> {
        self.random_initialized.then_some(self.random_value)
    }

    pub fn buffered_count(&self) -> usize {
        self.slots.iter().filter(|s| s.occupied).count()
    }

    pub fn last_check(&self) -> Timespec {
        self.last_check
    }

    /// `data` must not exceed `MAX_PACKET_LEN` bytes. `now` stamps the packet if it is buffered.
    pub fn process<S: Sink>(
        &mut self,
        now: Timespec,
        random: u64,
        counter: u64,
        data: &[u8],
        sink: &mut S,
    ) -> Outcome {
        self.stats.received += 1;

        if !self.random_initialized {
            self.random_value = random;
            self.random_initialized = true;
            self.expected_counter = counter;
            self.window_base = counter;
        }

        if random != self.random_value {
            sink.diag(&Diag::PeerRestarted);
            self.reset();
            self.random_value = random;
            self.random_initialized = true;
            self.expected_counter = counter;
            self.window_base = counter;
        }

        if counter < self.expected_counter {
            self.stats.duplicated += 1;
            return Outcome::Dropped;
        }

        if counter == self.expected_counter {
            self.expected_counter = self.expected_counter.wrapping_add(1);
            self.highest_processed = counter;
            sink.deliver(Delivery::Immediate, data);
            self.deliver_buffered(sink);
            self.window_base = self.expected_counter;
            return Outcome::Delivered;
        }

        if counter >= self.expected_counter.wrapping_add(WINDOW_SIZE as u64) {
            sink.diag(&Diag::TooFarAhead { expected: self.expected_counter, got: counter });
            self.reset();
            self.random_value = random;
            self.random_initialized = true;
            self.expected_counter = counter.wrapping_add(1);
            self.highest_processed = counter;
            sink.deliver(Delivery::Immediate, data);
            return Outcome::Delivered;
        }

        self.buffer(now, counter, data, sink)
    }

    fn buffer<S: Sink>(&mut self, now: Timespec, counter: u64, data: &[u8], sink: &mut S) -> Outcome {
        let index = (counter % WINDOW_SIZE as u64) as usize;
        let slot = &mut self.slots[index];
        if slot.occupied && slot.counter == counter {
            self.stats.duplicated += 1;
            return Outcome::Dropped;
        }
        if slot.occupied {
            sink.diag(&Diag::SlotCollision { slot: index, held: slot.counter, wanted: counter });
            return Outcome::Dropped;
        }
        slot.occupied = true;
        slot.counter = counter;
        slot.len = data.len();
        slot.timestamp = now;
        let base = index * MAX_PACKET_LEN;
        self.payloads[base..base + data.len()].copy_from_slice(data);
        self.stats.reordered += 1;
        Outcome::Buffered
    }

    fn deliver_buffered<S: Sink>(&mut self, sink: &mut S) -> usize {
        let mut delivered = 0;
        loop {
            let index = (self.expected_counter % WINDOW_SIZE as u64) as usize;
            let slot = self.slots[index];
            if !slot.occupied || slot.counter != self.expected_counter {
                break;
            }
            let base = index * MAX_PACKET_LEN;
            sink.deliver(Delivery::Buffered, &self.payloads[base..base + slot.len]);
            self.slots[index].occupied = false;
            self.expected_counter = self.expected_counter.wrapping_add(1);
            self.highest_processed = self.expected_counter.wrapping_sub(1);
            delivered += 1;
        }
        delivered
    }

    /// True when at least 50 ms have passed since the last periodic check.
    pub fn check_due(&self, now: Timespec) -> bool {
        now.since(self.last_check) >= CHECK_INTERVAL_MS
    }

    /// Runs the timeout scan if due and then records `now` as the last check. `scan_clock` is read
    /// after the due test, as the C loop reads the clock again inside the scan.
    pub fn tick<S: Sink>(
        &mut self,
        now: Timespec,
        scan_clock: impl FnOnce() -> Timespec,
        sink: &mut S,
    ) -> bool {
        if !self.check_due(now) {
            return false;
        }
        self.check_timeouts(scan_clock(), sink);
        self.last_check = now;
        true
    }

    /// Skips the gap in front of the lowest buffered packet once any buffered packet has waited
    /// strictly longer than 2,000 ms.
    pub fn check_timeouts<S: Sink>(&mut self, now: Timespec, sink: &mut S) {
        let now_ms = now.millis();
        let mut min_counter = 0u64;
        let mut have_min = false;
        let mut have_old = false;

        for slot in self.slots.iter() {
            if !slot.occupied {
                continue;
            }
            if !have_min || slot.counter < min_counter {
                min_counter = slot.counter;
                have_min = true;
            }
            if now_ms.wrapping_sub(slot.timestamp.millis()) > TIMEOUT_MS {
                have_old = true;
            }
        }

        if have_old && have_min && min_counter > self.expected_counter {
            sink.diag(&Diag::TimeoutSkip { from: self.expected_counter, to: min_counter });
            self.stats.lost = self.stats.lost.wrapping_add(min_counter - self.expected_counter);
            self.expected_counter = min_counter;
            self.window_base = min_counter;
            self.deliver_buffered(sink);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rec {
        delivered: Vec<(Delivery, u64)>,
        diags: Vec<String>,
    }

    impl Sink for Rec {
        fn deliver(&mut self, kind: Delivery, packet: &[u8]) {
            let n = u64::from_le_bytes(packet[..8].try_into().unwrap());
            self.delivered.push((kind, n));
        }
        fn diag(&mut self, diag: &Diag) {
            self.diags.push(diag.to_string());
        }
    }

    impl Rec {
        fn counters(&self) -> Vec<u64> {
            self.delivered.iter().map(|d| d.1).collect()
        }
    }

    const R: u64 = 0x1122_3344_5566_7788;

    fn pkt(counter: u64) -> [u8; 8] {
        counter.to_le_bytes()
    }

    fn at(ms: u64) -> Timespec {
        Timespec::from_millis(ms)
    }

    fn feed(r: &mut Reorder, rec: &mut Rec, now: u64, rv: u64, counter: u64) -> Outcome {
        r.process(at(now), rv, counter, &pkt(counter), rec)
    }

    fn fresh() -> (Reorder, Rec) {
        (Reorder::new(at(0)), Rec::default())
    }

    #[test]
    fn in_order_packets_are_delivered_immediately() {
        let (mut r, mut rec) = fresh();
        for c in 1..=5 {
            assert_eq!(feed(&mut r, &mut rec, 0, R, c), Outcome::Delivered);
        }
        assert_eq!(rec.counters(), [1, 2, 3, 4, 5]);
        assert!(rec.delivered.iter().all(|d| d.0 == Delivery::Immediate));
        assert_eq!(r.expected_counter(), 6);
        assert_eq!(r.highest_processed(), 5);
        assert_eq!(r.window_base(), 6);
        assert_eq!(r.stats(), Stats { received: 5, duplicated: 0, reordered: 0, lost: 0 });
        assert!(rec.diags.is_empty());
    }

    #[test]
    fn immediate_duplicate_is_dropped_and_counted() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        feed(&mut r, &mut rec, 0, R, 2);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 2), Outcome::Dropped);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 1), Outcome::Dropped);
        assert_eq!(rec.counters(), [1, 2]);
        assert_eq!(r.stats().duplicated, 2);
        assert_eq!(r.stats().received, 4);
    }

    #[test]
    fn buffered_duplicate_is_dropped_and_counted() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 3), Outcome::Buffered);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 3), Outcome::Dropped);
        assert_eq!(r.stats().duplicated, 1);
        assert_eq!(r.stats().reordered, 1);
        feed(&mut r, &mut rec, 0, R, 2);
        assert_eq!(rec.counters(), [1, 2, 3]);
        assert_eq!(rec.delivered[2].0, Delivery::Buffered);
    }

    #[test]
    fn gap_fill_releases_buffered_packets_in_order() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 3), Outcome::Buffered);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 4), Outcome::Buffered);
        assert_eq!(rec.counters(), [1]);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 2), Outcome::Delivered);
        assert_eq!(rec.counters(), [1, 2, 3, 4]);
        assert_eq!(r.expected_counter(), 5);
        assert_eq!(r.window_base(), 5);
        assert_eq!(r.buffered_count(), 0);
        assert_eq!(r.stats().reordered, 2);
    }

    #[test]
    fn reverse_burst_is_released_when_head_arrives() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        for c in (3..=100).rev() {
            assert_eq!(feed(&mut r, &mut rec, 0, R, c), Outcome::Buffered);
        }
        assert_eq!(rec.counters(), [1]);
        assert_eq!(r.buffered_count(), 98);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 2), Outcome::Delivered);
        assert_eq!(rec.counters(), (1..=100).collect::<Vec<_>>());
        assert_eq!(r.stats().reordered, 98);
    }

    #[test]
    fn reverse_burst_as_first_traffic_delivers_only_the_first_arrival() {
        let (mut r, mut rec) = fresh();
        for c in (2..=100).rev() {
            feed(&mut r, &mut rec, 0, R, c);
        }
        assert_eq!(rec.counters(), [100]);
        assert_eq!(r.expected_counter(), 101);
        assert_eq!(r.stats().duplicated, 98);
    }

    #[test]
    fn window_accepts_exactly_1023_ahead_and_jumps_at_1024() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        assert_eq!(r.expected_counter(), 2);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 2 + 1023), Outcome::Buffered);
        assert!(rec.diags.is_empty());
        assert_eq!(feed(&mut r, &mut rec, 0, R, 2 + 1024), Outcome::Delivered);
        assert_eq!(rec.diags, ["Packet too far ahead: expected 2, got 1026. Advancing window.\n"]);
        assert_eq!(rec.counters(), [1, 1026]);
    }

    #[test]
    fn jump_resets_state_statistics_and_buffer() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        feed(&mut r, &mut rec, 0, R, 5);
        feed(&mut r, &mut rec, 0, R, 6);
        feed(&mut r, &mut rec, 0, R, 5000);
        assert_eq!(rec.counters(), [1, 5000]);
        assert_eq!(r.buffered_count(), 0);
        assert_eq!(r.expected_counter(), 5001);
        assert_eq!(r.highest_processed(), 5000);
        assert_eq!(r.window_base(), 1);
        assert_eq!(r.stats(), Stats::default());
        assert_eq!(r.peer_random(), Some(R));
        assert_eq!(feed(&mut r, &mut rec, 0, R, 5001), Outcome::Delivered);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 5), Outcome::Dropped);
        assert_eq!(rec.counters(), [1, 5000, 5001]);
    }

    #[test]
    fn unexpected_first_counter_is_accepted_as_baseline() {
        let (mut r, mut rec) = fresh();
        assert_eq!(feed(&mut r, &mut rec, 0, R, 777), Outcome::Delivered);
        assert_eq!(r.expected_counter(), 778);
        assert_eq!(r.peer_random(), Some(R));
        assert_eq!(feed(&mut r, &mut rec, 0, R, 776), Outcome::Dropped);
        assert_eq!(rec.counters(), [777]);
        assert!(rec.diags.is_empty());
    }

    #[test]
    fn first_packet_with_counter_zero_is_delivered() {
        let (mut r, mut rec) = fresh();
        assert_eq!(feed(&mut r, &mut rec, 0, R, 0), Outcome::Delivered);
        assert_eq!(r.expected_counter(), 1);
        assert_eq!(rec.counters(), [0]);
    }

    #[test]
    fn peer_epoch_change_resets_and_accepts_new_counter() {
        let (mut r, mut rec) = fresh();
        for c in 1..=3 {
            feed(&mut r, &mut rec, 0, R, c);
        }
        feed(&mut r, &mut rec, 0, R, 10);
        assert_eq!(feed(&mut r, &mut rec, 0, R + 1, 500), Outcome::Delivered);
        assert_eq!(rec.diags, ["Random value mismatch - peer restarted. Resetting reorder state.\n"]);
        assert_eq!(rec.counters(), [1, 2, 3, 500]);
        assert_eq!(r.peer_random(), Some(R + 1));
        assert_eq!(r.expected_counter(), 501);
        assert_eq!(r.buffered_count(), 0);
        assert_eq!(r.stats(), Stats { received: 0, duplicated: 0, reordered: 0, lost: 0 });
    }

    #[test]
    fn epoch_change_to_counter_one_after_progress_is_delivered() {
        let (mut r, mut rec) = fresh();
        for c in 1..=50 {
            feed(&mut r, &mut rec, 0, R, c);
        }
        assert_eq!(feed(&mut r, &mut rec, 0, R ^ 1, 1), Outcome::Delivered);
        assert_eq!(rec.delivered.last(), Some(&(Delivery::Immediate, 1)));
        assert_eq!(feed(&mut r, &mut rec, 0, R ^ 1, 2), Outcome::Delivered);
    }

    #[test]
    fn old_epoch_packet_after_restart_resets_again() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        feed(&mut r, &mut rec, 0, R + 1, 1);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 2), Outcome::Delivered);
        assert_eq!(rec.diags.len(), 2);
        assert_eq!(r.peer_random(), Some(R));
    }

    #[test]
    fn near_wrap_in_order_counters_wrap_expected_to_zero() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, u64::MAX - 1);
        feed(&mut r, &mut rec, 0, R, u64::MAX);
        assert_eq!(r.expected_counter(), 0);
        assert_eq!(r.highest_processed(), u64::MAX);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 0), Outcome::Delivered);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 1), Outcome::Delivered);
        assert_eq!(rec.counters(), [u64::MAX - 1, u64::MAX, 0, 1]);
        assert_eq!(r.stats().duplicated, 0);
    }

    #[test]
    fn near_wrap_future_counter_is_treated_as_jump_when_window_end_wraps() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, u64::MAX - 10);
        assert_eq!(r.expected_counter(), u64::MAX - 9);
        assert_eq!(feed(&mut r, &mut rec, 0, R, u64::MAX - 5), Outcome::Delivered);
        assert_eq!(rec.diags.len(), 1);
        assert_eq!(r.expected_counter(), u64::MAX - 4);
        assert_eq!(r.buffered_count(), 0);
        assert_eq!(rec.counters(), [u64::MAX - 10, u64::MAX - 5]);
    }

    #[test]
    fn counter_wrapped_to_small_value_after_high_counter_counts_as_duplicate() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, u64::MAX - 1);
        assert_eq!(feed(&mut r, &mut rec, 0, R, 3), Outcome::Dropped);
        assert_eq!(r.stats().duplicated, 1);
        assert_eq!(rec.counters(), [u64::MAX - 1]);
    }

    #[test]
    fn jump_to_max_counter_wraps_expected_to_zero() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        assert_eq!(feed(&mut r, &mut rec, 0, R, u64::MAX), Outcome::Delivered);
        assert_eq!(r.expected_counter(), 0);
        assert_eq!(r.highest_processed(), u64::MAX);
    }

    #[test]
    fn slot_collision_drops_without_overwriting() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        r.slots[5] = Slot { occupied: true, counter: 5 + 1024, len: 8, timestamp: at(0) };
        r.payloads[5 * MAX_PACKET_LEN..5 * MAX_PACKET_LEN + 8].copy_from_slice(&pkt(5 + 1024));
        assert_eq!(feed(&mut r, &mut rec, 0, R, 5), Outcome::Dropped);
        assert_eq!(rec.diags, ["Buffer slot collision: slot 5 has counter 1029, trying to store 5\n"]);
        assert_eq!(r.slots[5].counter, 1029);
        assert_eq!(r.stats(), Stats { received: 2, duplicated: 0, reordered: 0, lost: 0 });
    }

    #[test]
    fn timeout_requires_strictly_more_than_2000_ms() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 1000, R, 1);
        feed(&mut r, &mut rec, 1000, R, 3);
        r.check_timeouts(at(3000), &mut rec);
        assert_eq!(rec.counters(), [1]);
        assert!(rec.diags.is_empty());
        r.check_timeouts(at(3001), &mut rec);
        assert_eq!(rec.counters(), [1, 3]);
        assert_eq!(rec.diags, ["Timeout: skipping from counter 2 to 3 (lost 1 packets)\n"]);
        assert_eq!(r.stats().lost, 1);
        assert_eq!(r.expected_counter(), 4);
        assert_eq!(r.window_base(), 3);
    }

    #[test]
    fn timeout_age_uses_truncated_milliseconds() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        r.process(Timespec::new(10, 999_999_999), R, 3, &pkt(3), &mut rec);
        r.check_timeouts(Timespec::new(12, 999_999_999), &mut rec);
        assert_eq!(rec.counters(), [1]);
        r.check_timeouts(Timespec::new(13, 0), &mut rec);
        assert_eq!(rec.counters(), [1, 3]);
    }

    #[test]
    fn timeout_skips_to_lowest_buffered_counter_even_if_only_another_is_old() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        feed(&mut r, &mut rec, 0, R, 10);
        feed(&mut r, &mut rec, 5000, R, 5);
        r.check_timeouts(at(5000), &mut rec);
        assert_eq!(rec.counters(), [1, 5]);
        assert_eq!(rec.diags, ["Timeout: skipping from counter 2 to 5 (lost 3 packets)\n"]);
        assert_eq!(r.expected_counter(), 6);
        assert_eq!(r.buffered_count(), 1);
    }

    #[test]
    fn timeout_does_nothing_without_a_gap_or_buffered_packets() {
        let (mut r, mut rec) = fresh();
        r.check_timeouts(at(100_000), &mut rec);
        feed(&mut r, &mut rec, 0, R, 1);
        r.check_timeouts(at(100_000), &mut rec);
        assert_eq!(rec.counters(), [1]);
        assert!(rec.diags.is_empty());
        assert_eq!(r.stats().lost, 0);
    }

    #[test]
    fn multiple_gaps_are_skipped_one_timeout_at_a_time() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        for c in [3, 4, 7, 8, 12] {
            feed(&mut r, &mut rec, 0, R, c);
        }
        r.check_timeouts(at(2001), &mut rec);
        assert_eq!(rec.counters(), [1, 3, 4]);
        r.check_timeouts(at(2002), &mut rec);
        assert_eq!(rec.counters(), [1, 3, 4, 7, 8]);
        r.check_timeouts(at(2003), &mut rec);
        assert_eq!(rec.counters(), [1, 3, 4, 7, 8, 12]);
        assert_eq!(
            rec.diags,
            [
                "Timeout: skipping from counter 2 to 3 (lost 1 packets)\n",
                "Timeout: skipping from counter 5 to 7 (lost 2 packets)\n",
                "Timeout: skipping from counter 9 to 12 (lost 3 packets)\n",
            ]
        );
        assert_eq!(r.stats().lost, 6);
        assert_eq!(r.expected_counter(), 13);
    }

    #[test]
    fn later_buffered_packet_gets_its_own_age_after_a_skip() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        feed(&mut r, &mut rec, 0, R, 3);
        feed(&mut r, &mut rec, 1500, R, 6);
        r.check_timeouts(at(2001), &mut rec);
        assert_eq!(rec.counters(), [1, 3]);
        r.check_timeouts(at(3500), &mut rec);
        assert_eq!(rec.counters(), [1, 3]);
        r.check_timeouts(at(3501), &mut rec);
        assert_eq!(rec.counters(), [1, 3, 6]);
    }

    #[test]
    fn periodic_check_runs_only_when_50_ms_have_elapsed() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        feed(&mut r, &mut rec, 0, R, 3);
        assert!(!r.tick(at(49), || at(9999), &mut rec));
        assert!(rec.delivered.len() == 1);
        assert_eq!(r.last_check(), at(0));
        assert!(r.tick(at(50), || at(2500), &mut rec));
        assert_eq!(r.last_check(), at(50));
        assert_eq!(rec.counters(), [1, 3]);
    }

    #[test]
    fn periodic_check_spacing_is_measured_from_the_last_performed_check() {
        let (mut r, mut rec) = fresh();
        assert!(r.tick(at(60), || at(60), &mut rec));
        assert!(!r.tick(at(109), || at(109), &mut rec));
        assert!(r.tick(at(110), || at(110), &mut rec));
        assert_eq!(r.last_check(), at(110));
    }

    #[test]
    fn check_spacing_truncates_a_negative_nanosecond_difference_toward_zero() {
        let (mut r, _) = fresh();
        r.last_check = Timespec::new(1, 990_000_000);
        assert!(!r.check_due(Timespec::new(2, 29_000_000)));
        assert!(!r.check_due(Timespec::new(2, 39_000_000)));
        assert!(r.check_due(Timespec::new(2, 39_999_999)));
        assert!(r.check_due(Timespec::new(2, 40_000_000)));
        assert!(r.check_due(Timespec::new(3, 0)));
    }

    #[test]
    fn timespec_milliseconds_truncate_nanoseconds() {
        assert_eq!(Timespec::new(3, 999_999).millis(), 3000);
        assert_eq!(Timespec::new(3, 1_000_000).millis(), 3001);
        assert_eq!(Timespec::new(2, 1_500_000_000).millis(), 3500);
    }

    #[test]
    fn reset_clears_buffer_and_peer_but_keeps_check_time() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        feed(&mut r, &mut rec, 0, R, 4);
        assert!(r.tick(at(70), || at(70), &mut rec));
        r.reset();
        assert_eq!(r.buffered_count(), 0);
        assert_eq!(r.peer_random(), None);
        assert_eq!(r.expected_counter(), 1);
        assert_eq!(r.stats(), Stats::default());
        assert_eq!(r.last_check(), at(70));
        assert_eq!(feed(&mut r, &mut rec, 0, R + 9, 40), Outcome::Delivered);
        assert!(rec.diags.is_empty());
    }

    #[test]
    fn full_size_payloads_are_buffered_and_delivered_intact() {
        let (mut r, _) = fresh();
        let mut big = vec![0u8; MAX_PACKET_LEN];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        struct Keep(Vec<Vec<u8>>);
        impl Sink for Keep {
            fn deliver(&mut self, _: Delivery, p: &[u8]) {
                self.0.push(p.to_vec());
            }
            fn diag(&mut self, _: &Diag) {}
        }
        let mut keep = Keep(Vec::new());
        r.process(at(0), R, 1, &[1], &mut keep);
        assert_eq!(r.process(at(0), R, 3, &big, &mut keep), Outcome::Buffered);
        assert_eq!(r.process(at(0), R, 1025, &big, &mut keep), Outcome::Buffered);
        r.process(at(0), R, 2, &[], &mut keep);
        assert_eq!(keep.0.len(), 3);
        assert!(keep.0[2] == big && keep.0[1].is_empty());
        assert_eq!(r.buffered_count(), 1);
    }

    #[test]
    fn all_window_slots_hold_distinct_counters_at_once() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        for c in 3..=1025 {
            assert_eq!(feed(&mut r, &mut rec, 0, R, c), Outcome::Buffered, "counter {c}");
        }
        assert_eq!(r.buffered_count(), 1023);
        feed(&mut r, &mut rec, 0, R, 2);
        assert_eq!(rec.counters(), (1..=1025).collect::<Vec<_>>());
    }

    #[test]
    fn late_probe_magic_header_is_a_new_peer_epoch() {
        let (mut r, mut rec) = fresh();
        feed(&mut r, &mut rec, 0, R, 1);
        assert_eq!(feed(&mut r, &mut rec, 0, u64::MAX, u64::MAX), Outcome::Delivered);
        assert_eq!(rec.diags.len(), 1);
        assert_eq!(r.expected_counter(), 0);
        assert_eq!(r.peer_random(), Some(u64::MAX));
    }
}
