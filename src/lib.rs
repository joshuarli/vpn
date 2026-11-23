pub mod cli;
pub mod config;
pub mod mtu;
pub mod proto;
pub mod reorder;

pub const VERSION_STRING: &str = "0.1.0";

pub const RECONNECT_ATTEMPTS: u32 = 100;

pub const TUN_WRITE_TIMEOUT_MS: i32 = 60 * 1000;

pub const EVENT_POLL_TIMEOUT_MS: i32 = reorder::CHECK_INTERVAL_MS as i32;

/// Seconds the client sleeps before reconnect attempt `attempt` (0-based), after printing
/// `Trying to reconnect`.
pub const fn reconnect_delay_secs(attempt: u32) -> u32 {
    if attempt > 3 { 3 } else { attempt }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_ramps_to_three_seconds() {
        let delays: Vec<u32> = (0..8).map(reconnect_delay_secs).collect();
        assert_eq!(delays, [0, 1, 2, 3, 3, 3, 3, 3]);
    }
}
