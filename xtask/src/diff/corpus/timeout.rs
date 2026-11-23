use super::spec::*;

pub fn cases() -> Vec<Spec> {
    let mut v = Vec::new();
    for d in [0u64, 1, 13, 25, 37, 49] {
        let t = 100 + d;
        v.push(Spec::server(&format!("timeout_boundary_offset_{d}")).udp(100, 1).udp(t, 3).end(t + 2400));
    }
    v.push(Spec::server_nokey("timeout_boundary_nokey").udp(100, 1).udp(100, 3).end(4000));
    v.push(Spec::client("timeout_boundary_client").udp(100, 1).udp(113, 3).end(4000));
    for (tag, step) in [("1ms", 1u64), ("7ms", 7), ("20ms", 20)] {
        let mut s = Spec::server(&format!("timeout_check_interval_wakeups_{tag}")).udp(100, 1).udp(100, 3);
        let mut t = 1900;
        while t < 2300 {
            s = s.perr(t, "udp", &["POLLERR"]);
            t += step;
        }
        v.push(s.end(3500));
    }
    for fill in [1999u64, 2049, 2050, 2051, 2099, 2100, 2101, 2149, 2150, 2151, 2200] {
        v.push(Spec::server(&format!("timeout_late_fill_at_{fill}")).udp(100, 1).udp(100, 3).udp(fill, 2).udp(fill + 10, 4).end(fill + 600));
    }
    v.push(Spec::server("timeout_skip_to_lowest_not_first_slot").udp(100, 1018).udp(200, 1025).udp(210, 1022).end(6000));
    v.push(Spec::server("timeout_skip_to_lowest_three_slots").udp(100, 1019).udp(200, 1026).udp(205, 1030).udp(210, 1023).udp(215, 1021).end(9000));
    v.push(Spec::server("timeout_any_old_packet_triggers_with_fresh_min").udp(100, 1).udp(100, 5).udp(2000, 3).end(4000));
    v.push(Spec::server("timeout_staggered_arrivals").udp(100, 1).udp(100, 3).udp(1900, 6).end(8000));
    v.push(Spec::server("timeout_then_inorder_resumes").udp(100, 1).udp(100, 3).udps(3000, 10, &[4, 5, 6]).end(5000));
    v.push(Spec::server("timeout_two_rounds").udp(100, 1).udp(100, 3).udp(4000, 7).udp(4010, 9).end(9000));
    v.push(Spec::server("timeout_skips_buffer_run_in_order").udps(100, 1, &[1, 4, 5, 6, 8, 9]).end(6000));
    v.push(Spec::server("timeout_not_triggered_when_filled").udp(100, 1).udp(100, 3).udp(1900, 2).end(6000));
    v.push(Spec::server("timeout_none_when_idle").udp(100, 1).udp(200, 2).end(15000));
    v.push(Spec::client("timeout_cleared_by_reconnect").udp(100, 1).udp(100, 3).udp_a(1500, 9, "bad_tag").end(6000));
    v.push(Spec::server("timeout_cleared_by_jump").udp(100, 1).udp(100, 3).udp(1500, 5000).end(6000));
    v.push(Spec::server("timeout_cleared_by_epoch_change").udp(100, 1).udp(100, 3).udp_r(1500, RB, 1).end(6000));
    v.push(Spec::server("timeout_counts_lost_between_gaps").udp(100, 1).udp(100, 500).end(6000));
    v.push(Spec::server("timeout_second_gap_after_first_skip").udp(100, 1).udp(100, 3).udp(100, 6).end(6000));
    v.push(Spec::server("timeout_check_at_start_time_zero").udp(0, 1).udp(0, 3).end(4000));
    v.push(Spec::server("timeout_buffered_across_second_boundary").udp(900, 1).udp(990, 3).end(5000));
    v.push(Spec::server("timeout_buffered_at_second_boundary_edges").udp(1, 1).udp(999, 3).udp(1000, 5).udp(1001, 7).end(5000));
    v.push(Spec::server("timeout_long_run_drift").udp(100, 1).udp(137, 3).udp(2500, 2).udp(2537, 6).udp(7777, 8).end(12000));
    v
}
