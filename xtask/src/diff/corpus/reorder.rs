use super::spec::*;

const MAX: u64 = u64::MAX;

fn first_counter_case(tag: &str, first: u64) -> Spec {
    Spec::server(&format!("first_counter_{tag}"))
        .udp(100, first)
        .udp(110, first.wrapping_add(1))
        .udp(120, first.wrapping_add(2))
        .udp(130, first)
        .udp(140, first.wrapping_add(3))
        .udp(150, first.wrapping_add(1))
}

pub fn cases() -> Vec<Spec> {
    let mut v = Vec::new();
    let in_order: Vec<u64> = (1..=20).collect();
    v.push(Spec::server("reorder_in_order_burst").udps(100, 5, &in_order));
    v.push(Spec::server_nokey("reorder_in_order_burst_nokey").udps(100, 5, &in_order));
    v.push(Spec::client("reorder_in_order_burst_client").udps(100, 5, &in_order));
    v.push(Spec::server("reorder_reverse_burst").udp(100, 1).udps(110, 5, &[10, 9, 8, 7, 6, 5, 4, 3, 2]));
    v.push(Spec::client_nokey("reorder_reverse_burst_client").udp(100, 1).udps(110, 5, &[10, 9, 8, 7, 6, 5, 4, 3, 2]));
    v.push(Spec::server("reorder_interleaved").udps(100, 5, &[1, 3, 2, 5, 4, 7, 6, 9, 8, 10]));
    v.push(Spec::server("reorder_duplicates").udps(100, 5, &[1, 2, 2, 3, 1, 5, 5, 4, 4, 4, 6, 6]));
    v.push(Spec::server_nokey("reorder_duplicates_nokey").udps(100, 5, &[1, 2, 2, 3, 1, 5, 5, 4, 4, 4, 6, 6]));
    v.push(Spec::server("reorder_buffered_duplicates").udps(100, 5, &[1, 3, 3, 3, 4, 2, 2, 5]));
    v.push(Spec::server("reorder_multiple_gaps_filled").udps(100, 5, &[1, 3, 5, 7, 9, 2, 4, 6, 8, 10]));
    v.push(Spec::server("reorder_multiple_gaps_timeout").udps(100, 5, &[1, 3, 5, 7]).end(8000));
    v.push(Spec::server("reorder_gap_then_late_fill_after_timeout").udps(100, 5, &[1, 3, 4]).udp(3000, 2).udp(3010, 5).end(5000));
    v.push(Spec::server("reorder_late_after_skip_dropped").udps(100, 5, &[1, 4, 5]).udps(2500, 10, &[2, 3, 6]).end(5000));

    v.push(Spec::server("reorder_window_edge_buffered").udps(100, 5, &[1, 1025, 2]).end(5000));
    v.push(Spec::server("reorder_window_edge_jump").udps(100, 5, &[1, 1026, 1027, 1028]));
    v.push(Spec::server("reorder_window_edge_after_gap").udps(100, 5, &[1, 2, 3, 1027, 4, 1028]).end(6000));
    v.push(Spec::server("reorder_window_edge_one_below").udps(100, 5, &[1, 1024, 1025, 2]).end(6000));
    v.push(Spec::server("reorder_window_edge_one_above").udps(100, 5, &[1, 1027, 1028, 2]).end(6000));
    let mut full = Spec::server("reorder_window_full_flush").udp(100, 1);
    for c in 3..=1025u64 {
        full = full.udp(200 + c, c);
    }
    v.push(full.udp(1500, 2).udp(1510, 1026).end(3000));
    v.push(Spec::server("reorder_slot_alias_jump").udps(100, 5, &[1, 1025, 2049, 2050, 1025]));
    v.push(Spec::server("reorder_slot_alias_second_lap").udps(100, 5, &[1, 2, 1024, 1025, 3]).end(6000));
    v.push(Spec::server("reorder_slot_modulus_scan").udps(100, 5, &[1020, 1021, 1025, 1022, 1023, 1024, 1026, 1027]).end(6000));
    v.push(Spec::server("reorder_jump_clears_buffered").udps(100, 5, &[1, 5, 6, 7, 3000, 4, 3001, 3002]));
    v.push(Spec::server("reorder_jump_then_old_dropped").udps(100, 5, &[1, 2, 5000, 4999, 2, 5001, 3]));
    v.push(Spec::server("reorder_jump_chain").udps(100, 5, &[1, 2000, 4000, 6000, 8000, 8001]));
    v.push(Spec::server("reorder_jump_huge").udps(100, 5, &[1, 1 << 40, (1 << 40) + 1, 1 << 62, MAX - 10]));
    v.push(Spec::server("reorder_old_counters_dropped").udps(100, 5, &[5, 4, 3, 0, 6, 5, 7]));
    v.push(Spec::server("reorder_jump_stats_reset_then_buffer").udps(100, 5, &[1, 3000, 3003, 3002, 3001]));

    for (tag, c) in [
        ("0", 0u64),
        ("1", 1),
        ("2", 2),
        ("5", 5),
        ("1023", 1023),
        ("1024", 1024),
        ("1m", 1_000_000),
        ("2pow63", 1 << 63),
        ("max_minus_1", MAX - 1),
        ("max", MAX),
    ] {
        v.push(first_counter_case(tag, c));
    }
    v.push(first_counter_case("client_5", 5).argv(&["-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX));
    v.push(Spec::client_nokey("first_counter_client_nokey_0").udps(100, 10, &[0, 1, 2]));

    v.push(Spec::server("epoch_restart_lower_counter").udps(100, 5, &[1, 2, 3, 4, 5]).udp_r(200, RB, 1).udp_r(210, RB, 2).udp_r(220, RB, 3));
    v.push(Spec::server("epoch_restart_higher_counter").udps(100, 5, &[1, 2, 3]).udp_r(200, RB, 500).udp_r(210, RB, 501));
    v.push(Spec::server("epoch_restart_mid_counter_gap").udps(100, 5, &[1, 2, 3]).udp_r(200, RB, 7).udp_r(210, RB, 9).udp_r(220, RB, 8));
    v.push(
        Spec::server("epoch_restart_with_buffered")
            .udps(100, 5, &[1, 3, 4])
            .udp_r(200, RB, 1)
            .udps(300, 5, &[2])
            .udp_r(400, RB, 2)
            .end(5000),
    );
    v.push(Spec::server("epoch_flip_flop").udp(100, 1).udp_r(110, RB, 1).udp(120, 2).udp_r(130, RB, 2).udp(140, 3).udp_r(150, RB, 3));
    v.push(
        Spec::server("epoch_old_replay_resets")
            .udps(100, 5, &[1, 2, 3, 4, 5])
            .udp_r(200, RB, 1)
            .udp_r(210, RB, 2)
            .udp(300, 2)
            .udp(310, 3)
            .udp_r(400, RB, 3),
    );
    v.push(Spec::server_nokey("epoch_old_replay_nokey_server").udps(100, 5, &[1, 2, 3]).udp_r(200, RB, 1).udp(300, 1));
    v.push(Spec::server("epoch_random_zero_first").udp_r(100, "0000000000000000", 1).udp_r(110, "0000000000000000", 2).udp(120, 1));
    v.push(Spec::server("epoch_random_all_ones_normal_counter").udp_r(100, MAGIC, 1).udp_r(110, MAGIC, 2).udp(120, 1));
    v.push(Spec::server("epoch_bit_flip_in_random").udp_r(100, "a1a2a3a4a5a6a7a8", 1).udp_r(110, "a0a2a3a4a5a6a7a8", 2).udp_r(120, "a1a2a3a4a5a6a7a9", 3));
    v.push(Spec::client("epoch_restart_client").udps(100, 5, &[1, 2, 3]).udp_r(200, RB, 1).udp_r(210, RB, 2));
    v.push(Spec::server("epoch_same_counter_different_random").udp(100, 1).udp_r(110, RB, 1).udp_r(120, RB, 1));
    v.push(Spec::server("epoch_restart_timeout_clock").udps(100, 5, &[1, 3]).udp_r(1500, RB, 1).udp_r(1510, RB, 3).end(6000));

    v.push(Spec::server("wrap_receiver_through_zero").udps(100, 5, &[MAX - 3, MAX - 2, MAX - 1, MAX, 0, 1, 2, 3]));
    v.push(Spec::server_nokey("wrap_receiver_through_zero_nokey").udps(100, 5, &[MAX - 1, MAX, 0, 1]));
    v.push(Spec::server("wrap_buffer_across_zero").udps(100, 5, &[MAX - 1, MAX, 1, 2, 0]));
    v.push(Spec::server("wrap_timeout_stuck_across_zero").udps(100, 5, &[MAX - 1, MAX, 1, 2]).udp(7000, 0).end(9000));
    v.push(Spec::server("wrap_old_after_zero_dropped").udps(100, 5, &[MAX, 0, 1, MAX, MAX - 1, 2]));
    v.push(Spec::server("wrap_window_all_jump").udps(100, 5, &[MAX - 5, MAX - 3, MAX - 2, MAX - 4, MAX - 1, MAX, 0, 1]));
    v.push(Spec::server("wrap_window_jump_unordered").udps(100, 5, &[MAX - 5, MAX - 2, MAX - 3, MAX - 4]));
    v.push(Spec::server("wrap_jump_lands_on_max").udps(100, 5, &[1, MAX, 0, 1]));
    v.push(Spec::server("wrap_expected_plus_window_equals_zero").udps(100, 5, &[MAX - 1023, MAX - 1022, MAX - 1000, 0]));
    v.push(Spec::server("wrap_boundary_1023_before_max").udps(100, 5, &[MAX - 1100, MAX - 1099, MAX - 80, MAX - 79, MAX - 78]));
    v.push(Spec::client("wrap_receiver_client").udps(100, 5, &[MAX - 2, MAX - 1, MAX, 0, 1]));

    v
}
