use super::spec::*;
use serde_json::json;

const PROBE16: &str = "ffffffffffffffffffffffffffffffff";

fn bytes(n: usize) -> String {
    pattern(n, 0x11)
}

fn both(v: &mut Vec<Spec>, name: &str, f: impl Fn(Spec) -> Spec) {
    v.push(f(Spec::server(name)));
    v.push(f(Spec::server_nokey(&format!("{name}_nokey"))));
}

pub fn server_cases() -> Vec<Spec> {
    let mut v = Vec::new();

    v.push(
        Spec::server("srv_short_datagrams_ignored")
            .raw(100, "")
            .raw(105, "00")
            .raw(110, &bytes(8))
            .raw(115, &bytes(15))
            .udp(120, 1)
            .tun_k(200, 1),
    );
    both(&mut v, "srv_too_small_16_to_31", |s| {
        s.raw(100, &bytes(16)).raw(105, &bytes(17)).raw(110, &bytes(24)).raw(115, &bytes(31)).udp(120, 1).raw(130, &bytes(32)).udp(140, 2)
    });
    both(&mut v, "srv_probe_echo_unauthenticated", |s| {
        s.raw(100, PROBE16)
            .raw(110, &format!("{PROBE16}{}", bytes(16)))
            .raw(120, &format!("{PROBE16}{}", bytes(100)))
            .raw(130, &format!("{PROBE16}{}", bytes(2000)))
            .raw(140, &format!("{PROBE16}{}", bytes(15)))
            .tun_k(200, 1)
            .udp(210, 1)
            .tun_k(300, 2)
    });
    both(&mut v, "srv_probe_echo_authenticated_form", |s| {
        s.udp_full(100, None, MAGIC, u64::MAX, &bytes(100), "valid").udp_full(110, None, MAGIC, u64::MAX, &bytes(0), "valid").udp_full(
            120,
            None,
            MAGIC,
            u64::MAX,
            &bytes(500),
            "bad_tag",
        )
    });
    v.push(
        Spec::server("srv_probe_echo_does_not_register_peer")
            .raw_from(100, "10.9.0.99:5000", PROBE16)
            .tun_k(200, 1)
            .udp(300, 1)
            .raw_from(400, "10.9.0.99:5000", &format!("{PROBE16}{}", bytes(40)))
            .tun_k(500, 2),
    );
    v.push(
        Spec::server("srv_probe_echo_to_each_sender")
            .udp(100, 1)
            .raw_from(200, "10.9.0.77:6000", PROBE16)
            .raw_from(210, "10.9.0.78:6001", &format!("{PROBE16}{}", bytes(33)))
            .tun_k(300, 1),
    );
    v.push(
        Spec::server("srv_probe_almost_magic")
            .udp_full(100, None, MAGIC, u64::MAX - 1, &pl(1), "valid")
            .udp_full(110, None, "fffffffffffffffe", u64::MAX, &pl(2), "valid")
            .udp_full(120, None, MAGIC, u64::MAX - 1, &pl(3), "bad_tag")
            .udp_full(130, None, MAGIC, 0, &pl(4), "valid")
            .tun_k(200, 1),
    );
    v.push(
        Spec::server("srv_probe_echo_send_fails")
            .err(rule_err("sendto", Some("udp"), 1, 2, "EIO"))
            .raw(100, PROBE16)
            .raw(110, &format!("{PROBE16}{}", bytes(20)))
            .raw(120, &format!("{PROBE16}{}", bytes(21))),
    );
    v.push(
        Spec::server("srv_probe_echo_send_eagain")
            .err(rule_err("sendto", Some("udp"), 1, 1, "EAGAIN"))
            .raw(100, PROBE16),
    );
    v.push(
        Spec::server("srv_probe_echo_ipv6")
            .set("passive", json!("::"))
            .raw_from(100, "[2001:db8::2]:5000", PROBE16)
            .udp_from(110, "[2001:db8::2]:5000", 1)
            .tun_k(200, 1),
    );

    both(&mut v, "srv_auth_failure_variants", |s| {
        s.udp(100, 1)
            .udp_a(110, 2, "bad_tag")
            .udp_a(120, 2, "flip:0")
            .udp_a(125, 2, "flip:7")
            .udp_a(130, 2, "flip:8")
            .udp_a(135, 2, "flip:15")
            .udp_a(140, 2, "flip:16")
            .udp_a(145, 2, "flip:20")
            .udp_a(150, 2, "flip:35")
            .udp_a(155, 2, "truncate:32")
            .udp_a(160, 2, "truncate:33")
            .udp_a(165, 2, "truncate:40")
            .udp_a(170, 2, "truncate:20")
            .udp_a(172, 2, "flip:36")
            .udp_a(173, 2, "flip:44")
            .udp_a(174, 2, "flip:51")
            .udp_a(175, 2, "truncate:16")
            .udp_a(180, 2, "truncate:15")
            .udp(190, 2)
            .tun_k(300, 1)
    });
    v.push(
        Spec::server("srv_auth_failure_does_not_update_peer")
            .udp(100, 1)
            .udp_full(110, Some("10.9.0.99:7777"), RA, 2, &pl(2), "bad_tag")
            .udp_full(120, Some("10.9.0.99:7777"), RA, 2, &pl(2), "flip:20")
            .tun_k(200, 1)
            .udp(300, 2)
            .tun_k(400, 2),
    );
    v.push(
        Spec::server("srv_peer_updates_on_replayed_datagram")
            .udps(100, 5, &[1, 2, 3])
            .tun_k(200, 1)
            .udp_from(300, "10.9.0.99:7777", 2)
            .tun_k(400, 2)
            .udp_from(500, "10.9.0.2:41194", 3)
            .tun_k(600, 3),
    );
    v.push(
        Spec::server("srv_peer_updates_on_old_epoch_replay")
            .udps(100, 5, &[1, 2, 3])
            .udp_full(200, None, RB, 1, &pl(9), "valid")
            .udp_full(300, Some("10.9.0.55:1111"), RA, 3, &pl(3), "valid")
            .tun_k(400, 1),
    );
    v.push(
        Spec::server("srv_peer_updates_on_window_jump")
            .udp(100, 1)
            .udp_from(200, "10.9.0.66:2222", 5000)
            .tun_k(300, 1),
    );
    v.push(
        Spec::server("srv_peer_connected_message_once")
            .udp(100, 1)
            .udp_from(110, "10.9.0.3:2000", 2)
            .udp_from(120, "10.9.0.4:2001", 3)
            .udp_from(130, "[2001:db8::9]:2002", 4)
            .tun_k(200, 1),
    );
    v.push(
        Spec::server("srv_peer_port_change")
            .udp(100, 1)
            .udp_from(110, "10.9.0.2:41195", 2)
            .tun_k(200, 1)
            .udp_from(300, "10.9.0.2:41194", 3)
            .tun_k(400, 2),
    );
    v.push(
        Spec::server("srv_peer_ipv6")
            .set("passive", json!("::"))
            .udp_from(100, "[2001:db8::2]:41194", 1)
            .udp_from(110, "[2001:db8::2]:41194", 2)
            .tun_k(200, 1),
    );
    v.push(
        Spec::server("srv_peer_ipv4_mapped")
            .set("passive", json!("::"))
            .udp_from(100, "[::ffff:10.9.0.2]:41194", 1)
            .tun_k(200, 1),
    );
    v.push(
        Spec::server("srv_peer_switch_v4_to_v6")
            .set("passive", json!("::"))
            .udp(100, 1)
            .udp_from(110, "[2001:db8::2]:41194", 2)
            .tun_k(200, 1),
    );
    v.push(Spec::server("srv_tun_before_client_dropped").tun_k(100, 1).tun_k(110, 2).udp(200, 1).tun_k(300, 3));
    v.push(
        Spec::server("srv_peer_unauthenticated_first_no_connect")
            .udp_a(100, 1, "bad_tag")
            .udp_a(110, 2, "truncate:40")
            .tun_k(200, 1),
    );
    v.push(
        Spec::server("srv_recvfrom_error")
            .err(rule_err("recvfrom", Some("udp"), 2, 2, "EIO"))
            .udps(100, 10, &[1, 2, 3, 4]),
    );
    v.push(
        Spec::server("srv_recvfrom_eagain_silent")
            .err(rule_err("recvfrom", Some("udp"), 1, 1, "EAGAIN"))
            .udps(100, 10, &[1, 2]),
    );
    v.push(Spec::server("srv_pollerr_udp_not_fatal").udp(100, 1).perr(200, "udp", &["POLLERR"]).udp(300, 2).perr(400, "udp", &["POLLHUP"]).tun_k(500, 1));
    v.push(
        Spec::server("srv_pollerr_udp_with_data")
            .udp(100, 1)
            .perr(200, "udp", &["POLLERR"])
            .udp(200, 2)
            .tun_k(300, 1),
    );
    v.push(Spec::server("srv_pollnval_ignored").udp(100, 1).perr(200, "udp", &["POLLNVAL"]).perr(210, "tun", &["POLLNVAL"]).udp(300, 2));

    v.push(Spec::server("send_server_eagain_silent").udp(100, 1).err(rule_err("sendmsg", Some("udp"), 1, 1, "EAGAIN")).tun_k(200, 1).tun_k(300, 2));
    v.push(Spec::server("send_server_enobufs_logged").udp(100, 1).err(rule_err("sendmsg", Some("udp"), 1, 2, "ENOBUFS")).tun_k(200, 1).tun_k(300, 2).tun_k(400, 3));
    v.push(Spec::server("send_server_eperm_continues").udp(100, 1).err(rule_err("sendmsg", Some("udp"), 1, 0, "EPERM")).tun_k(200, 1).udp(250, 2).tun_k(300, 2));
    v.push(Spec::server("send_server_eintr_logged").udp(100, 1).err(rule_err("sendmsg", Some("udp"), 2, 1, "EINTR")).tun_k(200, 1).tun_k(300, 2));
    v.push(Spec::server("send_server_econnrefused").udp(100, 1).err(rule_err("sendmsg", Some("udp"), 1, 1, "ECONNREFUSED")).tun_k(200, 1).tun_k(300, 2));
    v.push(Spec::server("send_server_emsgsize").udp(100, 1).err(rule_err("sendmsg", Some("udp"), 1, 1, "EMSGSIZE")).tun_k(200, 1));
    v.push(Spec::server("send_server_short_send").udp(100, 1).err(rule_short("sendmsg", "udp", 1, 1, 20)).tun_k(200, 1).tun_k(300, 2));

    v.push(
        Spec::server("wire_server_header_le")
            .prefix("0807060504030201")
            .udp(100, 1)
            .tun_k(200, 1)
            .tun(210, &bytes(1))
            .tun(220, &bytes(100)),
    );
    v.push(
        Spec::server_nokey("wire_server_header_le_nokey")
            .prefix("0807060504030201")
            .udp(100, 1)
            .tun_k(200, 1)
            .tun(210, &bytes(1))
            .tun(220, &bytes(100)),
    );
    let sizes = [0usize, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 1500, 4096, 9000];
    for (suffix, mk) in [("", true), ("_nokey", false)] {
        let mut s = if mk { Spec::server(&format!("wire_server_rx_sizes{suffix}")) } else { Spec::server_nokey(&format!("wire_server_rx_sizes{suffix}")) };
        for (i, n) in sizes.iter().enumerate() {
            s = s.udp_p(100 + 10 * i as u64, 1 + i as u64, &bytes(*n));
        }
        v.push(s.tun_k(1000, 1));
    }
    v.push(Spec::server("wire_server_rx_payload_max").udp_p(100, 1, &bytes(65536)).udp_p(200, 2, &pl(2)));
    v.push(Spec::server_nokey("wire_server_rx_payload_max_nokey").udp_p(100, 1, &bytes(65536)));
    v.push(
        Spec::server("wire_server_rx_oversized_datagram_truncated")
            .raw(100, &bytes(70000))
            .udp(120, 1),
    );
    v.push(Spec::server("wire_server_rx_zero_payload").udp_p(100, 1, "").udp_p(110, 2, &pl(2)).udp_p(120, 3, ""));
    v.push(Spec::server_nokey("wire_server_rx_zero_payload_nokey").udp_p(100, 1, "").udp_p(110, 2, &pl(2)));
    v.push(
        Spec::server("wire_server_rx_zero_payload_buffered")
            .udp_p(100, 1, &pl(1))
            .udp_p(110, 3, "")
            .udp_p(120, 4, &pl(4))
            .udp_p(130, 2, ""),
    );
    v
}

pub fn client_cases() -> Vec<Spec> {
    let mut v = Vec::new();

    v.push(
        Spec::client("wire_client_header_le")
            .prefix("0807060504030201")
            .tun_k(100, 1)
            .tun(110, &bytes(1))
            .tun(120, &bytes(100)),
    );
    v.push(
        Spec::client_nokey("wire_client_header_le_nokey")
            .prefix("0807060504030201")
            .tun_k(100, 1)
            .tun(110, &bytes(1))
            .tun(120, &bytes(100)),
    );
    let sizes = [1usize, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 1400, 1481, 1482];
    for (suffix, keyed) in [("", true), ("_nokey", false)] {
        let mut s = if keyed { Spec::client(&format!("wire_client_tx_sizes{suffix}")) } else { Spec::client_nokey(&format!("wire_client_tx_sizes{suffix}")) };
        for (i, n) in sizes.iter().enumerate() {
            s = s.tun(100 + 10 * i as u64, &bytes(*n));
        }
        v.push(s);
    }
    v.push(Spec::client("wire_client_tx_tun_roundtrip").tun_k(100, 1).udp(150, 1).tun_k(200, 2).udp(250, 2));

    for (tag, keyed) in [("", true), ("_nokey", false)] {
        let base = |n: &str| if keyed { Spec::client(n) } else { Spec::client_nokey(n) };
        v.push(
            base(&format!("cli_short_datagrams_ignored{tag}"))
                .raw(100, "")
                .raw(105, "00")
                .raw(110, &bytes(8))
                .raw(115, &bytes(15))
                .udp(120, 1)
                .tun_k(200, 1),
        );
        v.push(
            base(&format!("cli_too_small_reconnects{tag}"))
                .tun_k(50, 1)
                .raw(100, &bytes(16))
                .tun_k(150, 2)
                .raw(200, &bytes(31))
                .raw(210, &bytes(20))
                .udp(300, 1)
                .tun_k(350, 3)
                .end(2000),
        );
        v.push(
            base(&format!("cli_auth_failure_reconnects{tag}"))
                .tun_k(50, 1)
                .udp(100, 1)
                .udp_a(200, 2, "bad_tag")
                .tun_k(250, 2)
                .udp_a(300, 2, "flip:20")
                .udp_a(350, 2, "flip:51")
                .udp_a(380, 2, "flip:36")
                .udp_a(400, 2, "flip:0")
                .udp_a(500, 2, "truncate:40")
                .udp(600, 1)
                .tun_k(650, 3)
                .end(2000),
        );
        v.push(
            base(&format!("cli_reconnect_preserves_counter_resets_reorder{tag}"))
                .udps(100, 5, &[1, 2, 3])
                .tun_k(200, 1)
                .tun_k(210, 2)
                .udp_a(300, 4, "bad_tag")
                .tun_k(350, 3)
                .udps(400, 5, &[2, 3, 4])
                .tun_k(500, 4)
                .end(2000),
        );
        v.push(
            base(&format!("cli_reconnect_discards_buffered{tag}"))
                .udps(100, 5, &[1, 3, 4])
                .udp_a(200, 9, "bad_tag")
                .udps(300, 5, &[2, 3, 4])
                .end(5000),
        );
        v.push(
            base(&format!("cli_late_probe_reply_enters_reorder{tag}"))
                .udp(100, 1)
                .udp_full(150, None, MAGIC, u64::MAX, &bytes(20), "valid")
                .udp_full(160, None, MAGIC, u64::MAX, &bytes(21), "valid")
                .udp(200, 2)
                .tun_k(250, 1)
                .end(2000),
        );
        v.push(
            base(&format!("cli_late_probe_reply_first_packet{tag}"))
                .udp_full(100, None, MAGIC, u64::MAX, &bytes(40), "valid")
                .udp_full(110, None, MAGIC, 0, &bytes(40), "valid")
                .udp(200, 1),
        );
        v.push(
            base(&format!("cli_probe_unauthenticated_reconnects{tag}"))
                .raw(100, &format!("{PROBE16}{}", bytes(40)))
                .raw(200, PROBE16)
                .udp_full(300, None, MAGIC, u64::MAX, &bytes(30), "bad_tag")
                .end(2000),
        );
        v.push(
            base(&format!("cli_foreign_source_dropped{tag}"))
                .udp_from(100, "192.0.2.99:41194", 1)
                .udp_from(110, "192.0.2.10:41195", 2)
                .udp(120, 1)
                .tun_k(200, 1),
        );
        v.push(
            base(&format!("cli_ipv4_roundtrip_sizes{tag}"))
                .udp_p(100, 1, &bytes(1))
                .udp_p(110, 2, &bytes(1400))
                .udp_p(120, 3, ""),
        );
    }
    v.push(Spec::client("cli_recv_error_reconnects").err(rule_err("recv", Some("udp"), 1, 1, "EIO")).udp(100, 1).udp(200, 2).tun_k(300, 1).end(2000));
    v.push(Spec::client("cli_recv_eintr_reconnects").err(rule_err("recv", Some("udp"), 1, 1, "EINTR")).udp(100, 1).tun_k(300, 1).end(2000));
    v.push(Spec::client("cli_recv_eagain_silent").err(rule_err("recv", Some("udp"), 1, 1, "EAGAIN")).udp(100, 1).udp(200, 2).tun_k(300, 1));
    v.push(Spec::client("cli_recv_econnrefused_reconnects").err(rule_err("recv", Some("udp"), 1, 1, "ECONNREFUSED")).udp(100, 1).tun_k(300, 1).end(2000));
    v.push(Spec::client("cli_pollerr_udp_reconnects").udp(100, 1).perr(200, "udp", &["POLLERR"]).tun_k(300, 1).udp(400, 1).end(2000));
    v.push(Spec::client("cli_pollhup_udp_reconnects").udp(100, 1).perr(200, "udp", &["POLLHUP"]).tun_k(300, 1).end(2000));
    v.push(Spec::client("cli_pollerr_with_data_reconnects_first").udp(100, 1).perr(200, "udp", &["POLLERR"]).udp(200, 2).tun_k(300, 1).end(2000));
    v.push(Spec::client("cli_pollin_pollerr_combo").perr(100, "udp", &["POLLIN", "POLLERR"]).udp(100, 1).end(2000));
    v.push(Spec::client("cli_pollnval_udp_ignored").udp(100, 1).perr(200, "udp", &["POLLNVAL"]).udp(300, 2).tun_k(400, 1));
    v.push(Spec::client("cli_pollerr_tun_exits").udp(100, 1).perr(200, "tun", &["POLLERR"]).udp(300, 2));

    v.push(Spec::client("send_client_eagain_silent").err(rule_err("writev", Some("udp"), 1, 1, "EAGAIN")).tun_k(100, 1).tun_k(200, 2).tun_k(300, 3));
    v.push(Spec::client("send_client_enobufs_reconnects").err(rule_err("writev", Some("udp"), 1, 1, "ENOBUFS")).tun_k(100, 1).tun_k(200, 2).end(2000));
    v.push(Spec::client("send_client_eintr_reconnects").err(rule_err("writev", Some("udp"), 2, 1, "EINTR")).tun_k(100, 1).tun_k(200, 2).tun_k(300, 3).end(2000));
    v.push(Spec::client("send_client_eperm_reconnects").err(rule_err("writev", Some("udp"), 1, 1, "EPERM")).tun_k(100, 1).tun_k(200, 2).end(2000));
    v.push(Spec::client("send_client_econnrefused_reconnects").err(rule_err("writev", Some("udp"), 1, 1, "ECONNREFUSED")).tun_k(100, 1).tun_k(200, 2).end(2000));
    v.push(Spec::client("send_client_ewouldblock_silent").err(rule_err("writev", Some("udp"), 1, 2, "EWOULDBLOCK")).tun_k(100, 1).tun_k(200, 2).tun_k(300, 3));
    v.push(Spec::client("send_client_persistent_fail_exhausts_reconnect")
        .err(rule_err("writev", Some("udp"), 1, 0, "EIO"))
        .err(rule_err("connect", Some("udp"), 2, 0, "ECONNREFUSED"))
        .tun_k(100, 1)
        .tun_k(200, 2)
        .end_signal("none"));
    v.push(Spec::client("send_client_short_write").err(rule_short("writev", "udp", 1, 1, 20)).tun_k(100, 1).tun_k(200, 2));
    v.push(Spec::client_nokey("send_client_error_nokey").err(rule_err("writev", Some("udp"), 1, 1, "ENOBUFS")).tun_k(100, 1).tun_k(200, 2).end(2000));

    v
}

pub fn tun_cases() -> Vec<Spec> {
    let mut v = Vec::new();

    v.push(
        Spec::server("tun_oversize_boundary_server")
            .udp(100, 1)
            .tun(200, &bytes(1482))
            .tun(210, &bytes(1483))
            .tun(220, &bytes(1481))
            .tun(230, &bytes(1500))
            .tun(260, &bytes(70000))
            .tun(270, &bytes(1)),
    );
    v.push(
        Spec::client("tun_oversize_boundary_client")
            .tun(200, &bytes(1482))
            .tun(210, &bytes(1483))
            .tun(220, &bytes(1481))
            .tun(230, &bytes(65536)),
    );
    v.push(
        Spec::client_nokey("tun_oversize_boundary_client_nokey")
            .tun(200, &bytes(1482))
            .tun(210, &bytes(1483)),
    );
    v.push(
        Spec::tool("tun_oversize_mtu_68", &["-m", "68", "-k", "vpn.key", "server", "auto"])
            .keyed()
            .prefix(PREFIX)
            .udp(100, 1)
            .tun(200, &bytes(130))
            .tun(210, &bytes(131))
            .tun(220, &bytes(129)),
    );
    v.push(
        Spec::tool("tun_oversize_mtu_9000", &["-m", "9000", "-k", "vpn.key", "server", "auto"])
            .keyed()
            .prefix(PREFIX)
            .udp(100, 1)
            .tun(200, &bytes(9062))
            .tun(210, &bytes(9063)),
    );
    v.push(
        Spec::tool("tun_oversize_client_mtu_576", &["-m", "576", "-k", "vpn.key", "client", "192.0.2.10"])
            .keyed()
            .prefix(PREFIX)
            .tun(200, &bytes(638))
            .tun(210, &bytes(639)),
    );
    v.push(Spec::server("tun_oversize_does_not_consume_counter").udp(100, 1).tun(200, &bytes(1483)).tun_k(210, 1).tun(220, &bytes(1483)).tun_k(230, 2));
    v.push(Spec::client("tun_raw_framing_first_bytes").tun(100, "00").tun(110, "60").tun(120, "45").tun(130, "ff00ff00ff").udp_p(200, 1, "00").udp_p(210, 2, "6000000000000000").udp_p(220, 3, "ffffffff"));

    v.push(Spec::client("tunr_zero_length_ends_loop").udp(100, 1).tun(200, "").udp(300, 2));
    v.push(Spec::server("tunr_zero_length_ends_loop_server").udp(100, 1).tun(200, ""));
    v.push(Spec::client("tunr_error_eio").err(rule_err("read", Some("tun"), 1, 1, "EIO")).tun_k(100, 1).tun_k(200, 2));
    v.push(Spec::client("tunr_error_eagain_ends").err(rule_err("read", Some("tun"), 1, 1, "EAGAIN")).tun_k(100, 1));
    v.push(Spec::client("tunr_eintr_retried").err(rule_err("read", Some("tun"), 1, 2, "EINTR")).tun_k(100, 1).tun_k(200, 2));
    v.push(Spec::client("tunr_short_read_truncates").err(rule_short("read", "tun", 1, 1, 10)).tun_k(100, 1).tun_k(200, 2));
    v.push(Spec::server("tunr_short_read_server").udp(100, 1).err(rule_short("read", "tun", 1, 1, 7)).tun_k(200, 1).tun_k(210, 2));
    v.push(Spec::client("tunr_zero_short_read").err(rule_short("read", "tun", 1, 1, 0)).tun_k(100, 1).tun_k(200, 2));
    v.push(Spec::server("tunr_error_eio_server").udp(100, 1).err(rule_err("read", Some("tun"), 1, 1, "EIO")).tun_k(200, 1));
    v.push(Spec::client("tun_pollhup_exits").tun_k(100, 1).perr(200, "tun", &["POLLHUP"]).tun_k(300, 2));
    v.push(Spec::client("tun_pollerr_exits").perr(100, "tun", &["POLLERR"]));
    v.push(Spec::client("tun_pollin_and_pollhup_hup_wins").tun_k(100, 1).perr(100, "tun", &["POLLHUP"]));
    v.push(Spec::server("tun_pollhup_exits_server").udp(100, 1).perr(200, "tun", &["POLLHUP"]));
    v.push(Spec::client("tun_pollnval_alone_ignored").perr(100, "tun", &["POLLNVAL"]).tun_k(200, 1));

    v.push(Spec::server("tunw_error_eio_immediate").err(rule_err("write", Some("tun"), 2, 1, "EIO")).udps(100, 5, &[1, 2, 3]));
    v.push(Spec::server("tunw_error_eio_buffered").err(rule_err("write", Some("tun"), 2, 1, "EIO")).udps(100, 5, &[1, 3, 2, 4]));
    v.push(Spec::server("tunw_error_enospc").err(rule_err("write", Some("tun"), 1, 1, "ENOSPC")).udps(100, 5, &[1, 2]));
    v.push(Spec::server("tunw_eagain_retried").err(rule_err("write", Some("tun"), 1, 2, "EAGAIN")).udps(100, 5, &[1, 2]));
    v.push(Spec::server("tunw_eintr_retried").err(rule_err("write", Some("tun"), 1, 2, "EINTR")).udps(100, 5, &[1, 2]));
    v.push(Spec::server("tunw_short_split").err(rule_short("write", "tun", 1, 1, 10)).udps(100, 5, &[1, 2]));
    v.push(Spec::server("tunw_short_zero_progress").err(rule_short("write", "tun", 1, 1, 0)).udps(100, 5, &[1, 2]));
    v.push(Spec::server("tunw_short_one_byte_each").err(rule_short("write", "tun", 1, 20, 1)).udps(100, 5, &[1]));
    v.push(Spec::server("tunw_persistent_error").err(rule_err("write", Some("tun"), 1, 0, "EIO")).udps(100, 5, &[1, 2, 3, 5, 4]));
    v.push(Spec::server("tunw_buffered_short").err(rule_short("write", "tun", 3, 1, 8)).udps(100, 5, &[1, 3, 4, 2]));
    v.push(Spec::server("tunw_jump_error").err(rule_err("write", Some("tun"), 2, 1, "EIO")).udps(100, 5, &[1, 5000, 5001]));
    v.push(Spec::server("tunw_timeout_skip_error").err(rule_err("write", Some("tun"), 2, 1, "EIO")).udps(100, 5, &[1, 3, 4]).end(4000));
    v.push(Spec::client("tunw_eagain_then_error").err(rule_err("write", Some("tun"), 1, 1, "EAGAIN")).err(rule_err("write", Some("tun"), 2, 1, "EPIPE")).udps(100, 5, &[1, 2]));
    v.push(Spec::server("tunw_poll_error_during_wait").err(rule_err("write", Some("tun"), 1, 1, "EAGAIN")).err(rule_err("poll", None, 2, 1, "EBADF")).udps(100, 5, &[1, 2]));
    v.push(Spec::server("tunw_poll_eintr_during_wait").err(rule_err("write", Some("tun"), 1, 1, "EAGAIN")).err(rule_err("poll", None, 2, 1, "EINTR")).udps(100, 5, &[1, 2]));
    v
}
