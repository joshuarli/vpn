use super::spec::*;
use serde_json::json;
use std::collections::VecDeque;

const MAX: u64 = u64::MAX;

#[derive(Clone, Copy)]
pub enum Reply {
    None,
    Good,
    GoodTwice,
    WrongLen(i64),
    BadTag,
    NotProbe,
    Short(usize),
}

fn probe_reply(s: Spec, t: u64, data: i64, reply: Reply) -> Spec {
    let len = |d: i64| pattern((data + d).max(0) as usize, 0xaa);
    match reply {
        Reply::None => s,
        Reply::Good | Reply::GoodTwice => s.udp_full(t, None, MAGIC, MAX, &len(0), "valid"),
        Reply::WrongLen(d) => s.udp_full(t, None, MAGIC, MAX, &len(d), "valid"),
        Reply::BadTag => s.udp_full(t, None, MAGIC, MAX, &len(0), "bad_tag"),
        Reply::NotProbe => s.udp_full(t, None, RA, 7, &len(0), "valid"),
        Reply::Short(n) => s.raw(t, &pattern(n, 0x33)),
    }
}

/// Schedules datagrams so the client's binary search sees the given replies. Returns the spec,
/// the virtual time at which discovery ends, and the discovered best MTU.
pub fn mtu_script(mut s: Spec, start: u64, mut policy: impl FnMut(usize, i64, u32) -> Reply) -> (Spec, u64, i64) {
    let (mut min, mut max, mut best) = (576i64, 9000i64, 576i64);
    let mut t = start;
    let mut attempt = 0usize;
    let mut leftover: VecDeque<()> = VecDeque::new();
    while min <= max {
        let test = (min + max) / 2;
        let data = test - 62;
        let mut ok = false;
        for retry in 0..2u32 {
            attempt += 1;
            if leftover.pop_front().is_some() {
                continue;
            }
            let reply = policy(attempt, test, retry);
            match reply {
                Reply::None => t += 500,
                _ => {
                    t += 1;
                    s = probe_reply(s, t, data, reply);
                    if matches!(reply, Reply::GoodTwice) {
                        s = probe_reply(s, t, data, Reply::Good);
                        leftover.push_back(());
                    }
                    if matches!(reply, Reply::Good | Reply::GoodTwice) {
                        ok = true;
                        break;
                    }
                }
            }
        }
        if ok {
            best = test;
            min = test + 1;
        } else {
            max = test - 1;
        }
    }
    (s, t, best)
}

fn path_policy(path_data: i64) -> impl FnMut(usize, i64, u32) -> Reply {
    move |_, test, _| if test - 62 <= path_data { Reply::Good } else { Reply::None }
}

fn mtu_path_case(name: &str, keyed: bool, path_mtu: i64) -> Spec {
    let base = if keyed { Spec::tool(name, &["-d", "-k", "vpn.key", "client", "192.0.2.10"]).keyed() } else { Spec::tool(name, &["-d", "client", "192.0.2.10"]) };
    let base = base.prefix(PREFIX);
    let (s, end, best) = mtu_script(base, 0, path_policy(path_mtu - 62));
    let tun_mtu = (best - 62).max(576) as usize;
    s.tun(end + 100, &pattern(tun_mtu + 62, 1))
        .tun(end + 200, &pattern(tun_mtu + 63, 2))
        .udp_from(end + 300, CLI_PEER, 1)
        .tun(end + 400, &pattern(20, 3))
        .end(end + 1500)
}

fn client_discovery(name: &str) -> Spec {
    Spec::tool(name, &["-d", "-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX)
}

pub fn mtu_cases() -> Vec<Spec> {
    let mut v = Vec::new();
    for p in [575i64, 576, 577, 700, 1000, 1420, 1500, 2000, 4000, 9000] {
        v.push(mtu_path_case(&format!("mtu_path_{p}"), true, p));
    }
    for p in [576i64, 1500] {
        v.push(mtu_path_case(&format!("mtu_path_{p}_nokey"), false, p));
    }
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_second_try_succeeds"), 0, |_, test, retry| {
            if test - 62 <= 1400 { if retry == 0 { Reply::None } else { Reply::Good } } else { Reply::None }
        });
        s.tun(end + 100, &pattern(20, 1)).end(end + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_reply_wrong_length"), 0, |n, test, retry| {
            if test - 62 > 1400 { if n % 3 == 0 { Reply::WrongLen(1) } else { Reply::None } } else if retry == 0 && n % 2 == 0 { Reply::WrongLen(-1) } else { Reply::Good }
        });
        s.end(end + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_reply_bad_tag"), 0, |_, test, retry| {
            if test - 62 > 3000 { Reply::None } else if retry == 0 { Reply::BadTag } else { Reply::Good }
        });
        s.end(end + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_reply_not_probe_magic"), 0, |_, test, retry| {
            if test - 62 > 3000 { Reply::None } else if retry == 0 { Reply::NotProbe } else { Reply::Good }
        });
        s.end(end + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_reply_too_short"), 0, |_, test, retry| {
            if test - 62 > 3000 { Reply::None } else if retry == 0 { Reply::Short(20) } else { Reply::Good }
        });
        s.end(end + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_reply_short_16_to_31"), 0, |_, test, retry| {
            if test - 62 > 3000 { Reply::None } else if retry == 0 { Reply::Short(31) } else { Reply::Good }
        });
        s.end(end + 1000)
    });
    v.push({
        let mut first = true;
        let (s, end, _) = mtu_script(client_discovery("mtu_duplicate_reply_leaks_into_next_probe"), 0, move |_, test, _| {
            if test - 62 > 5000 {
                Reply::None
            } else if std::mem::take(&mut first) {
                Reply::GoodTwice
            } else {
                Reply::Good
            }
        });
        s.tun(end + 100, &pattern(20, 1)).end(end + 1000)
    });
    v.push({
        let mut last_good = 0;
        mtu_script(client_discovery("probe"), 0, |n, test, _| {
            if test - 62 <= 700 {
                last_good = n;
                Reply::Good
            } else {
                Reply::None
            }
        });
        let (s, end, _) = mtu_script(client_discovery("mtu_last_duplicate_delivered_as_late_probe"), 0, move |n, test, _| {
            if test - 62 > 700 { Reply::None } else if n == last_good { Reply::GoodTwice } else { Reply::Good }
        });
        s.tun(end + 100, &pattern(20, 1)).end(end + 1000)
    });
    v.push(
        client_discovery("mtu_probe_send_fails_always")
            .err(rule_err("writev", Some("udp"), 1, 0, "EIO"))
            .tun(60000, &pattern(20, 1))
            .end(70000),
    );
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_probe_send_fails_once"), 0, |_, test, retry| {
            if test - 62 <= 1400 && !(test == 4788 && retry == 0) { Reply::Good } else { Reply::None }
        });
        s.err(rule_err("writev", Some("udp"), 1, 1, "ENOBUFS")).end(end + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_set_interface_fails"), 0, path_policy(1400 - 62));
        s.err(rule_err("ioctl", Some("udp"), 2, 1, "EPERM")).tun(end + 100, &pattern(20, 1)).end(end + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_discovery_equals_current"), 0, path_policy(1482 - 62));
        s.end(end + 500)
    });
    v.push({
        let base = Spec::tool("mtu_discovery_again_after_reconnect", &["-d", "-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX);
        let (s, end, _) = mtu_script(base, 0, path_policy(1400 - 62));
        let s = s.udp_a(end + 100, 1, "bad_tag");
        let (s, end2, _) = mtu_script(s, end + 100, path_policy(1400 - 62));
        s.tun(end2 + 100, &pattern(20, 1)).end(end2 + 1000)
    });
    v.push({
        let base = Spec::tool("mtu_discovery_changes_after_reconnect", &["-d", "-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX);
        let (s, end, _) = mtu_script(base, 0, path_policy(1400 - 62));
        let s = s.tun(end + 50, &pattern(1400, 4)).udp_a(end + 100, 1, "bad_tag");
        let (s, end2, _) = mtu_script(s, end + 100, path_policy(3000 - 62));
        s.tun(end2 + 100, &pattern(2938, 1)).end(end2 + 1000)
    });
    v.push({
        let (s, end, _) = mtu_script(client_discovery("mtu_probe_wire_bytes"), 0, path_policy(1000));
        s.end(end + 100)
    });
    v.push(
        Spec::tool("mtu_discovery_ignores_server_role", &["-d", "-k", "vpn.key", "server", "auto"])
            .keyed()
            .prefix(PREFIX)
            .udp(100, 1)
            .tun_k(200, 1),
    );
    v.push(Spec::tool("mtu_manual_then_no_discovery", &["-d", "-m", "1200", "-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX).tun_k(100, 1));
    v.push(Spec::tool("mtu_manual_after_discover_flag", &["-m", "1200", "-d", "-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX).end(60000));
    v
}

pub fn exit_cases() -> Vec<Spec> {
    let mut v = Vec::new();
    v.push(Spec::tool("exit_early_gateway_missing_client", &["client", "192.0.2.10"]).cmd(rule_popen("print $3", 1, 0, "")));
    v.push(Spec::tool("exit_early_gateway_missing_server_continues", &["server", "auto"]).cmd(rule_popen("print $3", 1, 0, "")).udp(100, 1));
    v.push(Spec::tool("exit_early_ext_if_missing_server", &["server", "auto"]).cmd(rule_popen("print $5", 1, 0, "")));
    v.push(Spec::tool("exit_ext_if_missing_client_continues", &["client", "192.0.2.10"]).cmd(rule_popen("print $5", 1, 0, "")).tun_k(100, 1));
    v.push(Spec::tool("exit_gateway_command_unavailable", &["client", "192.0.2.10"]).err(rule_err("popen", None, 1, 1, "EMFILE")));
    v.push(Spec::tool("exit_ext_if_command_unavailable_server", &["server", "auto"]).err(rule_err("popen", None, 2, 1, "EMFILE")));
    v.push(Spec::tool("exit_gateway_explicit_skips_probe", &["client", "192.0.2.10", "auto", "auto", "auto", "auto", "198.51.100.1"]).tun_k(100, 1));
    v.push(Spec::tool("exit_early_tun_ioctl_fails", &["server", "auto"]).err(rule_err("ioctl", Some("tun"), 1, 1, "EPERM")));
    v.push(Spec::tool("exit_early_urandom_open_fails", &["server", "auto"]).err(rule_err("open", Some("urandom"), 1, 1, "EACCES")));
    v.push(Spec::tool("exit_early_urandom_read_fails", &["client", "192.0.2.10"]).err(rule_err("read", Some("urandom"), 1, 1, "EIO")));
    v.push(Spec::tool("exit_early_urandom_short_reads", &["client", "192.0.2.10"]).prefix(PREFIX).err(rule_short("read", "urandom", 1, 1, 3)).tun_k(100, 1));
    v.push(Spec::tool("exit_early_urandom_eintr", &["client", "192.0.2.10"]).err(rule_err("read", Some("urandom"), 1, 1, "EINTR")));
    v.push(Spec::tool("exit_mtu_ioctl_fails_continues", &["server", "auto"]).err(rule_err("ioctl", Some("udp"), 1, 1, "EPERM")).udp(100, 1));
    v.push(Spec::tool("exit_mtu_socket_fails_continues", &["server", "auto"]).err(rule_err("socket", None, 1, 1, "EMFILE")).udp(100, 1));
    v.push(Spec::tool("exit_resolve_fails_runs_unset", &["client", "nosuch.invalid"]));
    v.push(Spec::tool("exit_server_firewall_fails_255", &["server", "auto"]).cmd(rule_exec("ip addr add", 1, 0, 1)));
    v.push(Spec::tool("exit_server_firewall_first_cmd_fails", &["server", "auto"]).cmd(rule_exec("sysctl", 1, 0, 1)));
    v.push(Spec::tool("exit_server_firewall_last_cmd_fails", &["server", "auto"]).cmd(rule_exec("-i $IF_NAME", 1, 0, 1)).cmd(rule_exec("-A FORWARD", 2, 0, 3)));
    v.push(Spec::tool("exit_server_firewall_killed_by_signal", &["server", "auto"]).cmd(json!({"kind": "exec", "match": "iptables", "from": 1, "to": 1, "signal": 9})));
    v.push(Spec::tool("exit_server_firewall_exec_fails", &["server", "auto"]).err(rule_err("execvp", None, 3, 1, "ENOENT")));
    v.push(Spec::tool("exit_server_firewall_fork_fails", &["server", "auto"]).err(rule_err("fork", None, 2, 1, "EAGAIN")));
    v.push(Spec::tool("exit_server_firewall_waitpid_fails", &["server", "auto"]).err(rule_err("waitpid", None, 1, 1, "ECHILD")));
    v.push(Spec::tool("exit_server_bind_fails_255", &["server", "auto"]).err(rule_err("bind", Some("udp"), 1, 1, "EADDRINUSE")));
    v.push(Spec::tool("exit_server_socket_fails_255", &["server", "auto"]).err(rule_err("socket", None, 2, 1, "EMFILE")));
    v.push(Spec::tool("exit_server_reuseaddr_fails_255", &["server", "auto"]).err(rule_err("setsockopt", Some("udp"), 1, 1, "EPERM")));
    v.push(Spec::tool("exit_server_other_sockopts_ignored", &["server", "auto"]).err(rule_err("setsockopt", Some("udp"), 2, 3, "EPERM")).udp(100, 1));
    v.push(Spec::tool("exit_server_resolve_fails_1", &["server", "nosuch.invalid"]));
    v.push(Spec::tool("exit_server_bind_resolve_gai_fails", &["server", "10.1.2.3"]).err(rule_err("getaddrinfo", None, 2, 1, "EAI_AGAIN")));
    v.push(Spec::tool("exit_client_100_attempts_255", &["client", "192.0.2.10"]).err(rule_err("connect", Some("udp"), 1, 0, "ECONNREFUSED")).end_signal("none"));
    v.push(Spec::tool("exit_client_socket_fails_100_attempts", &["client", "192.0.2.10"]).err(rule_err("socket", None, 2, 0, "EMFILE")).end_signal("none"));
    v.push(
        Spec::tool("exit_client_reconnect_exhausted_done_0", &["-k", "vpn.key", "client", "192.0.2.10"])
            .keyed()
            .prefix(PREFIX)
            .err(rule_err("connect", Some("udp"), 2, 0, "ENETUNREACH"))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .end_signal("none"),
    );
    v.push(Spec::tool("exit_loop_tun_read_error_done_0", &["server", "auto"]).err(rule_err("read", Some("tun"), 1, 1, "EIO")).tun_k(100, 1));
    v.push(Spec::tool("exit_loop_poll_error_done_0", &["server", "auto"]).err(rule_err("poll", None, 4, 1, "EBADF")).udp(100, 1).udp(200, 2));
    v.push(Spec::tool("exit_loop_poll_eintr_continues", &["server", "auto"]).err(rule_err("poll", None, 3, 2, "EINTR")).udp(100, 1).udp(200, 2).tun_k(300, 1));
    v.push(Spec::tool("exit_loop_poll_error_client", &["client", "192.0.2.10"]).err(rule_err("poll", None, 2, 1, "ENOMEM")).tun_k(100, 1));
    v.push(Spec::tool("exit_loop_poll_eintr_client_discovery", &["-d", "client", "192.0.2.10"]).err(rule_err("poll", None, 1, 3, "EINTR")).end(60000));
    v.push(Spec::tool("exit_usage_no_args_again", &[]));
    v.push(Spec::tool("exit_usage_only_empty_arg", &[""]));
    v
}

pub fn signal_cases() -> Vec<Spec> {
    let mut v = Vec::new();
    v.push(Spec::server("sig_sigint_server").udp(100, 1).end(1000).end_signal("SIGINT"));
    v.push(Spec::server("sig_sigterm_server").udp(100, 1).end(1000));
    v.push(Spec::client("sig_sigint_client").tun_k(100, 1).end(1000).end_signal("SIGINT"));
    v.push(Spec::client("sig_sigterm_client").tun_k(100, 1).end(1000));
    v.push(Spec::server("sig_at_time_zero_server").sig(0, "SIGTERM").udp(100, 1));
    v.push(Spec::client("sig_at_time_zero_client").sig(0, "SIGINT").tun_k(100, 1));
    v.push(Spec::server("sig_second_signal_after_handler_not_reached").sig(100, "SIGINT").sig(110, "SIGINT").udp(120, 1));
    v.push(Spec::server("sig_sighup_default_kills").udp(100, 1).sig(200, "SIGHUP").end_signal("none").end(1000));
    v.push(Spec::server("sig_sigusr1_default_kills").udp(100, 1).sig(200, "SIGUSR1").end_signal("none").end(1000));
    v.push(Spec::client("sig_sigusr2_default_kills_client").tun_k(100, 1).sig(200, "SIGUSR2").end_signal("none").end(1000));
    v.push(Spec::client("sig_sigquit_default_kills_client").tun_k(100, 1).sig(200, "SIGQUIT").end_signal("none").end(1000));
    v.push(
        Spec::tool("sig_double_sigint_kills_during_discovery", &["-d", "-k", "vpn.key", "client", "192.0.2.10"])
            .keyed()
            .prefix(PREFIX)
            .sig(300, "SIGINT")
            .sig(900, "SIGINT")
            .end_signal("none")
            .end(60000),
    );
    v.push(
        Spec::tool("sig_sigint_then_sigterm_discovery_survives", &["-d", "-k", "vpn.key", "client", "192.0.2.10"])
            .keyed()
            .prefix(PREFIX)
            .sig(300, "SIGINT")
            .sig(900, "SIGTERM")
            .end_signal("none")
            .end(60000),
    );
    v.push(
        Spec::tool("sig_double_sigterm_kills_during_discovery", &["-d", "client", "192.0.2.10"])
            .sig(300, "SIGTERM")
            .sig(5000, "SIGTERM")
            .end_signal("none")
            .end(60000),
    );
    v.push(
        Spec::tool("sig_sigint_then_sigterm_then_sigint_discovery", &["-d", "client", "192.0.2.10"])
            .sig(300, "SIGINT")
            .sig(1200, "SIGTERM")
            .sig(3000, "SIGINT")
            .end_signal("none")
            .end(60000),
    );
    v.push(
        Spec::client("sig_during_reconnect_sleep_connect_ok")
            .err(rule_err("connect", Some("udp"), 2, 3, "ECONNREFUSED"))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .sig(2500, "SIGTERM")
            .end_signal("none")
            .end(3000),
    );
    v.push(
        Spec::client("sig_during_reconnect_sleep_connect_fails")
            .err(rule_err("connect", Some("udp"), 2, 0, "ECONNREFUSED"))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .sig(2500, "SIGINT")
            .end_signal("none")
            .end(3000),
    );
    v.push(
        Spec::client("sig_during_initial_connect_sleep")
            .err(rule_err("connect", Some("udp"), 1, 0, "ECONNREFUSED"))
            .sig(4000, "SIGTERM")
            .end_signal("none")
            .end(3000),
    );
    v.push(Spec::client("sig_ignored_second_after_exit_flag").sig(100, "SIGTERM").sig(100, "SIGINT").tun_k(200, 1));
    v.push(Spec::server("sig_sigterm_then_events_not_processed").sig(100, "SIGTERM").udp(100, 1).udp(110, 2));
    v
}

pub fn reconnect_cases() -> Vec<Spec> {
    let mut v = Vec::new();
    v.push(Spec::client("reconnect_initial_fail_then_ok_sleeps").err(rule_err("connect", Some("udp"), 1, 6, "ECONNREFUSED")).tun_k(100, 1).tun_k(20000, 2).end(30000));
    v.push(Spec::client("reconnect_after_bad_datagram_fail_then_ok").err(rule_err("connect", Some("udp"), 2, 5, "ECONNREFUSED")).tun_k(50, 1).udp_a(100, 1, "bad_tag").tun_k(30000, 2).end(40000));
    v.push(Spec::client("reconnect_socket_fails_then_ok").err(rule_err("socket", None, 3, 2, "EMFILE")).tun_k(100, 1).end(20000));
    v.push(Spec::client("reconnect_resolution_fails_then_ok").err(rule_err("getaddrinfo", None, 2, 2, "EAI_AGAIN")).tun_k(100, 1).end(20000));
    v.push(Spec::client("reconnect_resolution_fails_forever").err(rule_err("getaddrinfo", None, 2, 0, "EAI_FAIL")).end_signal("none"));
    v.push(Spec::client("reconnect_close_old_socket_events").udp(100, 1).udp_a(200, 2, "bad_tag").udp_a(300, 3, "bad_tag").tun_k(400, 1).end(5000));
    v.push(Spec::client("reconnect_repeated_resets_reorder_each_time").udps(100, 5, &[1, 2]).udp_a(200, 3, "bad_tag").udps(300, 5, &[1, 2]).udp_a(400, 3, "bad_tag").udps(500, 5, &[2, 3]).end(3000));
    v.push(Spec::client("reconnect_epoch_after_reset").udp(100, 1).udp_a(200, 2, "bad_tag").udp_r(300, RB, 1).udp_r(310, RB, 2).end(3000));
    v.push(Spec::client("reconnect_counter_preserved_many").tun_k(100, 1).tun_k(110, 2).udp_a(200, 1, "bad_tag").tun_k(210, 3).udp_a(300, 1, "bad_tag").tun_k(310, 4).end(2000));
    v.push(Spec::client("reconnect_pollerr_in_sleep_window").udp(100, 1).perr(200, "udp", &["POLLERR"]).perr(300, "udp", &["POLLHUP"]).tun_k(400, 1).end(3000));
    v.push(
        Spec::client("reconnect_gateway_changed")
            .cmd(rule_popen("print $3", 2, 2, "192.0.2.99\n"))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .tun_k(300, 1)
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_gateway_changed_twice")
            .cmd(rule_popen("print $3", 2, 2, "192.0.2.99\n"))
            .cmd(rule_popen("print $3", 3, 3, "192.0.2.100\n"))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .udp_a(300, 2, "bad_tag")
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_gateway_same_no_message")
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_gateway_lost_empty_output")
            .cmd(rule_popen("print $3", 2, 0, ""))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_gateway_popen_fails")
            .err(rule_err("popen", None, 3, 1, "EMFILE"))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .end(3000),
    );
    v.push(
        Spec::tool("reconnect_gateway_explicit_not_probed", &["-k", "vpn.key", "client", "192.0.2.10", "auto", "auto", "auto", "auto", "198.51.100.1"])
            .keyed()
            .prefix(PREFIX)
            .cmd(rule_popen("print $3", 2, 0, "192.0.2.99\n"))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_gateway_long_output_truncated")
            .cmd(rule_popen("print $3", 1, 1, &format!("{}\n", "1".repeat(80))))
            .cmd(rule_popen("print $3", 2, 2, &format!("{}\n", "2".repeat(70))))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_gateway_changed_firewall_unset_fails")
            .cmd(rule_popen("print $3", 2, 2, "192.0.2.99\n"))
            .cmd(rule_exec("iptables -t raw -D", 2, 2, 1))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_gateway_changed_firewall_set_fails")
            .cmd(rule_popen("print $3", 2, 2, "192.0.2.99\n"))
            .cmd(rule_exec("ip route add default", 1, 0, 2))
            .udp(100, 1)
            .udp_a(200, 2, "bad_tag")
            .tun_k(300, 1)
            .end(3000),
    );
    v.push(
        Spec::client("reconnect_server_role_untouched_probe_echo")
            .udp(100, 1)
            .end(1000),
    );
    v
}

pub fn socket_cases() -> Vec<Spec> {
    let mut v = Vec::new();
    v.push(Spec::server("sock_server_v4_buffers_reuseaddr").udp(100, 1));
    v.push(Spec::server("sock_server_v6_dualstack").set("passive", json!("::")).udp_from(100, "[2001:db8::2]:41194", 1).tun_k(200, 1));
    v.push(Spec::tool("sock_server_named_v6_bind", &["-k", "vpn.key", "server", "v6.example.test"]).keyed().prefix(PREFIX).dns("v6.example.test", "2001:db8::5").udp_from(100, "[2001:db8::2]:41194", 1));
    v.push(Spec::tool("sock_client_v6_connect", &["-k", "vpn.key", "client", "2001:db8::1"]).keyed().prefix(PREFIX).tun_k(100, 1).udp_from(200, "[2001:db8::1]:41194", 1));
    v.push(Spec::tool("sock_client_named_v4_connect", &["-k", "vpn.key", "client", "vpn.example.test"]).keyed().prefix(PREFIX).dns("vpn.example.test", "192.0.2.77").tun_k(100, 1).udp_from(200, "192.0.2.77:41194", 1));
    v.push(Spec::client("sock_client_fcntl_getfl_fails").err(rule_err("fcntl", Some("udp"), 1, 1, "EBADF")).tun_k(100, 1));
    v.push(Spec::client("sock_client_setsockopt_failures_ignored").err(rule_err("setsockopt", Some("udp"), 1, 2, "ENOMEM")).tun_k(100, 1));
    v.push(Spec::server("sock_server_fcntl_setfl_fails_ignored").err(rule_err("fcntl", Some("udp"), 2, 1, "EBADF")).udp(100, 1));
    v.push(Spec::server("sock_server_listening_banner_named").set("dns", json!({})).argv(&["-k", "vpn.key", "server", "10.20.30.40", "6000"]).udp(100, 1));
    v.push(Spec::client("sock_client_connect_banner_port").argv(&["-k", "vpn.key", "client", "192.0.2.10", "7000"]).tun_k(100, 1).udp_from(200, "192.0.2.10:7000", 1));
    v.push(Spec::server("sock_server_port_zero").argv(&["-k", "vpn.key", "server", "auto", "0"]).udp(100, 1));
    v
}

pub fn config_cases() -> Vec<Spec> {
    let mut v = Vec::new();
    v.push(Spec::server("cfg_server_default_commands").udp(100, 1));
    v.push(Spec::server("cfg_server_default_teardown_sigint").end(500).end_signal("SIGINT"));
    v.push(Spec::tool("cfg_server_custom_names", &["server", "auto", "5000", "tunx", "10.1.1.1", "10.1.1.2", "198.51.100.7"]).end(500));
    v.push(Spec::client("cfg_client_default_commands").tun_k(100, 1));
    v.push(Spec::client_nokey("cfg_client_nokey_commands").tun_k(100, 1));
    v.push(Spec::tool("cfg_client_custom_names", &["client", "192.0.2.10", "5555", "tuny", "10.8.0.2", "10.8.0.1", "198.51.100.1"]).end(500));
    v.push(Spec::tool("cfg_client_ipv6_server_ext_ip", &["client", "2001:db8::1"]).end(500));
    v.push(Spec::tool("cfg_client_named_server_ext_ip", &["client", "vpn.example.test"]).dns("vpn.example.test", "192.0.2.77").end(500));
    v.push(Spec::tool("cfg_server_named_bind_ext_ip", &["server", "vpn.example.test", "auto", "tunq"]).dns("vpn.example.test", "192.0.2.77").end(500));
    v.push(Spec::tool("cfg_server_ext_if_from_route", &["server", "auto"]).cmd(rule_popen("print $5", 1, 0, "wlan7\n")).end(500));
    v.push(Spec::tool("cfg_server_ext_if_with_space", &["server", "auto"]).cmd(rule_popen("print $5", 1, 0, "eth 0\n")).end(500));
    v.push(Spec::tool("cfg_server_ext_if_no_newline", &["server", "auto"]).cmd(rule_popen("print $5", 1, 0, "bond0")).end(500));
    v.push(Spec::tool("cfg_server_ext_if_long", &["server", "auto"]).cmd(rule_popen("print $5", 1, 0, &format!("{}\n", "e".repeat(90)))).end(500));
    v.push(Spec::tool("cfg_client_set_fails_continues", &["-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX).cmd(rule_exec("ip route add default dev", 1, 0, 2)).tun_k(100, 1).end(1000));
    v.push(Spec::tool("cfg_client_set_fails_reconnect_retries", &["-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX).cmd(rule_exec("ip -6 addr add", 1, 1, 2)).udp(100, 1).udp_a(200, 2, "bad_tag").tun_k(300, 1).end(2000));
    v.push(Spec::tool("cfg_client_unset_fails_at_exit", &["-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX).cmd(rule_exec("ip -6 rule delete", 2, 0, 2)).tun_k(100, 1).end(1000));
    v.push(Spec::tool("cfg_server_unset_fails_at_exit", &["-k", "vpn.key", "server", "auto"]).keyed().prefix(PREFIX).cmd(rule_exec("iptables -t nat -D", 1, 0, 1)).udp(100, 1).end(1000));
    v.push(Spec::tool("cfg_client_initial_unset_fails_silent", &["client", "192.0.2.10"]).cmd(rule_exec("ip rule delete table 42069", 1, 1, 1)).end(500));
    v.push(Spec::tool("cfg_server_exec_signal_death", &["-k", "vpn.key", "server", "auto"]).keyed().prefix(PREFIX).cmd(json!({"kind": "exec", "match": "ip link set", "from": 1, "to": 1, "signal": 11})));
    v.push(Spec::tool("cfg_server_nonzero_exit_masked_by_errno", &["server", "auto"]).cmd(rule_exec("MASQUERADE", 1, 1, 4)));
    v.push(Spec::tool("cfg_server_overlong_remote_ip", &["server", "auto", "auto", "auto", "auto", &"2".repeat(4200)]));
    v.push(Spec::tool("cfg_server_many_spaces_in_ip", &["server", "auto", "auto", "auto", &(0..70).map(|i| format!("a{i}")).collect::<Vec<_>>().join(" "), "10.1.1.2"]));
    v.push(Spec::tool("cfg_server_tabs_newlines_in_ip", &["server", "auto", "auto", "auto", "10.1.1.1\t\n10.1.1.3", "10.1.1.2"]));
    v.push(Spec::tool("cfg_server_empty_ip_arg", &["server", "auto", "auto", "auto", "", "10.1.1.2"]));
    v.push(Spec::tool("cfg_client_empty_remote_arg", &["client", "192.0.2.10", "auto", "auto", "10.8.0.2", ""]).end(500));
    v.push(Spec::tool("cfg_server_substitution_prefix_overlap", &["server", "auto", "auto", "auto", "x$LOCAL_TUN_IP6y", "$REMOTE_TUN_IP6"]));
    v.push(Spec::tool("cfg_server_unknown_dollar_token", &["server", "auto", "auto", "auto", "$UNKNOWN", "a$b"]));
    v
}
