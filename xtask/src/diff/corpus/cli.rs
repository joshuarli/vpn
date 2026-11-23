use super::spec::*;
use serde_json::json;

fn mtu_case(tag: &str, value: &str) -> Spec {
    Spec::tool(&format!("opt_mtu_{tag}"), &["-m", value, "server", "auto"])
}

pub fn cases() -> Vec<Spec> {
    let mut v = Vec::new();

    v.push(Spec::tool("opt_key_long", &["--key", "vpn.key", "server", "auto"]).keyed().prefix(PREFIX).udp(100, 1));
    v.push(Spec::tool("opt_mtu_long", &["--mtu", "1380", "server", "auto"]));
    v.push(Spec::tool("opt_discover_long", &["--discover-mtu", "client", "192.0.2.10"]).end(60000));
    v.push(Spec::tool("opt_key_last_wins", &["-k", "missing.key", "-k", "vpn.key", "server", "auto"]).keyed());
    v.push(Spec::tool("opt_mtu_last_wins", &["-m", "1380", "-m", "1400", "server", "auto"]));
    v.push(Spec::tool("opt_discover_twice", &["-d", "-d", "client", "192.0.2.10"]).end(60000));
    v.push(Spec::tool("opt_order_mtu_then_discover", &["-m", "1380", "-d", "client", "192.0.2.10"]).end(60000));
    v.push(Spec::tool("opt_order_discover_then_mtu", &["-d", "-m", "1380", "client", "192.0.2.10"]).tun(100, &pl(1)));
    v.push(Spec::tool("opt_discover_server_ignored", &["-d", "server", "auto"]));
    v.push(Spec::tool("opt_all_options", &["-d", "-k", "vpn.key", "-m", "1300", "-d", "client", "192.0.2.10"]).keyed().prefix(PREFIX).end(60000));

    let values = [
        ("68", "68"),
        ("67", "67"),
        ("9000", "9000"),
        ("9001", "9001"),
        ("0", "0"),
        ("negative", "-1"),
        ("text", "abc"),
        ("trailing_text", "1380abc"),
        ("leading_space", " 1380"),
        ("leading_tab_newline", "\t\n1380"),
        ("plus", "+1380"),
        ("fraction", "1380.9"),
        ("hex", "0x564"),
        ("exponent", "1e3"),
        ("leading_zeros", "00100"),
        ("minus_zero", "-0"),
        ("empty", ""),
        ("wrap_u32_to_valid", "4294968676"),
        ("wrap_u32_to_zero", "4294967296"),
        ("saturate_long_max", "99999999999999999999"),
        ("saturate_long_min", "-99999999999999999999"),
        ("int_min_boundary", "2147483648"),
        ("int_max", "2147483647"),
        ("long_max_exact", "9223372036854775807"),
        ("long_max_plus_one", "9223372036854775808"),
        ("trunc_to_9000", "4294976296"),
        ("trunc_to_68", "4294967364"),
    ];
    for (tag, value) in values {
        v.push(mtu_case(tag, value));
    }

    v.push(Spec::tool("opt_missing_key_value", &["-k"]));
    v.push(Spec::tool("opt_missing_mtu_value", &["-m"]));
    v.push(Spec::tool("opt_missing_mtu_value_after_key", &["-k", "vpn.key", "--mtu"]));
    v.push(Spec::tool("opt_mtu_before_missing_key", &["-m", "70", "--key"]));
    v.push(Spec::tool("opt_unknown_short", &["-x", "server", "auto"]));
    v.push(Spec::tool("opt_unknown_dash", &["-", "server", "auto"]));
    v.push(Spec::tool("opt_unknown_long", &["--bogus"]));
    v.push(Spec::tool("opt_unknown_after_valid", &["-k", "vpn.key", "-z", "client", "192.0.2.10"]).keyed());
    v.push(Spec::tool("opt_options_only", &["-d"]));
    v.push(Spec::tool("opt_options_only_mtu", &["-m", "1400"]));
    v.push(Spec::tool("opt_after_mode_discover", &["server", "-d", "auto"]));
    v.push(Spec::tool("opt_after_mode_key", &["client", "-k", "vpn.key"]).keyed());
    v.push(Spec::tool("opt_empty_key_path", &["-k", "", "server", "auto"]));
    v.push(Spec::tool("opt_missing_key_file", &["-k", "absent.key", "server", "auto"]));
    v.push(Spec::tool("opt_key_is_flag_value", &["-k", "-m", "server", "auto"]));
    v.push(Spec::tool("opt_genkey_not_first", &["-d", "genkey", "x.key"]));
    v.push(Spec::tool("opt_genkey_after_key", &["-k", "vpn.key", "genkey"]).keyed());

    let modes: [(&str, &[&str]); 12] = [
        ("mode_server_exact", &["server", "auto"]),
        ("mode_server_capitalized", &["Server", "auto"]),
        ("mode_server_upper", &["SERVER", "192.0.2.10"]),
        ("mode_server_prefix", &["servers", "192.0.2.10"]),
        ("mode_server_suffix_space", &["server ", "192.0.2.10"]),
        ("mode_client_exact", &["client", "192.0.2.10"]),
        ("mode_client_any_word", &["whatever", "192.0.2.10"]),
        ("mode_empty_word", &["", "192.0.2.10"]),
        ("mode_client_no_server", &["client"]),
        ("mode_client_auto_server", &["client", "auto"]),
        ("mode_server_only", &["server"]),
        ("mode_extra_args", &["server", "auto", "auto", "auto", "auto", "auto", "auto", "extra", "more"]),
    ];
    for (name, argv) in modes {
        let spec = Spec::tool(name, argv);
        v.push(if argv.contains(&"192.0.2.10") { spec.end(5000) } else { spec });
    }

    v.push(Spec::tool(
        "args_server_all_custom",
        &["server", "auto", "5000", "tunx", "10.1.1.1", "10.1.1.2", "198.51.100.7"],
    ));
    v.push(Spec::tool(
        "args_client_all_custom",
        &["client", "192.0.2.10", "5555", "tuny", "10.8.0.2", "10.8.0.1", "198.51.100.1"],
    ));
    v.push(Spec::tool("args_client_all_auto", &["client", "192.0.2.10", "auto", "auto", "auto", "auto", "auto"]));
    v.push(Spec::tool("args_server_all_auto", &["server", "auto", "auto", "auto", "auto", "auto", "auto"]));
    v.push(Spec::tool("args_server_explicit_bind", &["server", "10.1.2.3", "5000"]));
    v.push(Spec::tool("args_server_bind_ipv6", &["server", "2001:db8::5", "5000"]));
    v.push(Spec::tool("args_client_ipv6_server", &["client", "2001:db8::1", "5000"]).end(5000));
    v.push(Spec::tool("args_server_named_multi_address", &["server", "multi.example.test"]).dns("multi.example.test", "192.0.2.9,2001:db8::9"));
    v.push(Spec::tool("args_client_named_ipv6_first", &["client", "v6.example.test"]).dns("v6.example.test", "2001:db8::7,192.0.2.7").end(5000));
    v.push(Spec::tool("args_server_bad_port", &["server", "auto", "notaport"]));
    v.push(Spec::tool("args_server_port_zero", &["server", "auto", "0"]));
    v.push(Spec::tool("args_server_port_65535", &["server", "auto", "65535"]));
    v.push(Spec::tool("args_server_port_65536", &["server", "auto", "65536"]));
    v.push(Spec::tool("args_client_bad_port", &["client", "192.0.2.10", "70000"]).end_signal("none"));
    v.push(Spec::tool("args_server_long_ifname", &["server", "auto", "auto", "averyveryverylongtunnelname"]));
    v.push(Spec::tool("args_server_ifname_pattern", &["server", "auto", "auto", "tun%d"]).set("tun_name", json!("tun7")));
    v.push(Spec::tool("args_server_tun_ip_with_space", &["server", "auto", "auto", "auto", "10.1.1.1 extra", "10.1.1.2"]));
    v.push(Spec::tool("args_server_tun_ip_ipv6", &["server", "auto", "auto", "auto", "fd00::1", "fd00::2"]));
    v.push(Spec::tool("args_server_subst_token_in_arg", &["server", "auto", "auto", "auto", "$IF_NAME", "$EXT_PORT"]));
    v.push(Spec::tool("args_client_subst_token_gateway", &["client", "192.0.2.10", "auto", "auto", "auto", "auto", "$EXT_IP"]).end(5000));
    let long_ip = "1".repeat(5000);
    v.push(Spec::tool("args_server_overlong_tun_ip", &["server", "auto", "auto", "auto", &long_ip, "10.1.1.2"]));
    let long_ip6 = "9".repeat(60);
    v.push(Spec::tool("args_server_tun_ip_truncates_ip6", &["server", "auto", "auto", "auto", &long_ip6, "10.1.1.2"]));

    v.push(Spec::tool("dns_resolve_again", &["client", "again.example.test"]).dns("again.example.test", "EAI_AGAIN"));
    v.push(Spec::tool("dns_resolve_fail", &["server", "fail.example.test"]).dns("fail.example.test", "EAI_FAIL"));
    v.push(Spec::tool("dns_resolve_noname_server", &["server", "nosuch.invalid"]));
    v.push(Spec::tool("dns_numeric_service_fails_flag", &["client", "192.0.2.10"]).err(rule_err("getnameinfo", None, 1, 1, "EAI_FAIL")));
    v.push(Spec::tool("dns_getaddrinfo_system_error", &["client", "192.0.2.10"]).err(rule_err("getaddrinfo", None, 1, 1, "EAI_SYSTEM")));

    for (tag, len) in [("empty", 0usize), ("short31", 31), ("exact32", 32), ("trailing_8", 40), ("trailing_1000", 1032)] {
        let file = if len <= 32 { pattern(len, 0) } else { format!("{}{}", &KEY, pattern(len - 32, 0xf0)) };
        let mut s = Spec::tool(&format!("key_file_{tag}"), &["-k", "vpn.key", "server", "auto"]).prefix(PREFIX).files("vpn.key", &file);
        if len >= 32 {
            s = s.set("key", json!(&file[..64])).udp(100, 1).udp(110, 2).tun(200, &pl(1));
        }
        v.push(s);
    }
    v.push(
        Spec::tool("key_file_trailing_ignored_wire", &["-k", "vpn.key", "client", "192.0.2.10"])
            .prefix(PREFIX)
            .set("key", json!(KEY))
            .files("vpn.key", &format!("{KEY}ffffffffffffffffffffffffffffffff"))
            .tun(100, &pl(1))
            .udp(200, 1)
            .tun(300, &pl(2)),
    );
    v.push(
        Spec::tool("key_file_all_zero_keyed", &["-k", "vpn.key", "server", "auto"])
            .prefix(PREFIX)
            .set("key", json!("00".repeat(32)))
            .files("vpn.key", &"00".repeat(32))
            .udp(100, 1)
            .tun(200, &pl(1)),
    );
    v.push(Spec::tool("key_file_banner_keyed_client", &["-k", "vpn.key", "client", "192.0.2.10"]).keyed());

    v.push(Spec::tool("genkey_alias", &["generate-key", "g.key"]).normalize(&["generated-key"]));
    v.push(Spec::tool("genkey_default_path", &["genkey"]).normalize(&["generated-key"]));
    v.push(Spec::tool("genkey_extra_args_ignored", &["genkey", "g.key", "other.key", "-d"]).normalize(&["generated-key"]));
    v.push(Spec::tool("genkey_existing_refused", &["genkey", "have.key"]).files("have.key", "aa"));
    v.push(Spec::tool("genkey_existing_default_refused", &["genkey"]).files("vpn.key", &KEY));
    v.push(Spec::tool("genkey_missing_directory", &["genkey", "nodir/g.key"]));
    v.push(Spec::tool("genkey_deterministic_bytes", &["genkey", "d.key"]).prefix(&pattern(32, 0x40)));
    v.push(Spec::tool("genkey_urandom_open_fails", &["genkey", "g.key"]).err(rule_err("open", Some("urandom"), 1, 1, "EACCES")));
    v.push(Spec::tool("genkey_urandom_read_fails", &["genkey", "g.key"]).err(rule_err("read", Some("urandom"), 1, 1, "EIO")));
    v.push(Spec::tool("genkey_urandom_short_read", &["genkey", "g.key"]).err(rule_short("read", "urandom", 1, 1, 7)).normalize(&["generated-key"]));
    v.push(Spec::tool("genkey_urandom_eintr", &["genkey", "g.key"]).err(rule_err("read", Some("urandom"), 1, 1, "EINTR")));
    v.push(Spec::tool("genkey_then_use_not_run", &["genkey", "dir/../g.key"]).normalize(&["generated-key"]));
    v.push(Spec::tool("genkey_as_flag_value", &["genkey", "-k"]).normalize(&["generated-key"]));

    v
}
