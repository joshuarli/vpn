use serde_json::{Map, Value, json};

pub const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub const RA: &str = "a1a2a3a4a5a6a7a8";
pub const RB: &str = "b1b2b3b4b5b6b7b8";
pub const PREFIX: &str = "0102030405060708";
pub const SRV_PEER: &str = "10.9.0.2:41194";
pub const CLI_PEER: &str = "192.0.2.10:41194";
pub const MAGIC: &str = "ffffffffffffffff";

pub fn hx(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn pl(k: u64) -> String {
    format!("45000014000100004001{:04x}c0a80001c0a800fe", k & 0xffff)
}

pub fn pattern(n: usize, salt: u8) -> String {
    hx(&(0..n).map(|i| (i as u8).wrapping_mul(7).wrapping_add(salt)).collect::<Vec<_>>())
}

fn name_seed(name: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in name.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x100000001b3);
    }
    h % 1_000_000
}

#[derive(Clone)]
pub struct Spec {
    pub name: String,
    pub header: Map<String, Value>,
    pub inputs: Vec<(u64, Value)>,
}

impl Spec {
    pub fn new(name: &str, role: &str, argv: &[&str]) -> Spec {
        let mut header = Map::new();
        header.insert("name".into(), json!(name));
        header.insert("role".into(), json!(role));
        header.insert("argv".into(), json!(argv));
        header.insert("seed".into(), json!(name_seed(name)));
        Spec { name: name.to_owned(), header, inputs: Vec::new() }
    }

    pub fn server(name: &str) -> Spec {
        Spec::new(name, "server", &["-k", "vpn.key", "server", "auto"]).keyed().prefix(PREFIX)
    }

    pub fn server_nokey(name: &str) -> Spec {
        Spec::new(name, "server", &["server", "auto"]).prefix(PREFIX)
    }

    pub fn client(name: &str) -> Spec {
        Spec::new(name, "client", &["-k", "vpn.key", "client", "192.0.2.10"]).keyed().prefix(PREFIX)
    }

    pub fn client_nokey(name: &str) -> Spec {
        Spec::new(name, "client", &["client", "192.0.2.10"]).prefix(PREFIX)
    }

    pub fn tool(name: &str, argv: &[&str]) -> Spec {
        Spec::new(name, "tool", argv)
    }

    pub fn keyed(self) -> Spec {
        self.with_key(KEY, KEY)
    }

    pub fn with_key(mut self, key: &str, file: &str) -> Spec {
        self.header.insert("key".into(), json!(key));
        self.files("vpn.key", file)
    }

    pub fn files(mut self, path: &str, hex: &str) -> Spec {
        let files = self.header.entry("files").or_insert_with(|| json!({}));
        files[path] = json!(hex);
        self
    }

    pub fn argv(mut self, argv: &[&str]) -> Spec {
        self.header.insert("argv".into(), json!(argv));
        self
    }

    pub fn prefix(self, hex: &str) -> Spec {
        self.set("urandom_prefix", json!(hex))
    }

    pub fn set(mut self, key: &str, value: Value) -> Spec {
        self.header.insert(key.to_owned(), value);
        self
    }

    pub fn end(self, ms: u64) -> Spec {
        self.set("end_ms", json!(ms))
    }

    pub fn end_signal(self, name: &str) -> Spec {
        self.set("end_signal", json!(name))
    }

    pub fn normalize(self, ids: &[&str]) -> Spec {
        self.set("normalize", json!(ids))
    }

    pub fn dns(mut self, name: &str, value: &str) -> Spec {
        let dns = self.header.entry("dns").or_insert_with(|| json!({}));
        dns[name] = json!(value);
        self
    }

    pub fn err(mut self, rule: Value) -> Spec {
        let errors = self.header.entry("errors").or_insert_with(|| json!([]));
        errors.as_array_mut().expect("errors is an array").push(rule);
        self
    }

    pub fn cmd(mut self, rule: Value) -> Spec {
        let cmds = self.header.entry("cmds").or_insert_with(|| json!([]));
        cmds.as_array_mut().expect("cmds is an array").push(rule);
        self
    }

    pub fn peer(&self) -> &'static str {
        let serves = self
            .header
            .get("argv")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|x| x == "server"));
        if serves { SRV_PEER } else { CLI_PEER }
    }

    pub fn push(mut self, t: u64, v: Value) -> Spec {
        self.inputs.push((t, v));
        self
    }

    pub fn udp(self, t: u64, counter: u64) -> Spec {
        self.udp_full(t, None, RA, counter, &pl(counter), "valid")
    }

    pub fn udps(mut self, start: u64, step: u64, counters: &[u64]) -> Spec {
        for (i, c) in counters.iter().enumerate() {
            self = self.udp(start + step * i as u64, *c);
        }
        self
    }

    pub fn udp_r(self, t: u64, random: &str, counter: u64) -> Spec {
        self.udp_full(t, None, random, counter, &pl(counter), "valid")
    }

    pub fn udp_a(self, t: u64, counter: u64, auth: &str) -> Spec {
        self.udp_full(t, None, RA, counter, &pl(counter), auth)
    }

    pub fn udp_from(self, t: u64, from: &str, counter: u64) -> Spec {
        self.udp_full(t, Some(from), RA, counter, &pl(counter), "valid")
    }

    pub fn udp_p(self, t: u64, counter: u64, payload: &str) -> Spec {
        self.udp_full(t, None, RA, counter, payload, "valid")
    }

    pub fn udp_full(self, t: u64, from: Option<&str>, random: &str, counter: u64, payload: &str, auth: &str) -> Spec {
        let from = from.unwrap_or_else(|| self.peer()).to_owned();
        self.push(
            t,
            json!({"udp_in": {"from": from, "random": random, "counter": counter, "payload": payload, "auth": auth}}),
        )
    }

    pub fn raw(self, t: u64, hex: &str) -> Spec {
        let from = self.peer();
        self.raw_from(t, from, hex)
    }

    pub fn raw_from(self, t: u64, from: &str, hex: &str) -> Spec {
        self.push(
            t,
            json!({"udp_in": {"from": from, "random": RA, "counter": 0, "payload": "", "auth": format!("raw:{hex}")}}),
        )
    }

    pub fn tun(self, t: u64, hex: &str) -> Spec {
        self.push(t, json!({"tun_in": hex}))
    }

    pub fn tun_k(self, t: u64, k: u64) -> Spec {
        self.tun(t, &pl(k))
    }

    pub fn sig(self, t: u64, name: &str) -> Spec {
        self.push(t, json!({"signal": name}))
    }

    pub fn perr(self, t: u64, fd: &str, revents: &[&str]) -> Spec {
        self.push(t, json!({"poll_err": {"fd": fd, "revents": revents}}))
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&json!({"case": Value::Object(self.header.clone())}).to_string());
        out.push('\n');
        for (t, v) in &self.inputs {
            let mut m = Map::new();
            m.insert("t_ms".into(), json!(t));
            if let Value::Object(o) = v {
                for (k, x) in o {
                    m.insert(k.clone(), x.clone());
                }
            }
            out.push_str(&Value::Object(m).to_string());
            out.push('\n');
        }
        out
    }
}

pub fn rule_err(call: &str, fd: Option<&str>, nth: u32, count: u32, errno: &str) -> Value {
    let mut v = json!({"call": call, "nth": nth, "count": count, "errno": errno});
    if let Some(fd) = fd {
        v["fd"] = json!(fd);
    }
    v
}

pub fn rule_short(call: &str, fd: &str, nth: u32, count: u32, short: i64) -> Value {
    json!({"call": call, "fd": fd, "nth": nth, "count": count, "short": short})
}

pub fn rule_exec(pattern: &str, from: u32, to: u32, status: i32) -> Value {
    json!({"kind": "exec", "match": pattern, "from": from, "to": to, "status": status})
}

pub fn rule_popen(pattern: &str, from: u32, to: u32, stdout: &str) -> Value {
    json!({"kind": "popen", "match": pattern, "from": from, "to": to, "stdout": stdout})
}
