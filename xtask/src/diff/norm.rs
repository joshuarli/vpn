use crate::util::{self, Result};
use serde_json::Value;

const STRERROR: &[&str] = &[
    "Operation not permitted",
    "No such file or directory",
    "Interrupted system call",
    "Input/output error",
    "Bad file descriptor",
    "Resource temporarily unavailable",
    "Cannot allocate memory",
    "Permission denied",
    "No such device",
    "Invalid argument",
    "Too many open files",
    "Inappropriate ioctl for device",
    "No space left on device",
    "Broken pipe",
    "Message too long",
    "Destination address required",
    "Address already in use",
    "Network is down",
    "Network is unreachable",
    "No buffer space available",
    "Transport endpoint is not connected",
    "Connection refused",
    "No route to host",
    "Protocol error",
];

const GAI_STRERROR: &[&str] = &[
    "Name or service not known",
    "Temporary failure in name resolution",
    "Non-recoverable failure in name resolution",
    "Servname not supported for ai_socktype",
    "Address family for hostname not supported",
    "Memory allocation failure",
    "System error",
    "Argument buffer overflow",
];

const OS_ERROR_MASK: &str = "<os-error>";

pub fn known_ids() -> Result<Vec<String>> {
    let text = util::read(&util::repo_root().join("compat/normalizations.json"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("compat/normalizations.json: {e}"))?;
    Ok(v.as_array()
        .ok_or("compat/normalizations.json is not an array")?
        .iter()
        .filter_map(|e| e.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect())
}

pub fn validate(ids: &[String]) -> Result<()> {
    let known = known_ids()?;
    for id in ids {
        if !known.contains(id) {
            return Err(format!("normalization `{id}` is not listed in compat/normalizations.json"));
        }
    }
    Ok(())
}

pub fn apply(ids: &[String], events: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = events.to_vec();
    for id in ids {
        match id.as_str() {
            "startup-random" => startup_random(&mut out),
            "generated-key" => generated_key(&mut out),
            "interface-name" => interface_name(&mut out),
            "os-error-text" => os_error_text(&mut out),
            "pid" => pid(&mut out),
            _ => {}
        }
    }
    out
}

fn startup_random(events: &mut [Value]) {
    for e in events {
        if e["ev"] == "udp_out" {
            let raw_len = e["raw"].as_str().map_or(0, |s| s.len() / 2);
            e["random"] = Value::from("<random>");
            e["raw"] = Value::from(format!("<derived:{raw_len}>"));
        }
    }
}

fn generated_key(events: &mut [Value]) {
    for e in events {
        if e["ev"] == "file" && e["hex"].as_str().is_some_and(|h| h.len() == 64) {
            e["hex"] = Value::from("<key>");
        }
    }
}

fn walk_strings(v: &mut Value, f: &dyn Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| walk_strings(x, f)),
        Value::Object(o) => o.values_mut().for_each(|x| walk_strings(x, f)),
        _ => {}
    }
}

fn interface_name(events: &mut [Value]) {
    let assigned = events
        .iter()
        .find(|e| e["ev"] == "ioctl" && e["req"] == "SIOCSIFMTU")
        .and_then(|e| e["ifname"].as_str().map(str::to_owned));
    let Some(name) = assigned.filter(|n| !n.is_empty()) else { return };
    for e in events.iter_mut() {
        if e["ev"] == "ioctl" && e["req"] == "TUNSETIFF" {
            continue;
        }
        walk_strings(e, &|s| s.replace(&name, "<ifname>"));
    }
}

fn mask_line(line: &str) -> String {
    for text in STRERROR {
        if let Some(prefix) = line.strip_suffix(text) {
            if prefix.ends_with(": ") {
                return format!("{prefix}{OS_ERROR_MASK}");
            }
        }
    }
    for text in GAI_STRERROR {
        let bracketed = format!("[{text}]");
        if let Some(prefix) = line.strip_suffix(&bracketed) {
            if prefix.ends_with(": ") {
                return format!("{prefix}[{OS_ERROR_MASK}]");
            }
        }
    }
    line.to_owned()
}

fn os_error_text(events: &mut [Value]) {
    for e in events {
        let is_stream = e["ev"] == "stdout" || e["ev"] == "stderr";
        if !is_stream {
            continue;
        }
        if let Some(t) = e["text"].as_str() {
            let masked: Vec<String> = t.split('\n').map(mask_line).collect();
            e["text"] = Value::from(masked.join("\n"));
        }
    }
}

fn pid(events: &mut [Value]) {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    if k == "pid" {
                        *x = Value::from(0);
                    } else {
                        walk(x);
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(walk),
            _ => {}
        }
    }
    events.iter_mut().for_each(walk);
}
