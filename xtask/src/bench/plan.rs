use crate::lab::topology::LAB;
use serde_json::{Map, Value, json};

pub const ENDPOINTS: [&str; 3] = ["client", "server", "combined"];

fn arm(built: &Value, which: &str) -> Value {
    let a = &built[which];
    json!({
        "candidate": which,
        "twice": a["twice"],
        "crypto_bench": a["crypto_bench"],
        "crypto_bench_unavailable": a["crypto_bench_unavailable"],
        "packet_bench": a["packet_bench"],
        "packet_bench_unavailable": a["packet_bench_unavailable"],
        "twice_build_error": a["twice_build_error"],
    })
}

fn tunnel_units(layer: &mut Value) {
    let phases = layer["phases"].clone();
    let Some(sessions) = layer["sessions"].as_array_mut() else { return };
    for session in sessions {
        let mut units = Vec::new();
        for step in session["steps"].as_array().cloned().unwrap_or_default() {
            let phase = step["phase"].as_str().unwrap_or_default();
            units.push(json!({
                "unit": format!("tunnel/{}/{}", step["label"].as_str().unwrap_or_default(), phase),
                "metrics": phases[phase]["metrics"],
            }));
        }
        session["units"] = Value::Array(units);
    }
}

fn memory_units(layer: &mut Value) {
    let phase_metrics = layer["phase_metrics"].clone();
    let Some(sessions) = layer["sessions"].as_array_mut() else { return };
    for session in sessions {
        let id = session["id"].as_str().unwrap_or_default().to_owned();
        let mut units = Vec::new();
        for endpoint in ENDPOINTS {
            for phase in session["phases"].as_array().cloned().unwrap_or_default() {
                let phase = phase.as_str().unwrap_or_default();
                units.push(json!({
                    "unit": format!("memory/{id}/{endpoint}/{phase}"),
                    "metrics": phase_metrics[phase],
                }));
            }
        }
        session["units"] = Value::Array(units);
    }
}

pub fn expected_units(layer_name: &str, layer: &Value) -> Vec<(String, Vec<String>)> {
    let strings = |v: &Value| -> Vec<String> {
        v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_default()
    };
    let mut out = Vec::new();
    match layer_name {
        "crypto" => {
            for op in strings(&layer["ops"]) {
                for size in layer["sizes"].as_array().cloned().unwrap_or_default() {
                    out.push((format!("crypto/{op}/{}", size.as_u64().unwrap_or(0)), vec!["ns_per_op".to_owned()]));
                }
            }
        }
        "packet" => {
            for sc in layer["scenarios"].as_array().cloned().unwrap_or_default() {
                let metrics = ["ns_per_packet", "alloc_count", "alloc_bytes", "retained_kb"].map(str::to_owned).to_vec();
                out.push((format!("packet/{}", sc["name"].as_str().unwrap_or_default()), metrics));
            }
        }
        _ => {
            for session in layer["sessions"].as_array().cloned().unwrap_or_default() {
                for unit in session["units"].as_array().cloned().unwrap_or_default() {
                    out.push((unit["unit"].as_str().unwrap_or_default().to_owned(), strings(&unit["metrics"])));
                }
            }
        }
    }
    out
}

pub fn build(manifest: &Value, suite: &str, layers: &[String], pairs: Option<u32>, seed: Option<u64>, built: &Value) -> Result<Value, String> {
    let spec = manifest.pointer(&format!("/suites/{suite}")).ok_or_else(|| format!("manifest has no suite `{suite}`"))?;
    let mut plan_layers = Map::new();
    for name in layers {
        let mut layer = spec["layers"][name.as_str()].clone();
        if layer.is_null() {
            return Err(format!("suite {suite} has no layer {name}"));
        }
        if let Some(p) = pairs {
            layer["pairs"] = json!(p);
        }
        match name.as_str() {
            "tunnel" => tunnel_units(&mut layer),
            "memory" => memory_units(&mut layer),
            _ => {}
        }
        plan_layers.insert(name.clone(), layer);
    }
    let mut setups = Map::new();
    for layer in plan_layers.values() {
        for session in layer["sessions"].as_array().cloned().unwrap_or_default() {
            let mtu = session["veth_mtu"].as_u64().unwrap_or(1500) as u32;
            setups.insert(mtu.to_string(), json!(LAB.setup_script(mtu)));
        }
    }
    let mut netem = Map::new();
    for (name, spec) in manifest["impairments"].as_object().ok_or("manifest has no impairments")? {
        netem.insert(name.clone(), json!(LAB.netem_script(spec.as_str().unwrap_or_default())));
    }
    Ok(json!({
        "suite": suite,
        "seed": seed.unwrap_or_else(|| spec["seed"].as_u64().unwrap_or(1)),
        "arms": {"baseline": arm(built, "baseline_ref"), "candidate": arm(built, "candidate_ref")},
        "tools": {"udpprobe": built["udpprobe"]},
        "metric_defs": manifest["metric_defs"],
        "layers": plan_layers,
        "topology": {
            "setup": setups,
            "teardown": LAB.teardown_script(),
            "clear_netem": LAB.clear_netem_script(),
            "netem": netem,
        },
        "clean_exit_codes": [0],
    }))
}
