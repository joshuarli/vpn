use serde_json::Value;

pub struct Mismatch {
    pub report: String,
}

fn short(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    if s.len() > 400 { format!("{}...", &s[..400]) } else { s }
}

pub fn compare(expected: &[Value], actual: &[Value]) -> Option<Mismatch> {
    let n = expected.len().max(actual.len());
    for i in 0..n {
        let (e, a) = (expected.get(i), actual.get(i));
        if e == a {
            continue;
        }
        let mut report = format!("first difference at event {i} (expected {} events, actual {})\n", expected.len(), actual.len());
        report.push_str(&format!("  expected: {}\n", e.map_or("<none>".to_owned(), short)));
        report.push_str(&format!("  actual:   {}\n", a.map_or("<none>".to_owned(), short)));
        if let (Some(e), Some(a)) = (e, a) {
            if e["ev"] == a["ev"] && (e["ev"] == "stdout" || e["ev"] == "stderr") {
                report.push_str(&format!(
                    "  {} expected text: {:?}\n  {} actual text:   {:?}\n",
                    e["ev"].as_str().unwrap_or(""),
                    e["text"],
                    a["ev"].as_str().unwrap_or(""),
                    a["text"]
                ));
            }
        }
        return Some(Mismatch { report });
    }
    None
}

pub fn contains_text(events: &[Value], needle: &str) -> bool {
    events.iter().any(|e| serde_json::to_string(e).is_ok_and(|s| s.contains(&needle.replace('"', "\\\""))) || e["text"].as_str().is_some_and(|t| t.contains(needle)))
}
