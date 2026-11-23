use crate::util::{self, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub role: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    pub seed: u64,
    #[serde(default)]
    pub urandom_prefix: Option<String>,
    #[serde(default)]
    pub end_ms: Option<u64>,
    #[serde(default)]
    pub end_signal: Option<String>,
    #[serde(default)]
    pub hang_ms: Option<u64>,
    #[serde(default)]
    pub tun_name: Option<String>,
    #[serde(default)]
    pub passive: Option<String>,
    #[serde(default)]
    pub dns: BTreeMap<String, String>,
    #[serde(default)]
    pub cmds: Vec<CmdRule>,
    #[serde(default)]
    pub errors: Vec<ErrRule>,
    #[serde(default)]
    pub normalize: Vec<String>,
    #[serde(default)]
    pub calls: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CmdRule {
    #[serde(default = "any_kind")]
    pub kind: String,
    #[serde(default, rename = "match")]
    pub pattern: Option<String>,
    #[serde(default = "one")]
    pub from: u32,
    #[serde(default)]
    pub to: u32,
    #[serde(default)]
    pub status: i32,
    #[serde(default)]
    pub signal: u32,
    #[serde(default)]
    pub stdout: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ErrRule {
    pub call: String,
    #[serde(default)]
    pub fd: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "one")]
    pub nth: u32,
    #[serde(default = "one")]
    pub count: u32,
    #[serde(default)]
    pub errno: Option<String>,
    #[serde(default)]
    pub short: Option<i64>,
}

fn any_kind() -> String {
    "any".to_owned()
}

fn one() -> u32 {
    1
}

fn valid_auth() -> String {
    "valid".to_owned()
}

fn zero_random() -> String {
    "0000000000000000".to_owned()
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct UdpIn {
    pub from: String,
    #[serde(default = "zero_random")]
    pub random: String,
    #[serde(default)]
    pub counter: u64,
    #[serde(default)]
    pub payload: String,
    #[serde(default = "valid_auth")]
    pub auth: String,
}

#[derive(Clone, Debug)]
pub enum Kind {
    UdpIn(UdpIn),
    TunIn(String),
    Signal(String),
    PollErr { fd: String, revents: Vec<String> },
}

#[derive(Clone, Debug)]
pub struct Input {
    pub t_ms: u64,
    pub kind: Kind,
    pub line: String,
}

#[derive(Clone, Debug)]
pub struct Case {
    pub path: PathBuf,
    pub header: Header,
    pub header_line: String,
    pub inputs: Vec<Input>,
    pub expected: Vec<Value>,
}

pub fn cases_dir() -> PathBuf {
    util::repo_root().join("oracle/cases")
}

pub fn resolve(name: &str) -> PathBuf {
    let direct = Path::new(name);
    if name.ends_with(".jsonl") && direct.is_file() {
        return direct.to_path_buf();
    }
    let top = cases_dir().join(format!("{name}.jsonl"));
    let minimized = cases_dir().join("minimized").join(format!("{name}.jsonl"));
    if !top.is_file() && minimized.is_file() { minimized } else { top }
}

pub fn all_paths() -> Result<Vec<PathBuf>> {
    let dir = cases_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "jsonl") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn parse_input(line: &str, value: &Value) -> Result<Input> {
    let obj = value.as_object().ok_or("input line is not an object")?;
    let t_ms = obj
        .get("t_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("input line lacks integer t_ms: {line}"))?;
    let mut found = None;
    for (k, v) in obj {
        if k == "t_ms" {
            continue;
        }
        if found.is_some() {
            return Err(format!("input line has more than one event: {line}"));
        }
        let kind = match k.as_str() {
            "udp_in" => Kind::UdpIn(serde_json::from_value(v.clone()).map_err(|e| format!("udp_in: {e}: {line}"))?),
            "tun_in" => Kind::TunIn(v.as_str().ok_or("tun_in must be a hex string")?.to_owned()),
            "signal" => Kind::Signal(v.as_str().ok_or("signal must be a name")?.to_owned()),
            "poll_err" => {
                let fd = v.get("fd").and_then(Value::as_str).ok_or("poll_err needs fd")?.to_owned();
                let revents = v
                    .get("revents")
                    .and_then(Value::as_array)
                    .ok_or("poll_err needs revents")?
                    .iter()
                    .map(|x| x.as_str().map(str::to_owned).ok_or("revents entries are strings"))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Kind::PollErr { fd, revents }
            }
            other => return Err(format!("unknown input event `{other}`: {line}")),
        };
        found = Some(kind);
    }
    let kind = found.ok_or_else(|| format!("input line has no event: {line}"))?;
    Ok(Input { t_ms, kind, line: line.to_owned() })
}

impl Case {
    pub fn load(path: &Path) -> Result<Case> {
        let text = util::read(path)?;
        let mut header = None;
        let mut inputs = Vec::new();
        let mut expected = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value =
                serde_json::from_str(line).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?;
            if let Some(h) = value.get("case") {
                if header.is_some() {
                    return Err(format!("{}:{}: second header", path.display(), n + 1));
                }
                let h: Header = serde_json::from_value(h.clone())
                    .map_err(|e| format!("{}:{}: header: {e}", path.display(), n + 1))?;
                header = Some((h, line.to_owned()));
            } else if value.get("ev").is_some() {
                expected.push(value);
            } else {
                inputs.push(parse_input(line, &value).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?);
            }
        }
        let (header, header_line) = header.ok_or_else(|| format!("{}: no header line", path.display()))?;
        Ok(Case { path: path.to_path_buf(), header, header_line, inputs, expected })
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.header_line);
        out.push('\n');
        for input in &self.inputs {
            out.push_str(&input.line);
            out.push('\n');
        }
        for ev in &self.expected {
            out.push_str(&serde_json::to_string(ev).expect("events serialize"));
            out.push('\n');
        }
        out
    }

    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        std::fs::write(&self.path, self.render()).map_err(|e| format!("write {}: {e}", self.path.display()))
    }

    pub fn with_inputs(&self, keep: &[usize]) -> Case {
        let mut c = self.clone();
        c.inputs = keep.iter().map(|&i| self.inputs[i].clone()).collect();
        c
    }
}
