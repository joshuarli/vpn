mod case;
mod compare;
mod minimize;
mod norm;
mod run;
mod script;

use crate::util::Result;
use case::Case;
use run::{Impl, Job};
use serde_json::Value;

const BAD_EVENTS: &[&str] = &["shim_error", "hang", "unvirtualized"];

struct Opts {
    mode: Mode,
    impls: Option<Vec<Impl>>,
    calls: bool,
    contains: Option<String>,
    against: Option<Impl>,
}

enum Mode {
    SelfCheck,
    Record(Vec<String>),
    Case(String),
    All,
    Minimize(String),
    MutationCheck,
    Ledger,
}

const USAGE: &str = "usage: cargo xtask diff <mode> [options]

modes:
  --self-check              replay twice, detect altered expectations, check ddmin and normalizers
  --record <case>... | --record --all
                            run the C oracle and write the golden expected events into the case file
  --case <name>             replay one case
  --all                     replay every oracle/cases/*.jsonl
  --minimize <case>         delta-debug input events down to a minimal disagreement
  --mutation-check          reserved for lane D1
  --ledger                  reserved for lane X1

options:
  --impl c|rust|both        implementations to replay (default both; minimize subject default rust)
  --calls                   record verbose libc call events (poll, close, fork) as well
  --contains <text>         minimize: keep the trace while the subject's output contains <text>
  --against c|rust          minimize: reference implementation (default c)";

fn parse_impl(s: &str) -> Result<Vec<Impl>> {
    match s {
        "c" => Ok(vec![Impl::C]),
        "rust" => Ok(vec![Impl::Rust]),
        "both" => Ok(vec![Impl::C, Impl::Rust]),
        other => Err(format!("--impl expects c|rust|both, got {other}")),
    }
}

fn parse(args: &[String]) -> Result<Opts> {
    let mut mode = None;
    let mut opts = Opts { mode: Mode::All, impls: None, calls: false, contains: None, against: None };
    let mut i = 0;
    let mut record_names: Vec<String> = Vec::new();
    let mut record_all = false;
    let mut recording = false;
    let value = |i: &mut usize, flag: &str| -> Result<String> {
        *i += 1;
        args.get(*i).cloned().ok_or_else(|| format!("{flag} needs a value"))
    };
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--self-check" => mode = Some(Mode::SelfCheck),
            "--all" if recording => record_all = true,
            "--all" => mode = Some(Mode::All),
            "--record" => {
                recording = true;
                mode = Some(Mode::Record(Vec::new()));
            }
            "--case" => mode = Some(Mode::Case(value(&mut i, a)?)),
            "--minimize" => mode = Some(Mode::Minimize(value(&mut i, a)?)),
            "--mutation-check" => mode = Some(Mode::MutationCheck),
            "--ledger" => mode = Some(Mode::Ledger),
            "--impl" => opts.impls = Some(parse_impl(&value(&mut i, a)?)?),
            "--calls" => opts.calls = true,
            "--contains" => opts.contains = Some(value(&mut i, a)?),
            "--against" => opts.against = Some(parse_impl(&value(&mut i, a)?)?[0]),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other if recording && !other.starts_with("--") => record_names.push(other.to_owned()),
            other => return Err(format!("unexpected argument `{other}`\n\n{USAGE}")),
        }
        i += 1;
    }
    opts.mode = match mode {
        Some(Mode::Record(_)) => {
            if record_all {
                Mode::Record(Vec::new())
            } else if record_names.is_empty() {
                return Err("--record needs case names or --all".to_owned());
            } else {
                Mode::Record(record_names)
            }
        }
        Some(m) => m,
        None => return Err(USAGE.to_owned()),
    };
    Ok(opts)
}

pub fn run(args: &[String]) -> Result<()> {
    let opts = parse(args)?;
    match &opts.mode {
        Mode::SelfCheck => selfcheck(&opts),
        Mode::Record(names) => record(names, &opts),
        Mode::Case(name) => replay(vec![Case::load(&case::resolve(name))?], &opts),
        Mode::All => {
            let cases = case::all_paths()?.iter().map(|p| Case::load(p)).collect::<Result<Vec<_>>>()?;
            replay(cases, &opts)
        }
        Mode::Minimize(name) => minimize_case(name, &opts),
        Mode::MutationCheck => Err("--mutation-check is reserved for lane D1".to_owned()),
        Mode::Ledger => Err("--ledger is reserved for lane X1".to_owned()),
    }
}

fn health(events: &[Value]) -> Option<String> {
    for e in events {
        let ev = e["ev"].as_str().unwrap_or("");
        if BAD_EVENTS.contains(&ev) {
            return Some(format!("shim reported {ev}: {}", serde_json::to_string(e).unwrap_or_default()));
        }
        if ev == "exit" && (e["timeout"] == true || e.get("spawn_error").is_some()) {
            return Some(format!("abnormal run: {}", serde_json::to_string(e).unwrap_or_default()));
        }
    }
    None
}

fn record(names: &[String], opts: &Opts) -> Result<()> {
    let mut cases = if names.is_empty() {
        case::all_paths()?.iter().map(|p| Case::load(p)).collect::<Result<Vec<_>>>()?
    } else {
        names.iter().map(|n| Case::load(&case::resolve(n))).collect::<Result<Vec<_>>>()?
    };
    let jobs = cases.iter().map(|c| Job::new(Impl::C, c, opts.calls)).collect::<Result<Vec<_>>>()?;
    let outs = run::run_batch(&jobs)?;
    for (c, events) in cases.iter_mut().zip(outs) {
        norm::validate(&c.header.normalize)?;
        if let Some(problem) = health(&events) {
            return Err(format!("{}: refusing to record: {problem}", c.header.name));
        }
        println!("recorded {} ({} events)", c.header.name, events.len());
        c.expected = events;
        c.save()?;
    }
    Ok(())
}

pub struct Outcome {
    pub case: String,
    pub which: Impl,
    pub ok: bool,
    pub report: String,
    pub events: usize,
}

pub fn evaluate(cases: &[Case], impls: &[Impl], calls: bool) -> Result<Vec<Outcome>> {
    let mut jobs = Vec::new();
    let mut keys = Vec::new();
    for c in cases {
        norm::validate(&c.header.normalize)?;
        for &which in impls {
            jobs.push(Job::new(which, c, calls)?);
            keys.push((c, which));
        }
    }
    let outs = run::run_batch(&jobs)?;
    let mut res = Vec::new();
    for ((c, which), events) in keys.into_iter().zip(outs) {
        let (ok, report) = if c.expected.is_empty() {
            (false, "no recorded golden events (run --record)\n".to_owned())
        } else {
            let exp = norm::apply(&c.header.normalize, &c.expected);
            let act = norm::apply(&c.header.normalize, &events);
            match compare::compare(&exp, &act) {
                None => (true, String::new()),
                Some(m) => (false, m.report),
            }
        };
        res.push(Outcome { case: c.header.name.clone(), which, ok, report, events: events.len() });
    }
    Ok(res)
}

fn replay(cases: Vec<Case>, opts: &Opts) -> Result<()> {
    let impls = opts.impls.clone().unwrap_or_else(|| vec![Impl::C, Impl::Rust]);
    let outcomes = evaluate(&cases, &impls, opts.calls)?;
    let mut failed = 0;
    for o in &outcomes {
        if o.ok {
            println!("PASS {:<5} {} ({} events)", o.which.name(), o.case, o.events);
        } else {
            failed += 1;
            println!("FAIL {:<5} {}", o.which.name(), o.case);
            for line in o.report.lines() {
                println!("       {line}");
            }
        }
    }
    println!("{} passed, {failed} failed", outcomes.len() - failed);
    if failed > 0 { Err(format!("{failed} case run(s) disagree with the recorded events")) } else { Ok(()) }
}

fn minimize_case(name: &str, opts: &Opts) -> Result<()> {
    let case = Case::load(&case::resolve(name))?;
    let subject = opts.impls.as_ref().and_then(|v| v.first().copied()).unwrap_or(if opts.contains.is_some() { Impl::C } else { Impl::Rust });
    let pred = match &opts.contains {
        Some(needle) => minimize::Predicate::Contains { subject, needle: needle.clone() },
        None => minimize::Predicate::Disagree { subject, reference: opts.against.unwrap_or(Impl::C) },
    };
    let kept = minimize::minimize(&case, &pred, opts.calls)?;
    let mut min = case.with_inputs(&kept);
    min.header.name = format!("{}.min", case.header.name);
    min.header_line = serde_json::json!({"case": min.header}).to_string();
    min.path = case::cases_dir().join("minimized").join(format!("{}.min.jsonl", case.header.name));
    min.expected = minimize::expected_for(&min)?;
    min.save()?;
    println!("minimized {} -> {} input events: {}", case.header.name, kept.len(), min.path.display());
    for i in &min.inputs {
        println!("  {}", i.line);
    }
    Ok(())
}

fn selfcheck(opts: &Opts) -> Result<()> {
    let base = Case::load(&case::resolve("server_keyed_inorder"))?;
    let seeded = {
        let mut c = Case::load(&case::resolve("client_tun_send"))?;
        c.header.normalize.clear();
        c
    };
    let mut other = seeded.clone();
    other.header.seed = other.header.seed.wrapping_add(1);
    let jobs = vec![
        Job::new(Impl::C, &base, opts.calls)?,
        Job::new(Impl::C, &base, opts.calls)?,
        Job::new(Impl::C, &seeded, opts.calls)?,
        Job::new(Impl::C, &other, opts.calls)?,
    ];
    let outs = run::run_batch(&jobs)?;
    for (i, o) in outs.iter().enumerate() {
        if let Some(p) = health(o) {
            return Err(format!("self-check run {i}: {p}"));
        }
    }
    if outs[0].len() < 8 {
        return Err(format!("self-check: base replay produced only {} events", outs[0].len()));
    }
    if let Some(m) = compare::compare(&outs[0], &outs[1]) {
        return Err(format!("self-check: two replays of {} differ\n{}", base.header.name, m.report));
    }
    println!("self-check: two replays of {} identical ({} events)", base.header.name, outs[0].len());

    let mut golden = base.clone();
    golden.expected = outs[0].clone();
    let verdict = evaluate(std::slice::from_ref(&golden), &[Impl::C], opts.calls)?;
    if !verdict[0].ok {
        return Err(format!("self-check: replay disagrees with its own recorded events\n{}", verdict[0].report));
    }
    println!("self-check: replay agrees with recorded events");
    let mut tampered = golden.clone();
    if let Some(e) = tampered.expected.iter_mut().find(|e| e["ev"] == "udp_out") {
        e["counter"] = Value::from(999);
    }
    let verdict = evaluate(std::slice::from_ref(&tampered), &[Impl::C], opts.calls)?;
    if verdict[0].ok {
        return Err("self-check: replay accepted a tampered recorded event".to_owned());
    }
    println!("self-check: tampered recorded event rejected by replay:\n{}", verdict[0].report.trim_end());

    let mut altered = outs[0].clone();
    let victim = altered
        .iter_mut()
        .find(|e| e["ev"] == "tun_out")
        .ok_or("self-check: base replay has no tun_out event to alter")?;
    let data = victim["data"].as_str().unwrap_or_default().to_owned();
    let flipped = if let Some(rest) = data.strip_prefix('0') { format!("1{rest}") } else { format!("0{}", &data[1..]) };
    victim["data"] = Value::from(flipped);
    if compare::compare(&altered, &outs[1]).is_none() {
        return Err("self-check: altered tun_out data was NOT detected".to_owned());
    }
    println!("self-check: altered tun_out data detected");

    let mut dropped = outs[0].clone();
    let pos = dropped.iter().position(|e| e["ev"] == "tun_out").unwrap_or(0);
    dropped.remove(pos);
    if compare::compare(&dropped, &outs[1]).is_none() {
        return Err("self-check: removed event was NOT detected".to_owned());
    }
    println!("self-check: removed event detected");

    let mut stream = outs[0].clone();
    if let Some(e) = stream.iter_mut().find(|e| e["ev"] == "stderr") {
        e["text"] = Value::from(format!("{}x", e["text"].as_str().unwrap_or_default()));
    }
    if compare::compare(&stream, &outs[1]).is_none() {
        return Err("self-check: altered stderr text was NOT detected".to_owned());
    }
    println!("self-check: altered stderr detected");

    if compare::compare(&outs[2], &outs[3]).is_none() {
        return Err("self-check: different urandom seeds produced identical traces".to_owned());
    }
    let ids = vec!["startup-random".to_owned()];
    norm::validate(&ids)?;
    if let Some(m) = compare::compare(&norm::apply(&ids, &outs[2]), &norm::apply(&ids, &outs[3])) {
        return Err(format!("self-check: startup-random normalization left a difference\n{}", m.report));
    }
    println!("self-check: seeds differ raw, agree under startup-random normalization");

    let target = [3usize, 11];
    let mut tests = 0usize;
    let mut eval = |cands: &[Vec<usize>]| -> Result<Vec<bool>> {
        tests += cands.len();
        Ok(cands.iter().map(|c| target.iter().all(|t| c.contains(t))).collect())
    };
    let kept = minimize::ddmin(16, &mut eval)?;
    if kept != target {
        return Err(format!("self-check: ddmin returned {kept:?}, expected {target:?}"));
    }
    println!("self-check: ddmin reduced 16 events to {kept:?} in {tests} candidate runs");
    println!("self-check: ok");
    Ok(())
}
