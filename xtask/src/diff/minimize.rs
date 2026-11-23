use super::case::Case;
use super::compare;
use super::norm;
use super::run::{self, Impl, Job};
use crate::util::Result;
use serde_json::Value;
use std::collections::HashMap;

pub type Eval<'a> = dyn FnMut(&[Vec<usize>]) -> Result<Vec<bool>> + 'a;

fn split(items: &[usize], n: usize) -> Vec<Vec<usize>> {
    let size = items.len().div_ceil(n);
    items.chunks(size.max(1)).map(<[usize]>::to_vec).collect()
}

pub fn ddmin(total: usize, eval: &mut Eval) -> Result<Vec<usize>> {
    let all: Vec<usize> = (0..total).collect();
    if eval(&[Vec::new()])?[0] {
        return Ok(Vec::new());
    }
    let mut cur = all;
    let mut n = 2usize;
    while cur.len() >= 2 {
        let chunks = split(&cur, n);
        let mut cands: Vec<Vec<usize>> = chunks.clone();
        for i in 0..chunks.len() {
            cands.push(
                chunks
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .flat_map(|(_, c)| c.iter().copied())
                    .collect(),
            );
        }
        let res = eval(&cands)?;
        if let Some(i) = res[..chunks.len()].iter().position(|b| *b) {
            cur = cands[i].clone();
            n = 2;
        } else if let Some(i) = res[chunks.len()..].iter().position(|b| *b) {
            cur = cands[chunks.len() + i].clone();
            n = (n - 1).max(2);
        } else if n < cur.len() {
            n = (2 * n).min(cur.len());
        } else {
            break;
        }
    }
    Ok(cur)
}

pub enum Predicate {
    Disagree { subject: Impl, reference: Impl },
    Contains { subject: Impl, needle: String },
}

fn evaluate(case: &Case, pred: &Predicate, calls: bool, cands: &[Vec<usize>]) -> Result<Vec<bool>> {
    let norm_ids = &case.header.normalize;
    let mut jobs = Vec::new();
    for keep in cands {
        let sub = case.with_inputs(keep);
        match pred {
            Predicate::Disagree { subject, reference } => {
                jobs.push(Job::new(*subject, &sub, calls)?);
                jobs.push(Job::new(*reference, &sub, calls)?);
            }
            Predicate::Contains { subject, .. } => jobs.push(Job::new(*subject, &sub, calls)?),
        }
    }
    let outs = run::run_batch(&jobs)?;
    let mut res = Vec::new();
    match pred {
        Predicate::Disagree { .. } => {
            for pair in outs.chunks(2) {
                let a = norm::apply(norm_ids, &pair[0]);
                let b = norm::apply(norm_ids, &pair[1]);
                res.push(compare::compare(&b, &a).is_some());
            }
        }
        Predicate::Contains { needle, .. } => {
            for out in &outs {
                res.push(compare::contains_text(out, needle));
            }
        }
    }
    Ok(res)
}

pub fn minimize(case: &Case, pred: &Predicate, calls: bool) -> Result<Vec<usize>> {
    let mut cache: HashMap<Vec<usize>, bool> = HashMap::new();
    let mut rounds = 0usize;
    let kept = {
        let mut eval = |cands: &[Vec<usize>]| -> Result<Vec<bool>> {
            let missing: Vec<Vec<usize>> = {
                let mut m: Vec<Vec<usize>> = Vec::new();
                for c in cands {
                    if !cache.contains_key(c) && !m.contains(c) {
                        m.push(c.clone());
                    }
                }
                m
            };
            if !missing.is_empty() {
                rounds += 1;
                let r = evaluate(case, pred, calls, &missing)?;
                for (c, b) in missing.into_iter().zip(r) {
                    cache.insert(c, b);
                }
            }
            Ok(cands.iter().map(|c| cache[c]).collect())
        };
        let full: Vec<usize> = (0..case.inputs.len()).collect();
        if !eval(&[full])?[0] {
            return Err("the full trace does not satisfy the predicate; nothing to minimize".to_owned());
        }
        ddmin(case.inputs.len(), &mut eval)?
    };
    eprintln!("minimize: {} -> {} input events in {rounds} batches", case.inputs.len(), kept.len());
    Ok(kept)
}

pub fn expected_for(sub: &Case) -> Result<Vec<Value>> {
    run::run_one(Impl::C, sub, false)
}
