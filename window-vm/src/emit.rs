//! §10.5 per-step stdout JSON + the final RC_SOLVE line, and the §14.1 WINDOW_JSON.
//! stdout carries exactly two kinds of lines in solve mode: per-step JSON events (one
//! object per line, the §10.5 vocabulary — a superset of the Python RC_STEP names) and the
//! final `RC_SOLVE: {…}` as the LAST stdout line. Diagnostics → stderr ONLY. The broker
//! (rc_solve.js) takes the token from RC_SOLVE.token.
//! --emit-window is a PRODUCER: it prints the §14.1 WINDOW_JSON as the last stdout line and
//! never prints RC_SOLVE or RC_RUN_REPORT.

use serde_json::{json, Value};

/// A per-step event — one JSON object per stdout line (§10.5).
pub fn step(fields: Value) {
    println!("{fields}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

pub fn step_ok(step_name: &str, extra: Value) {
    let mut o = json!({"step": step_name, "ok": true});
    if let (Some(a), Some(b)) = (o.as_object_mut(), extra.as_object()) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
    step(o);
}

pub fn step_fail(step_name: &str, error: &str) {
    step(json!({"step": step_name, "ok": false, "error": error}));
}

/// The RC_SOLVE line — exactly the eight RC_RUN_REPORT field names, with injected always
/// "none" (injection/submit is the broker's job; the broker collapses token to "yes|no").
/// The `scrape` field echoes the broker's input verdict: "ok" when invoked with a sitekey.
pub fn rc_solve(report: &SolveReport) {
    let line = json!({
        "scrape": report.scrape,
        "anchor": report.anchor,
        "reload": report.reload,
        "challenge": report.challenge,
        "solved": report.solved,
        "token": report.token,
        "injected": "none",
        "error": report.error,
    });
    println!("RC_SOLVE: {line}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

#[derive(Debug, Clone)]
pub struct SolveReport {
    pub scrape: &'static str,     // ok|fail (echoed from the broker's input)
    pub anchor: &'static str,     // ok|fail
    pub reload: &'static str,     // ok|fail|skipped
    pub challenge: &'static str,  // acquired-audio|acquired-image|none
    pub solved: &'static str,     // transcribed|none
    pub token: bool,
    pub error: Option<String>,
}

impl SolveReport {
    pub fn fresh() -> Self {
        SolveReport {
            scrape: "ok",
            anchor: "fail",
            reload: "skipped",
            challenge: "none",
            solved: "none",
            token: false,
            error: None,
        }
    }
}

/// The §14.1 WINDOW_JSON — exactly one JSON object as the LAST stdout line (both faces).
pub fn window_json(out: &Value) {
    println!("{out}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc_solve_key_order_is_the_contract() {
        // capture stdout briefly by rendering through serde_json key order
        let r = SolveReport {
            scrape: "ok",
            anchor: "ok",
            reload: "ok",
            challenge: "acquired-audio",
            solved: "transcribed",
            token: true,
            error: None,
        };
        let line = json!({
            "scrape": r.scrape, "anchor": r.anchor, "reload": r.reload,
            "challenge": r.challenge, "solved": r.solved, "token": r.token,
            "injected": "none", "error": r.error,
        });
        let keys: Vec<&str> = line.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        assert_eq!(keys, vec!["scrape", "anchor", "reload", "challenge", "solved", "token", "injected", "error"]);
    }
}
