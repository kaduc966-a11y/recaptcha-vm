//! §10.4 the round loop: warm-up → anchor → window emit (in-process) → reload (f6='a'
//! rebuilt body) → route on chal_type (audio | image | doscaptcha wait-and-retry | fresh
//! round) → solve via the python shims → userverify. Pacing between every step; doscaptcha
//! waits and deps-missing image rounds re-roll WITHOUT consuming an attempt (one attempt =
//! a solve actually performed on an acquired challenge). Tokens are spent immediately by
//! the broker; the engine reports the ladder.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand::Rng;
use serde_json::{json, Value};

use crate::emit::{self, SolveReport};
use crate::protobuf::{
    self, looks_like_doscaptcha, parse_rresp, parse_uvresp, rebuild_reload_body,
};
use crate::requests;
use crate::shim;
use crate::vm;
use crate::window::answers;
use crate::window::clock::Clock;
use crate::window::probe::{EmitContext, ProbeSurface};
use crate::window::profile;

pub struct ChainOpts {
    pub url: String,
    pub sitekey: String,
    pub profile_id: String,
    pub vm_name: String,
    pub rounds: u32,
    pub model: String,
    pub solve_image: bool,
    pub mode: String, // demo | link4m
    pub alias: String,
    pub code: String,
    pub window_off: bool,
    pub timeout_ms: u64,
    pub dump_dir: Option<PathBuf>,
    /// OPT-IN egress route — every chain request (anchor→reload→userverify→check-captcha)
    /// rides this proxy for the WHOLE session; default = direct client (§10.1 note).
    pub proxy: Option<String>,
    pub page_context: Option<EmitContext>,
    pub fresh_session: Option<PathBuf>,
}

const MAX_NON_ATTEMPTS: u32 = 8; // §9.8 engineering guard — a never-solvable page cannot spin forever
const MAX_DOS_ROUNDS: u32 = 3;

fn pace(lo: f64, hi: f64) {
    let secs = rand::thread_rng().gen_range(lo..hi);
    std::thread::sleep(Duration::from_millis((secs * 1000.0) as u64));
}

fn pace_async(lo: f64, hi: f64) {
    pace(lo, hi); // blocking sleep is fine here: the chain is sequential by nature
}

/// §10.4 step 0's optional seed: `--fresh-session` path, else the workspace artifact. If its
/// `ts` is within 86400 s, merge `google_cookies` into the jar (read-only use of the file;
/// nothing is ever written into rc_jsdom/). Reload-reuse (<90 s) is reported reload:skipped.
fn load_seed(opts: &ChainOpts) -> Option<(Vec<(String, String)>, Option<Value>)> {
    let candidate = opts
        .fresh_session
        .clone()
        .unwrap_or_else(|| PathBuf::from("../recaptcha/_fresh_session.json"));
    let text = std::fs::read_to_string(&candidate).ok()?;
    let j: Value = serde_json::from_str(&text).ok()?;
    let ts = j.get("ts").and_then(|v| v.as_f64())?;
    let age = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
        - ts;
    if !(0.0..=86400.0).contains(&age) {
        eprintln!("[seed] _fresh_session.json too old (age={age:.0}s) — ignored");
        return None;
    }
    let mut cookies = Vec::new();
    if let Some(list) = j.get("google_cookies").and_then(|v| v.as_object()) {
        for (name, v) in list {
            if let Some(val) = v.as_str() {
                cookies.push((name.clone(), val.to_string()));
            }
        }
    }
    let reload_body = j
        .get("reload_resp_body_b64")
        .and_then(|v| v.as_str())
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .map(|b| b);
    let reload_body = reload_body.map(|b| {
        serde_json::from_str::<Value>(&String::from_utf8_lossy(&b)).unwrap_or(Value::Null)
    });
    eprintln!("[seed] merged {} google cookies (age={age:.0}s)", cookies.len());
    Some((cookies, reload_body.filter(|v| !v.is_null()).filter(|_| age < 90.0)))
}

fn dump(opts: &ChainOpts, name: &str, bytes: &[u8]) {
    if let Some(d) = &opts.dump_dir {
        let _ = std::fs::write(d.join(name), bytes);
    }
}

/// Cookie-posture diagnostic — the python chain's `_jar_names()` (§9.3: the cookie variable
/// is the first thing to diagnose). Names only, never values.
fn jar_names(t: &crate::transport::Transport) -> Vec<String> {
    t.jar.get_all().map(|c| c.name().to_string()).collect()
}

/// The in-process window emit (§10.4 step 2 — no CLI, the pivot's whole point). A failure
/// never fails the run: the chain proceeds verbatim with the pinned constants (§13.4/§14.4).
fn emit_window_once(opts: &ChainOpts, anchor_keys: (Option<i64>, Option<i64>)) -> Option<Value> {
    if opts.window_off {
        return None;
    }
    let folder = project_root()?;
    let wroot = folder.join("window");
    let prof = match profile::load_with_fallback(&wroot, &opts.profile_id) {
        Ok((p, fb)) => {
            if let Some(from) = fb {
                eprintln!("[window] profile {from} failed validation — falling back to chrome-win");
            }
            p
        }
        Err(e) => {
            eprintln!("[window] profile load failed: {e} — fallback to constants");
            return None;
        }
    };
    let store = match answers::load(&wroot, prof.answers.as_deref().unwrap_or("answers/fingerprint.json")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[window] answers store unreadable: {e} — fallback to constants");
            return None;
        }
    };
    let clock = Arc::new(Clock::new());
    let mut ctx = opts.page_context.clone().unwrap_or_default();
    ctx.url = opts.url.clone();
    ctx.sitekey = opts.sitekey.clone();
    if anchor_keys.0.is_none() || anchor_keys.1.is_none() {
        eprintln!("[window] anchor keys absent/garbled (§18.10) — encryption stays null");
    }
    let mut surface = ProbeSurface::new(Arc::new(prof.clone()), store, clock.clone(), ctx);
    let fp_ser = surface.fingerprint_serialization();
    let fp_hash = crate::window::probe::hash_string(&fp_ser);
    let oc_ser = surface.oc_serialization();
    let ch = crate::window::probe::hash_string(&oc_ser);
    let gate = surface.consistency_check(
        &prof.transport.user_agent,
        (prof.browser.screen.width, prof.browser.screen.height),
        prof.browser.device_pixel_ratio,
        (clock.now() as i64) as f64 / 10.0,
    );
    if !gate.is_empty() {
        eprintln!("[window] consistency gate FAILED: {} — fallback to constants", gate.join("; "));
        return None;
    }
    let vm_res = match vm::run_vm(&wroot, &opts.vm_name, &clock) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[window] VM run failed: {e} — bgdata absent, material above is real");
            crate::vm::VmOutcome::default()
        }
    };
    let out = json!({
        "ok": true, "runner": "rust", "profile": prof.id, "engine": prof.engine, "vm": opts.vm_name,
        "url": opts.url, "sitekey": opts.sitekey,
        "fingerprint": fp_ser,
        "fingerprint_hash": fp_hash,
        "fingerprint_encrypted": Value::Null,
        "oc": oc_ser,
        "oc_encrypted": Value::Null,
        "ch": ch,
        "bgdata": vm_res.bgdata.clone(),
        "encrypted": false,
        "head_hash": if opts.page_context.as_ref().map(|c| c.head_bloom.is_some()).unwrap_or(false) { "computed" } else { "recorded" },
        "errors": vm_res.errors.len(),
        "elapsed_ms": 0,
    });
    if let Some(d) = &opts.dump_dir {
        let _ = std::fs::write(d.join("window.json"), out.to_string());
    }
    Some(out)
}

// the emit consumed the serialization twice above; keep ONE canonical hash (fix in solve())
// Resolution: cwd holding window/profiles first, then ANY ancestor of the exe holding
// window/profiles — no fixed ancestor depth (a packaged repo ships the exe at its root).
fn project_root() -> Option<&'static Path> {
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("window").join("profiles").exists() {
            return Some(Box::leak(cwd.into_boxed_path()));
        }
    }
    let exe = std::env::current_exe().ok()?;
    for anc in exe.ancestors() {
        if anc.join("window").join("profiles").is_dir() {
            return Some(Box::leak(anc.to_path_buf().into_boxed_path()));
        }
    }
    None
}

/// The §10.4 round loop. Returns the SolveReport the broker maps onto RC_RUN_REPORT.
pub async fn solve(opts: ChainOpts) -> SolveReport {
    let mut rep = SolveReport::fresh();
    let t0 = Instant::now();
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    emit::step(json!({"step":"engine","ok":true,"runner":format!("window-vm {}", env!("CARGO_PKG_VERSION"))}));

    let transport = match crate::transport::Transport::build_with_proxy(opts.proxy.as_deref()) {
        Ok(t) => {
            if let Some(p) = &opts.proxy {
                eprintln!("[transport] proxy: {p} (whole session rides the proxy)");
            }
            t
        }
        Err(e) => {
            eprintln!("[transport] build failed: {e}");
            rep.error = Some("transport_failed".into());
            return rep;
        }
    };

    // step 0 — warm-up + seed (§10.4 step 0)
    emit::step(json!({"step":"warmup","ok":true}));
    if let Err(e) = requests::warmup(&transport).await {
        eprintln!("[warmup] failed (continuing): {e}");
    }
    eprintln!("[warmup] jar now: {:?}", jar_names(&transport));
    pace_async(1.0, 2.0);
    let seed = load_seed(&opts);
    if let Some((cookies, _)) = &seed {
        for (name, val) in cookies {
            // wreq Jar::add takes any IntoCookie — a Set-Cookie-shaped &str parses here
            transport.jar.add(
                format!("{name}={val}; Domain=.google.com; Path=/; Secure"),
                "https://www.google.com/",
            );
        }
    }

    let mut attempts: u32 = 0;
    let mut non_attempts: u32 = 0;
    let mut dos_waits: u32 = 0;
    let mut iters: u32 = 0;
    let mut prev_bft: Option<String> = None;
    let mut window_emitted = false;
    let mut window_f5: Option<i64> = None;
    let mut window_f16: Option<String> = None;
    let mut window_ch: Option<String> = None;
    let mut window_oc: Option<String> = None;
    let mut challenge_acquired_at: Option<Instant> = None;
    let seed_reload: Option<Value> = seed.and_then(|(_, b)| b);

    loop {
        if attempts >= opts.rounds.max(4) || non_attempts >= MAX_NON_ATTEMPTS {
            break;
        }
        if t0.elapsed().as_millis() as u64 > opts.timeout_ms {
            eprintln!("[timeout] engine budget exceeded");
            break;
        }
        iters += 1;
        eprintln!("=== ROUND {iters} (attempts {attempts}/{}, non-attempts {non_attempts}) ===", opts.rounds.max(4));

        // step 1 — anchor (§10.4 step 1)
        let anchor_res = requests::anchor(&transport, &opts.url, &opts.sitekey).await;
        let (anchor_tok, k18, k31) = match anchor_res {
            Ok((200, html)) => {
                let (tok, k18, k31) = requests::extract_anchor(&html);
                (tok, k18, k31)
            }
            Ok((status, _)) => {
                eprintln!("[anchor] -> HTTP {status}");
                (None, None, None)
            }
            Err(e) => {
                eprintln!("[anchor] error: {e}");
                (None, None, None)
            }
        };
        let anchor_tok = match anchor_tok {
            Some(t) => {
                eprintln!("[anchor] token len={}", t.len());
                emit::step(json!({"step":"anchor","ok":true,"keys": k18.is_some() || k31.is_some()}));
                rep.anchor = "ok";
                eprintln!("[anchor] jar now: {:?}", jar_names(&transport));
                t
            }
            None => {
                emit::step(json!({"step":"anchor","ok":false}));
                rep.anchor = "fail";
                rep.error = Some("anchor_fail".into());
                break;
            }
        };
        pace_async(0.8, 2.0);

        // step 2 — the in-process window emit, ONCE, after the first anchor (§10.4 step 2)
        if !window_emitted {
            window_emitted = true;
            match emit_window_once(&opts, (k18, k31)) {
                Some(wout) => {
                    // §14.2 consumption table — BOTH-or-NEITHER for the f5/f16 pair
                    let fe = wout.get("fingerprint_encrypted").and_then(|v| v.as_str());
                    let fh = wout.get("fingerprint_hash").and_then(|v| v.as_i64());
                    let encrypted = wout.get("encrypted").and_then(|v| v.as_bool()).unwrap_or(false);
                    let mut used: Vec<&str> = Vec::new();
                    if encrypted && fe.is_some() && fh.is_some() {
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(fe.unwrap()) {
                            if !bytes.is_empty() {
                                window_f5 = fh;
                                window_f16 = Some(fe.unwrap().to_string());
                                used.push("idx5");
                                used.push("idx16");
                            }
                        }
                    } else {
                        eprintln!("[window] encrypted:false (reload-f16 encryptor absent) — the captured f5+f16 pair stays");
                    }
                    if let Some(ch) = wout.get("ch").and_then(|v| v.as_i64()) {
                        window_ch = Some(ch.to_string());
                        used.push("ch");
                    }
                    if let Some(oc) = wout.get("oc_encrypted").and_then(|v| v.as_str()) {
                        window_oc = Some(oc.to_string());
                        used.push("oc");
                    }
                    emit::step(json!({"step":"window","ok":true,"runner":"rust","used":used,
                        "bgdata": wout.get("bgdata").map(|b| b.as_str().map(|s| !s.is_empty()).unwrap_or(false)).unwrap_or(false)}));
                }
                None => {
                    emit::step(json!({"step":"window","ok":false,"fallback":"constants"}));
                }
            }
        }

        // step 3 — reload (§10.3/§10.4), or the <90 s seed-reuse path
        let parsed;
        if iters == 1 {
            if let Some(seed_j) = &seed_reload {
                parsed = seed_j.clone();
                eprintln!("[reload] SKIPPED — round-1 reload answered from _fresh_session.json (<90s)");
                emit::step(json!({"step":"reload","ok":true,"skipped":true}));
                rep.reload = "skipped";
                // the seed path still needs the routing fields
                pace_async(0.8, 2.0);
                if route(
                    &opts, &mut rep, &transport, &parsed, &mut attempts, &mut non_attempts,
                    &mut dos_waits, &mut challenge_acquired_at, &window_ch, &window_oc,
                ).await
                {
                    break;
                }
                continue;
            }
            rep.reload = "skipped";
        }
        let body = match rebuild_reload_body(
            &anchor_tok,
            &opts.sitekey,
            "a",
            None,
            window_f5,
            window_f16.as_deref(),
        ) {
            Ok(b) => {
                eprintln!("[reload] body len={} (python reference: 8420 for a 1977-char token)", b.len());
                b
            }
            Err(e) => {
                eprintln!("[reload] body rebuild failed: {e}");
                rep.reload = "fail";
                rep.error = Some("reload_fail".into());
                emit::step(json!({"step":"reload","ok":false}));
                break;
            }
        };
        match requests::reload(&transport, &opts.sitekey, body, prev_bft.as_deref()).await {
            Ok((200, text)) => {
                dump(&opts, &format!("reload_{iters}.txt"), text.as_bytes());
                let p = parse_rresp(&text);
                if p.get("error").is_some() {
                    eprintln!("[reload] rresp parse fail");
                    rep.reload = "fail";
                    rep.error = Some("reload_fail".into());
                    emit::step(json!({"step":"reload","ok":false}));
                    break;
                }
                rep.reload = "ok";
                emit::step(json!({"step":"reload","ok":true,"skipped":false,
                    "chal_type": p.get("chal_type").cloned().unwrap_or(Value::Null)}));
                prev_bft = p.get("bft").and_then(|v| v.as_str()).map(|s| s.to_string()).or(prev_bft);
                parsed = p;
            }
            Ok((status, _)) => {
                eprintln!("[reload] -> HTTP {status}");
                rep.reload = "fail";
                rep.error = Some("reload_fail".into());
                emit::step(json!({"step":"reload","ok":false}));
                break;
            }
            Err(e) => {
                eprintln!("[reload] error: {e}");
                rep.reload = "fail";
                rep.error = Some("reload_fail".into());
                emit::step(json!({"step":"reload","ok":false}));
                break;
            }
        }
        pace_async(0.8, 2.0);

        if route(
            &opts, &mut rep, &transport, &parsed, &mut attempts, &mut non_attempts,
            &mut dos_waits, &mut challenge_acquired_at, &window_ch, &window_oc,
        ).await
        {
            break;
        }
    }

    if rep.token {
        rep.solved = "transcribed";
    }
    let _ = started;
    rep
}

/// Routes one parsed rresp. Returns true when the loop should STOP (token minted, budget
/// exhausted, or a fatal upstream failure); false = re-roll (fresh anchor next iteration).
#[allow(clippy::too_many_arguments)]
async fn route(
    opts: &ChainOpts,
    rep: &mut SolveReport,
    transport: &crate::transport::Transport,
    parsed: &Value,
    attempts: &mut u32,
    non_attempts: &mut u32,
    dos_waits: &mut u32,
    challenge_acquired_at: &mut Option<Instant>,
    window_ch: &Option<String>,
    window_oc: &Option<String>,
) -> bool {
    let chal = parsed.get("chal_type").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let c = parsed.get("c").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let bft = parsed.get("bft").and_then(|v| v.as_str()).map(|s| s.to_string());
    let p_tok = parsed.get("p").and_then(|v| v.as_str()).map(|s| s.to_string());
    let mids: Vec<String> = parsed
        .get("mids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    eprintln!("[route] chal_type={chal} c={} p={} bft={}", c.is_empty(), p_tok.is_some(), bft.is_some());

    // doscaptcha — the dominant observed outcome (42 of 46 routes in the runs audit, §1):
    // wait ≥ 30 s respecting the countdown, fresh anchor, never treat the envelope's j[1]
    // token as a solve. reload stays "ok" (a genuine rresp came back); the block is
    // expressed by challenge:none + error:doscaptcha.
    if chal == "doscaptcha" {
        emit::step(json!({"step":"challenge","type":"doscaptcha"}));
        *non_attempts += 1;
        *dos_waits += 1;
        if *dos_waits > MAX_DOS_ROUNDS {
            rep.error = Some("doscaptcha".into());
            return true;
        }
        let countdown = parsed.get("token_expiration").and_then(|v| v.as_u64()).unwrap_or(120);
        let wait = std::cmp::max(30, countdown) + rand::thread_rng().gen_range(0..5u64);
        eprintln!("[doscaptcha] waiting {wait}s (countdown floor {countdown})");
        tokio::time::sleep(Duration::from_secs(wait)).await;
        return false; // fresh anchor next iteration — never reuse the stale envelope's token
    }

    // image challenge types (§10.4 step 4b)
    if ["imageselect", "tileselect", "dynamic", "multicaptcha"].contains(&chal.as_str()) {
        emit::step(json!({"step":"challenge","type":"image"}));
        return image_branch(opts, rep, transport, parsed, attempts, non_attempts, challenge_acquired_at, window_ch, window_oc, p_tok.as_deref(), None).await;
    }

    if chal != "audio" {
        emit::step(json!({"step":"challenge","type":"none"}));
        *non_attempts += 1;
        pace_async(1.0, 2.5);
        rep.error = rep.error.clone().or(Some("no_audio_challenge".into()));
        return false;
    }

    // audio — payload (§10.4 step 4a), discriminated by CONTENT, never by trust
    let p_tok = match p_tok {
        Some(p) => p,
        None => {
            emit::step(json!({"step":"challenge","type":"none"}));
            *non_attempts += 1;
            rep.error = rep.error.clone().or(Some("mp3_fail".into()));
            return false;
        }
    };
    let (status, _ct, body) = match requests::payload(transport, &opts.sitekey, &p_tok).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[payload] error: {e}");
            emit::step(json!({"step":"challenge","type":"none"}));
            *non_attempts += 1;
            rep.error = rep.error.clone().or(Some("mp3_fail".into()));
            return false;
        }
    };
    if status != 200 {
        eprintln!("[payload] -> HTTP {status}");
        emit::step(json!({"step":"challenge","type":"none"}));
        *non_attempts += 1;
        rep.error = rep.error.clone().or(Some("mp3_fail".into()));
        return false;
    }
    if body.starts_with(&[0xff, 0xd8]) || body.starts_with(&[0x89, b'P']) {
        // image despite an audio rresp — the image branch handles it (rule 5)
        eprintln!("[payload] got an IMAGE despite an audio rresp — routed to the image branch");
        emit::step(json!({"step":"challenge","type":"image"}));
        return image_branch(opts, rep, transport, parsed, attempts, non_attempts, challenge_acquired_at, window_ch, window_oc, None, Some(body)).await;
    }
    if looks_like_doscaptcha(&body) {
        emit::step(json!({"step":"challenge","type":"doscaptcha"}));
        *non_attempts += 1;
        *dos_waits += 1;
        if *dos_waits > MAX_DOS_ROUNDS {
            rep.error = Some("doscaptcha".into());
            return true;
        }
        let countdown = parsed.get("token_expiration").and_then(|v| v.as_u64()).unwrap_or(120);
        let wait = std::cmp::max(30, countdown) + rand::thread_rng().gen_range(0..5u64);
        eprintln!("[doscaptcha] waiting {wait}s (payload-blocked, floor {countdown})");
        tokio::time::sleep(Duration::from_secs(wait)).await;
        return false;
    }
    let is_mp3 = body.len() >= 1000
        && (body.starts_with(b"ID3") || (body.len() > 2 && body[0] == 0xFF && (body[1] & 0xE0) == 0xE0));
    if !is_mp3 {
        // the audio_solve.py:268 gate keeps interstitial/blocked pages out of whisper
        eprintln!("[payload] not MP3 (len={}) — gate rejects, fresh challenge", body.len());
        emit::step(json!({"step":"challenge","type":"none"}));
        *non_attempts += 1;
        return false;
    }

    emit::step(json!({"step":"challenge","type":"audio"}));
    rep.challenge = "acquired-audio";
    *challenge_acquired_at = Some(Instant::now());

    // whisper via the shim (§13.1); empty/<2-char answer → fresh audio challenge
    let transcript = match tokio::task::spawn_blocking({
        let body = body.clone();
        let model = opts.model.clone();
        let dump_dir = opts.dump_dir.clone();
        move || shim::transcribe(&body, &model, dump_dir.as_deref())
    })
    .await
    {
        Ok(Ok(t)) => crate::protobuf::clean_transcript(&t),
        Ok(Err(e)) => {
            eprintln!("[transcribe] failed: {e}");
            emit::step(json!({"step":"transcribe","ok":false,"error":"transcribe_failed"}));
            rep.error = rep.error.clone().or(Some("transcribe_failed".into()));
            *non_attempts += 1;
            return false;
        }
        Err(e) => {
            eprintln!("[transcribe] task join failed: {e}");
            emit::step(json!({"step":"transcribe","ok":false,"error":"transcribe_failed"}));
            *non_attempts += 1;
            return false;
        }
    };
    emit::step(json!({"step":"transcribe","ok":true,"engine":format!("whisper-{}", opts.model)}));
    if transcript.chars().count() < 2 {
        eprintln!("[transcribe] empty answer — fresh audio challenge");
        *non_attempts += 1;
        return false;
    }

    *attempts += 1; // a solve was performed on an acquired challenge (§9.8)
    pace_async(1.0, 2.5);
    let t_ms = protobuf::clamp_tct_ms(
        challenge_acquired_at.map(|t| t.elapsed().as_secs_f64()).unwrap_or(10.0),
    );
    let response_b64 = protobuf::encode_userverify_response(&json!(transcript));
    let ch = window_ch.clone().unwrap_or_else(|| protobuf::CH_CONST.to_string());
    let oc = window_oc.clone().unwrap_or_else(|| protobuf::OC_CONST.to_string());
    eprintln!("[userverify] t/ct={t_ms} (ms) ch/oc={}", if window_ch.is_some() || window_oc.is_some() { "window" } else { "pinned constants" });
    userverify_and_finish(rep, transport, opts, parsed, &response_b64, &t_ms, &ch, &oc, bft.as_deref(), non_attempts).await
}

/// The image branch (§10.4 step 4b): payload → YOLO/CLIP via the shim → userverify.
#[allow(clippy::too_many_arguments)]
async fn image_branch(
    opts: &ChainOpts,
    rep: &mut SolveReport,
    transport: &crate::transport::Transport,
    parsed: &Value,
    attempts: &mut u32,
    non_attempts: &mut u32,
    challenge_acquired_at: &mut Option<Instant>,
    window_ch: &Option<String>,
    window_oc: &Option<String>,
    p_tok: Option<&str>,
    body: Option<Vec<u8>>,
) -> bool {
    let bytes = match body {
        Some(b) => b,
        None => {
            let p = match p_tok.map(|s| s.to_string()).or_else(|| parsed.get("p").and_then(|v| v.as_str()).map(|s| s.to_string())) {
                Some(p) => p,
                None => {
                    emit::step(json!({"step":"image_solve","ok":false}));
                    *non_attempts += 1;
                    rep.error = rep.error.clone().or(Some("image_unsolved".into()));
                    return false;
                }
            };
            match requests::payload(transport, &opts.sitekey, &p).await {
                Ok((200, _, b)) => b,
                Ok((status, _, _)) => {
                    eprintln!("[payload(image)] -> HTTP {status}");
                    emit::step(json!({"step":"image_solve","ok":false}));
                    *non_attempts += 1;
                    return false;
                }
                Err(e) => {
                    eprintln!("[payload(image)] error: {e}");
                    emit::step(json!({"step":"image_solve","ok":false}));
                    *non_attempts += 1;
                    return false;
                }
            }
        }
    };
    if looks_like_doscaptcha(&bytes) {
        emit::step(json!({"step":"challenge","type":"doscaptcha"}));
        *non_attempts += 1;
        rep.error = Some("doscaptcha".into());
        return true;
    }
    if !bytes.starts_with(&[0xff, 0xd8]) && !bytes.starts_with(&[0x89, b'P']) {
        eprintln!("[image] payload is not an image — re-roll");
        emit::step(json!({"step":"image_solve","ok":false}));
        *non_attempts += 1;
        return false;
    }
    rep.challenge = "acquired-image";
    *challenge_acquired_at = Some(Instant::now());

    if !opts.solve_image {
        eprintln!("[image] --solve-image not set — image round re-rolled");
        *non_attempts += 1;
        pace_async(1.0, 2.5);
        return false;
    }
    let targets: Vec<String> = {
        let mids: Vec<String> = parsed
            .get("mids")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        if mids.is_empty() {
            vec!["traffic light".into(), "bus".into(), "fire hydrant".into()]
        } else {
            // MID_LABEL.get(x, x) — unmapped labels pass through (e2e.py:25 shape)
            mids.iter()
                .map(|m| {
                    mid_map::MID_LABEL
                        .iter()
                        .find(|(k, _)| k == m)
                        .map(|(_, l)| l.to_string())
                        .unwrap_or_else(|| m.clone())
                })
                .collect()
        }
    };
    let classify_res = tokio::task::spawn_blocking({
        let bytes = bytes.clone();
        let targets = targets.clone();
        move || shim::classify(&bytes, &targets, 3)
    })
    .await;
    let indices = match classify_res {
        Ok(Ok(crate::shim::ClassifyOut::Indices(v))) => v,
        Ok(Ok(crate::shim::ClassifyOut::Skipped)) => {
            // §10.4 step 4b: deps-missing image rounds re-roll WITHOUT consuming an attempt
            emit::step(json!({"step":"image_solve","skipped":"deps_missing"}));
            *non_attempts += 1;
            pace_async(1.0, 2.5);
            return false;
        }
        Ok(Err(e)) => {
            eprintln!("[classify] failed: {e}");
            emit::step(json!({"step":"image_solve","ok":false}));
            rep.error = rep.error.clone().or(Some("image_unsolved".into()));
            *non_attempts += 1;
            return false;
        }
        Err(e) => {
            eprintln!("[classify] task join failed: {e}");
            emit::step(json!({"step":"image_solve","ok":false}));
            *non_attempts += 1;
            return false;
        }
    };
    if indices.is_empty() {
        emit::step(json!({"step":"image_solve","ok":false}));
        *non_attempts += 1;
        pace_async(1.0, 2.5);
        return false;
    }
    emit::step(json!({"step":"image_solve","ok":true,"indices":indices}));
    *attempts += 1; // the cascade ran on an acquired image (§9.8)
    pace_async(1.0, 2.5);
    let t_ms = protobuf::clamp_tct_ms(
        challenge_acquired_at.map(|t| t.elapsed().as_secs_f64()).unwrap_or(10.0),
    );
    let response_b64 = protobuf::encode_userverify_response(&json!(indices));
    let ch = window_ch.clone().unwrap_or_else(|| protobuf::CH_CONST.to_string());
    let oc = window_oc.clone().unwrap_or_else(|| protobuf::OC_CONST.to_string());
    let bft = parsed.get("bft").and_then(|v| v.as_str()).map(|s| s.to_string());
    userverify_and_finish(rep, transport, opts, parsed, &response_b64, &t_ms, &ch, &oc, bft.as_deref(), non_attempts).await
}

/// userverify POST + the >300 uvresp gate (§10.4 step 4a end). Returns true = STOP.
async fn userverify_and_finish(
    rep: &mut SolveReport,
    transport: &crate::transport::Transport,
    opts: &ChainOpts,
    parsed: &Value,
    response_b64: &str,
    t_ms: &str,
    ch: &str,
    oc: &str,
    bft: Option<&str>,
    non_attempts: &mut u32,
) -> bool {
    let c = parsed.get("c").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let res = requests::userverify(transport, &opts.sitekey, &c, response_b64, t_ms, ch, oc, bft).await;
    match res {
        Ok((status, text)) => {
            dump(opts, "userverify.txt", text.as_bytes());
            let uv = parse_uvresp(&text);
            let tok = uv.get("token").and_then(|v| v.as_str()).map(|s| s.to_string());
            let dyn_rresp = uv.get("dynamic_rresp").map(|v| !v.is_null()).unwrap_or(false);
            match tok {
                Some(t) if t.len() > 300 && !dyn_rresp => {
                    eprintln!("[userverify] -> {status} TOKEN len={}", t.len());
                    emit::step(json!({"step":"userverify","ok":true,"token_len":t.len()}));
                    rep.token = true;
                    // Persistence on MINT (opt-in via --dump-dir): the raw token BODY to
                    // token_<unix>.txt + one append line in tokens.log. RC_SOLVE carries
                    // only the boolean, so without this the token survives nowhere on disk.
                    if let Some(d) = &opts.dump_dir {
                        let _ = std::fs::create_dir_all(d);
                        let unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|x| x.as_secs())
                            .unwrap_or(0);
                        let path = d.join(format!("token_{unix}.txt"));
                        let _ = std::fs::write(&path, t.as_bytes());
                        let mut log = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(d.join("tokens.log"));
                        if let Some(f) = log.as_mut().ok() {
                            use std::io::Write as _;
                            let _ = writeln!(
                                f,
                                "{} mode={} alias={} sitekey={} len={} file={}",
                                unix, opts.mode, opts.alias, opts.sitekey, t.len(), path.display()
                            );
                        }
                        eprintln!("[token-dump] {} ({} bytes) + tokens.log appended", path.display(), t.len());
                    }
                    // §15 — in link4m mode the minted token is SPENT IMMEDIATELY on the
                    // broker's check-captcha POST (s1 first, then link4m.com, e2e.py:710-729):
                    // the shaped reply's `success` + destination `url` is where the flow
                    // ends. The RC_SOLVE eight-field contract stays untouched — the reply
                    // rides the step event + stderr. Without --alias the POST is SKIPPED
                    // and that is recorded here — never silently fabricated.
                    if opts.mode == "link4m" && !opts.alias.is_empty() {
                        match requests::check_captcha(transport, &t, &opts.alias, &opts.code).await {
                            Ok(logs) => {
                                // the shaped reply is the FIRST host whose body parses as a
                                // JSON object (s1's 200/159B) — the ladder's later raw hosts
                                // (404 HTML of link4m.com) must not shadow it.
                                let pick = logs
                                    .iter()
                                    .find(|(_, _, b)| serde_json::from_str::<serde_json::Value>(b).is_ok())
                                    .unwrap_or_else(|| logs.last().unwrap());
                                let (host, status, body) = pick.clone();
                                let v = serde_json::from_str::<serde_json::Value>(&body).ok();
                                let success = v.as_ref()
                                    .and_then(|j| j.get("success")).and_then(|x| x.as_bool()).unwrap_or(false);
                                let dest = v.as_ref()
                                    .and_then(|j| j.get("url")).and_then(|x| x.as_str()).unwrap_or("");
                                eprintln!("[check-captcha] host={host} status={status} success={success} dest={dest}");
                                emit::step(json!({
                                    "step":"check-captcha","ok":success,"host":host,"status":status,
                                    "dest":dest,
                                    "reply_excerpt": body.chars().take(240).collect::<String>()
                                }));
                            }
                            Err(e) => {
                                eprintln!("[check-captcha] error: {e}");
                                emit::step(json!({"step":"check-captcha","ok":false,"error":format!("{e:#}")}));
                            }
                        }
                    } else if opts.mode == "link4m" {
                        eprintln!("[check-captcha] skipped: mode=link4m but NO --alias — token minted only (recorded)");
                        emit::step(json!({"step":"check-captcha","ok":false,"skipped":"alias_required"}));
                    }
                    return true;
                }
                Some(t) => {
                    eprintln!("[userverify] -> {status} rejected (len={} dyn={dyn_rresp}) — next round", t.len());
                    emit::step(json!({"step":"userverify","ok":false,"token_len":t.len()}));
                }
                None => {
                    eprintln!("[userverify] -> {status} no token — next round");
                    emit::step(json!({"step":"userverify","ok":false}));
                }
            }
        }
        Err(e) => {
            eprintln!("[userverify] error: {e}");
            emit::step(json!({"step":"userverify","ok":false}));
        }
    }
    *non_attempts += 1;
    pace_async(1.0, 2.5); // between rounds (e2e.py:701)
    false
}

// The MID→label table (e2e.py:25) — used by the image branch to derive the shim's targets.
pub(crate) mod mid_map {
    pub const MID_LABEL: &[(&str, &str)] = &[
        ("/m/015qff", "traffic light"),
        ("/m/04_sv", "motorcycle"),
        ("/m/01bjv", "bus"),
        ("/m/0199g", "bicycle"),
        ("/m/01lynh", "fire hydrant"),
        ("/m/014xcs", "car"),
        ("/m/02kx1l", "bridge"),
        ("/m/0k4j", "chimney"),
        ("/m/02sgy", "palm tree"),
        ("/m/04h7h", "stairs"),
        ("/m/09g5v", "crosswalk"),
        ("/m/0k2k", "boat"),
        ("/m/015258", "car"),
        ("/m/01pns0", "fire hydrant"),
    ];
}
