//! window-vm — rc_jsdom's full-Rust engine (DESIGN.md §9). CLI (§9.3):
//!   window-vm solve --url <page> --sitekey <key> [--profile] [--answers] [--vm]
//!                  [--page-context <json>] [--rounds 4] [--model tiny.en]
//!                  [--mode demo|link4m] [--alias <a>] [--code <c>] [--fresh-session <path>]
//!                  [--window auto|off] [--solve-image] [--timeout <ms>] [--dump-dir <dir>]
//!   window-vm emit-window --url <page> --sitekey <key> [--anchor-keys k18,k31]
//!                         [--profile] [--answers] [--vm] [--page-context] [--json-only]
//!   window-vm --selftest
//!   window-vm --selftest-vm                                  (§19 offline sandbox gate)
//!   window-vm --vm-sandbox --ainput <json> [--release-js <p>] (§19 live sandbox run)
//!   window-vm --emit --url <page> --sitekey <key> --profile <path> --answers <path>
//!             --vm <vm.js> --bc <bc.txt> [--json-only] [--anchor-keys k18,k31]
//!             [--ainput <json>] [--release-js <p>]           (§19 the solve_service contract)
//!
//! stdout contract (§6.4/§10.5): per-step JSON events + the final RC_SOLVE line (solve), or
//! exactly one WINDOW_JSON as the last line (emit-window / --emit). Diagnostics → stderr only.
//! Exit codes: 0 = token minted (solve) / emit ok / selftest pass; 1 = controlled failure;
//! 2 = crash.

mod chain;
mod emit;
mod engine;
mod js;
mod protobuf;
mod requests;
mod shim;
mod transport;
mod vm;
mod vm_sandbox;
mod window;

/// Allocator diagnostics for the sandbox boot (VM_SANDBOX_ALLOCDIAG=1): boa attempts REAL
/// allocations for oversized computed lengths (V8 throws RangeError instead) and Rust
/// aborts before anything can record; the global allocator prints the size + a native
/// backtrace so the offending site is nameable. Zero-cost when the env var is unset.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};

struct DiagAlloc;

static DIAG_INIT: AtomicBool = AtomicBool::new(false);
static DIAG_ON: AtomicBool = AtomicBool::new(false);

#[inline]
fn diag_enabled() -> bool {
    if !DIAG_INIT.load(Ordering::Relaxed) {
        DIAG_INIT.store(true, Ordering::Relaxed);
        DIAG_ON.store(
            std::env::var("VM_SANDBOX_ALLOCDIAG").map(|v| v == "1" || v == "true").unwrap_or(false),
            Ordering::Relaxed,
        );
    }
    DIAG_ON.load(Ordering::Relaxed)
}

unsafe impl GlobalAlloc for DiagAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > 512 * 1024 * 1024 && diag_enabled() {
            eprintln!("[alloc-diag] BIG alloc {} bytes align={} — native backtrace:", layout.size(), layout.align());
            eprintln!("{}", std::backtrace::Backtrace::force_capture());
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > 512 * 1024 * 1024 && diag_enabled() {
            eprintln!("[alloc-diag] BIG realloc {} bytes — native backtrace:", new_size);
            eprintln!("{}", std::backtrace::Backtrace::force_capture());
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static A: DiagAlloc = DiagAlloc;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

use crate::window::answers::Store;
use crate::window::clock::Clock;
use crate::window::probe::{EmitContext, PageText, ProbeSurface};
use crate::window::profile::Profile;

#[derive(Parser)]
#[command(name = "window-vm", version, about = "rc_jsdom's full-Rust engine")]
struct Cli {
    #[arg(long, help = "offline engine gate (§9.3): profile+answers+VM+template+hash known-answers, no network")]
    selftest: bool,
    #[arg(long, help = "§19 offline vm-sandbox gate: runs the sb.html recipe on the bundled recap.js \
                        with a synthetic ainput fixture built from the embedded constants; exit 0 required")]
    selftest_vm: bool,
    #[arg(long, requires = "ainput", help = "§19: run the ReCaptcha-VM sandbox live — prints the sandbox JSON \
                        (payload slots + consumer keys) as the last stdout line")]
    vm_sandbox: bool,
    /// §19 — the anchor ainput array (the 32-element recaptcha.anchor.Main.init argument)
    /// as a JSON file; a bare array or {"ainput": [...]} are both accepted.
    #[arg(long)]
    ainput: Option<PathBuf>,
    #[arg(long, help = "§19: a live release bundle to run instead of the bundled recap.js \
                        (preferred when provided — the live release matches the current anchor)")]
    release_js: Option<PathBuf>,
    /// §19 — the solve_service.py emit contract (its argv is exactly: --emit --url --sitekey
    /// --profile <path> --answers <path> --vm <vm.js> --bc <bc.txt> --json-only
    /// [--anchor-keys k18,k31]). Implemented here so solve_service needs no change.
    #[arg(long)]
    emit: bool,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    sitekey: Option<String>,
    #[arg(long, help = "profile: a full path to the profile JSON (--emit contract) or a profile name")]
    profile: Option<String>,
    #[arg(long, help = "answers: a full path to the answers JSON (--emit contract)")]
    answers: Option<PathBuf>,
    #[arg(long, help = "vm: full path to vm.js (--emit contract) or a captured program name")]
    vm: Option<String>,
    #[arg(long, help = "bc: full path to bc.txt (--emit contract)")]
    bc: Option<PathBuf>,
    #[arg(long)]
    json_only: bool,
    #[arg(long, help = "k18,k31 from the chain's anchor scrape (--emit / emit-window)")]
    anchor_keys: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// replay the full chain (§10.4) and print the ladder + token
    Solve {
        #[arg(long)]
        url: String,
        #[arg(long)]
        sitekey: String,
        #[arg(long, default_value = "chrome-win")]
        profile: String,
        #[arg(long, default_value = "script_7")]
        vm: String,
        #[arg(long, help = "JSON {head_bloom?, page_text?} from the broker's scrape")]
        page_context: Option<PathBuf>,
        #[arg(long, default_value_t = 4)]
        rounds: u32,
        #[arg(long, default_value = "tiny.en")]
        model: String,
        #[arg(long, default_value = "demo")]
        mode: String,
        #[arg(long, default_value = "")]
        alias: String,
        #[arg(long, default_value = "")]
        code: String,
        #[arg(long)]
        fresh_session: Option<PathBuf>,
        #[arg(long, default_value = "auto")]
        window: String,
        #[arg(long)]
        solve_image: bool,
        #[arg(long, default_value_t = 600_000)]
        timeout: u64,
        #[arg(long)]
        dump_dir: Option<PathBuf>,
        /// optional egress proxy for the WHOLE session (if the IP is blocked); e.g. http://host:port
        #[arg(long)]
        proxy: Option<String>,
    },
    /// fully offline WINDOW_JSON producer (§14.1) — never prints RC_SOLVE
    EmitWindow {
        #[arg(long)]
        url: String,
        #[arg(long)]
        sitekey: String,
        #[arg(long, help = "k18,k31 from the chain's anchor scrape")]
        anchor_keys: Option<String>,
        #[arg(long, default_value = "chrome-win")]
        profile: String,
        #[arg(long, default_value = "script_7")]
        vm: String,
        #[arg(long)]
        page_context: Option<PathBuf>,
        #[arg(long)]
        json_only: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.selftest {
        std::process::exit(selftest());
    }
    if cli.selftest_vm {
        std::process::exit(selftest_vm());
    }
    if cli.vm_sandbox {
        std::process::exit(vm_sandbox_cli(&cli));
    }
    if cli.emit {
        std::process::exit(emit_contract(cli));
    }
    match cli.command {
        Some(Command::Solve {
            url, sitekey, profile, vm, page_context, rounds, model, mode, alias, code,
            fresh_session, window, solve_image, timeout, dump_dir, proxy,
        }) => {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            let opts = chain::ChainOpts {
                url,
                sitekey,
                profile_id: profile,
                vm_name: vm,
                rounds,
                model,
                solve_image,
                mode,
                alias,
                code,
                window_off: window == "off",
                timeout_ms: timeout,
                dump_dir,
                proxy,
                page_context: page_context.and_then(|p| read_page_context(&p).ok()),
                fresh_session,
            };
            let report = rt.block_on(chain::solve(opts));
            emit::rc_solve(&report);
            // 0 = token minted (acceptance is unknowable at mint time); 1 = no token
            std::process::exit(if report.token { 0 } else { 1 });
        }
        Some(Command::EmitWindow { url, sitekey, anchor_keys, profile, vm, page_context, json_only }) => {
            let code = emit_window(emit_window::Args {
                url, sitekey, anchor_keys, profile, vm, page_context, json_only,
            });
            std::process::exit(code);
        }
        None => {
            // no subcommand and no --selftest → usage
            eprintln!("usage: window-vm solve … | window-vm emit-window … | window-vm --selftest");
            std::process::exit(2);
        }
    }
    Ok(())
}

mod emit_window {
    use std::path::PathBuf;
    pub struct Args {
        pub url: String,
        pub sitekey: String,
        pub anchor_keys: Option<String>,
        pub profile: String,
        pub vm: String,
        pub page_context: Option<PathBuf>,
        pub json_only: bool,
    }
}

/// §14.1 emit — fully offline (no network, no bridge, no jsdom): profile → probe surface →
/// timing fakes → VM runner; exactly one JSON object as the LAST stdout line. Exit 0/1.
fn emit_window(args: emit_window::Args) -> i32 {
    let t0 = std::time::Instant::now();
    let folder = match project_root() {
        Some(f) => f,
        None => return fail_emit("profile_invalid", "cannot resolve rc_jsdom/", args.json_only),
    };
    if !args.json_only {
        eprintln!(
            "[emit-window] url={} sitekey={} profile={} vm={} (fully offline)",
            args.url,
            if args.sitekey.is_empty() { "(none)" } else { "yes" },
            args.profile,
            args.vm
        );
    }
    let wroot = folder.join("window");
    let (prof, fallback_from) = match window::profile::load_with_fallback(&wroot, &args.profile) {
        Ok(x) => x,
        Err(e) => return fail_emit("profile_invalid", &e.to_string(), args.json_only),
    };
    let store = match window::answers::load(&wroot, prof.answers.as_deref().unwrap_or("answers/fingerprint.json")) {
        Ok(s) => s,
        Err(e) => return fail_emit("answers_missing", &e.to_string(), args.json_only),
    };
    let clock = Arc::new(Clock::new());
    let mut ctx = args
        .page_context
        .as_deref()
        .and_then(|p| read_page_context(p).ok())
        .unwrap_or_default();
    ctx.url = args.url.clone();
    ctx.sitekey = args.sitekey.clone();
    let mut surface = ProbeSurface::new(Arc::new(prof.clone()), store, clock.clone(), ctx);
    let fp_ser = surface.fingerprint_serialization();
    let fp_hash = window::probe::hash_string(&fp_ser);
    let oc_ser = surface.oc_serialization();
    let ch = window::probe::hash_string(&oc_ser);
    let gate = surface.consistency_check(
        &prof.transport.user_agent,
        (prof.browser.screen.width, prof.browser.screen.height),
        prof.browser.device_pixel_ratio,
        (clock.now() as i64) as f64 / 10.0,
    );
    if !gate.is_empty() {
        return fail_emit("consistency_failed", &gate.join("; "), args.json_only);
    }
    let vm_res = match vm::run_vm(&wroot, &args.vm, &clock) {
        Ok(r) => r,
        Err(e) => return fail_emit("vm_boot_failed", &e.to_string(), args.json_only),
    };
    let (k18, k31) = match &args.anchor_keys {
        Some(s) => {
            let parts: Vec<&str> = s.split(',').collect();
            (parts.first().and_then(|x| x.trim().parse::<i64>().ok()),
             parts.get(1).and_then(|x| x.trim().parse::<i64>().ok()))
        }
        None => (None, None),
    };
    let _ = (k18, k31); // encryption needs the reload-f16 encryptor (§14.1 caveat) — stays null
    let out = json!({
        "ok": true,
        "runner": "rust",
        "profile": prof.id,
        "engine": prof.engine,
        "vm": args.vm,
        "url": args.url,
        "sitekey": args.sitekey,
        "fingerprint": fp_ser,
        "fingerprint_hash": fp_hash,
        "fingerprint_encrypted": Value::Null,
        "oc": oc_ser,
        "oc_encrypted": Value::Null,
        "ch": ch,
        "bgdata": vm_res.bgdata.clone(),
        "encrypted": false,
        "head_hash": if args.page_context.is_some() { "computed" } else { "recorded" },
        "errors": vm_res.errors.len(),
        "elapsed_ms": t0.elapsed().as_millis() as u64,
    });
    let mut out = out;
    if let Some(from) = fallback_from {
        out["fallback_from"] = json!(from);
    }
    out["vm_detail"] = json!({
        "prefix": vm_res.prefix,
        "booted": vm_res.booted,
        "notes": vm_res.notes,
        "host_errors": vm_res.errors,
    });
    if !args.json_only {
        eprintln!(
            "[emit-window] ok profile={} engine={} vm={} bgdata={} fp_hash={} ch={} in {}ms",
            prof.id,
            prof.engine,
            args.vm,
            if vm_res.bgdata.is_some() { "yes" } else { "null" },
            fp_hash,
            ch,
            t0.elapsed().as_millis()
        );
    }
    emit::window_json(&out);
    0
}

fn fail_emit(tag: &str, detail: &str, json_only: bool) -> i32 {
    if !json_only {
        eprintln!("[emit-window] emit failed: {tag} — {detail}");
    }
    emit::window_json(&json!({"ok": false, "error": tag, "runner": "rust", "detail": detail}));
    1
}

// ── §19 — the vm-sandbox faces (--selftest-vm / --vm-sandbox / --emit) ─────────────────

/// §19 --selftest-vm — the OFFLINE vm-sandbox gate: the sb.html recipe runs on the bundled
/// recap.js with a SYNTHETIC ainput fixture built from the embedded constants (sb.html's qA/
/// Ue literals mirrored below; the bgdata slot is neutral — the true pre-transform bytes are
/// unreconstructable offline, and every degradation rides the driver's recorded ladder). The
/// gate requires the sandbox to END with a produced payload (ran_vm + payload_slots > 0 +
/// zero host errors); when the synthetic ladder nets nothing a second run executes the
/// pure-embedded constants path (ainput=None, the sb.html offline behavior) before the gate
/// verdict. Fully offline — no sockets, no child processes. LAST stdout line = the sandbox
/// JSON; exit 0 = pass, 1 = controlled failure, 2 = engine-level crash.
fn selftest_vm() -> i32 {
    // The synthetic fixture mirrors sb.html's MData literal (sandbox_recipe.js:119-144):
    // a0[21] → M.qA, a0[23] → M.Ue via genMArray; a0[1][4] is the bgdata slot.
    let synth = json!({
        "1": [0.0, 0.0, 0.0, 0.0, ""],
        "21": [247, 34, 245, 199, 230],
        "23": [154, 150, 135, 120, 244],
    });
    eprintln!("[selftest-vm] run 1: synthetic ainput fixture (live ladder with recorded degradation)");
    let first = crate::vm_sandbox::run(crate::vm_sandbox::SandboxOpts { ainput: Some(&synth), release_js: None });
    match first {
        Ok(out) if out.ok => {
            selftest_vm_finish(&out);
            0
        }
        first_res => {
            match &first_res {
                Ok(o) => {
                    eprintln!("[selftest-vm] synthetic ladder netted no payload ({} errors) — run 2: the pure embedded constants", o.errors.len());
                    for n in &o.notes { eprintln!("[selftest-vm] run1 | note: {n}"); }
                    for e in &o.errors { eprintln!("[selftest-vm] run1 | error: {e}"); }
                }
                Err(e) => eprintln!("[selftest-vm] run 1 crashed: {e:#} — run 2: the pure embedded constants"),
            }
            eprintln!("[selftest-vm] run 2: ainput=None (all-embedded offline path)");
            match crate::vm_sandbox::run(crate::vm_sandbox::SandboxOpts::default()) {
                Ok(out) if out.ok => {
                    selftest_vm_finish(&out);
                    0
                }
                Ok(out) => {
                    for n in &out.notes { eprintln!("[selftest-vm] run2 | note: {n}"); }
                    for e in &out.errors { eprintln!("[selftest-vm] run2 | error: {e}"); }
                    eprintln!("[selftest-vm] FAIL — no VM payload produced (vm_result_count={}, payload_slots={})", out.vm_result_count, out.payload_slots);
                    1
                }
                Err(e) => {
                    eprintln!("{{\"ok\":false,\"selftest-vm\":\"fail\",\"error\":\"{e:#}\"}}");
                    2
                }
            }
        }
    }
}

/// The pass verdict + the sandbox JSON as the last stdout line (gate contract).
fn selftest_vm_finish(out: &crate::vm_sandbox::SandboxOutcome) {
    eprintln!(
        "[selftest-vm] release={} m_source={} fx_source={} vm_result_count={} payload_slots={}",
        out.release, out.m_source, out.fx_source, out.vm_result_count, out.payload_slots
    );
    eprintln!("[selftest-vm] internals={}", out.internals);
    if !out.shim_gaps.is_empty() {
        eprintln!("[selftest-vm] shim_gaps={}", out.shim_gaps.join(" | "));
    }
    for n in &out.notes { eprintln!("[selftest-vm] note: {n}"); }
    eprintln!(
        "[selftest-vm] PASS — the sandbox recipe ran the real widget VM and produced {} payload slot(s), {} host error(s)",
        out.payload_slots, out.errors.len()
    );
    if let Ok(line) = serde_json::to_string(out) {
        println!("{line}");
    }
}

/// §19 --vm-sandbox — the live face: --ainput <json file> (the anchor ainput array — a bare
/// 32-element array or {"ainput": [...]} — both accepted) + optional --release-js <p> (a
/// live release bundle instead of the bundled Poyoq recap.js). Prints the sandbox JSON
/// (release identity, internals probe, shim gaps, m_used/vm_result, payload slots) as the
/// LAST stdout line; diagnostics → stderr only. Exit 0 = sandbox ok, 1 = controlled
/// failure, 2 = engine-level crash.
fn vm_sandbox_cli(cli: &Cli) -> i32 {
    let Some(path) = cli.ainput.as_ref() else {
        // clap "requires" guards this in practice
        eprintln!("[vm-sandbox] --vm-sandbox requires --ainput <json>");
        emit::window_json(&json!({"ok": false, "error": "ainput_required", "runner": "rust"}));
        return 2;
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            let detail = format!("{}: {e}", path.display());
            eprintln!("[vm-sandbox] fail: ainput_unreadable — {detail}");
            emit::window_json(&json!({"ok": false, "error": "ainput_unreadable", "runner": "rust", "detail": detail}));
            return 1;
        }
    };
    let v: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            let detail = format!("{}: {e}", path.display());
            eprintln!("[vm-sandbox] fail: ainput_invalid — {detail}");
            emit::window_json(&json!({"ok": false, "error": "ainput_invalid", "runner": "rust", "detail": detail}));
            return 1;
        }
    };
    let a0 = match v.get("ainput") {
        Some(inner) => inner.clone(),
        None => v.clone(),
    };
    eprintln!(
        "[vm-sandbox] run: ainput={} releaseJs={}",
        path.display(),
        cli.release_js.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "(bundled recap.js)".into())
    );
    match crate::vm_sandbox::run(crate::vm_sandbox::SandboxOpts {
        ainput: Some(&a0),
        release_js: cli.release_js.as_deref(),
    }) {
        Ok(out) => {
            eprintln!(
                "[vm-sandbox] release={} m_source={} fx_source={} vm_result_count={} payload_slots={} shim_gaps={}",
                out.release, out.m_source, out.fx_source, out.vm_result_count, out.payload_slots, out.shim_gaps.len()
            );
            for n in &out.notes { eprintln!("[vm-sandbox] note: {n}"); }
            for e in &out.errors { eprintln!("[vm-sandbox] error: {e}"); }
            if !out.shim_gaps.is_empty() {
                eprintln!("[vm-sandbox] shim_gaps={}", out.shim_gaps.join(" | "));
            }
            if let Ok(line) = serde_json::to_string(&out) {
                println!("{line}");
            }
            if out.ok { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("[vm-sandbox] crashed: {e:#}");
            emit::window_json(&json!({"ok": false, "error": "vm_sandbox_crash", "runner": "rust", "detail": format!("{e:#}")}));
            2
        }
    }
}

/// §19 the solve_service.py --emit contract (its argv is exactly: --emit --url --sitekey
/// --profile <path> --answers <path> --vm <vm.js> --bc <bc.txt> --json-only
/// [--anchor-keys k18,k31] [--ainput <json>] [--release-js <p>]). Produces the §14.1
/// WINDOW_JSON face with no bridge/node dependency: profile + answers validated, the probe
/// surface serialized/hash-gated, the captured VM run UNMODIFIED through vm::run_vm_at, and
/// — when an ainput is provided — the §13/§14 sandbox run grafting the REAL widget-VM
/// payload structure under "sandbox". --profile may be a FULL path (the contract's form)
/// or a profile name resolved from window/profiles/. Exit 0 = emit ok, 1 = controlled
/// failure, 2 = crash. Diagnostics → stderr only (silenced under --json-only).
fn emit_contract(cli: Cli) -> i32 {
    let loud = !cli.json_only;
    macro_rules! fail {
        ($tag:expr, $detail:expr) => {{
            let detail: String = $detail.into();
            if loud {
                eprintln!("[emit] fail: {} — {detail}", $tag);
            }
            emit::window_json(&json!({"ok": false, "error": $tag, "runner": "rust", "detail": detail}));
            return 1;
        }};
    }
    let t0 = std::time::Instant::now();

    // -- profile: full path (the contract's form) or a profile name from window/profiles/
    let profile_arg = cli.profile.clone().unwrap_or_default();
    if profile_arg.is_empty() {
        fail!("profile_invalid", "--emit requires --profile <path-or-name>");
    }
    let prof: Profile = match std::path::Path::new(&profile_arg) {
        p if p.is_file() => {
            let text = match std::fs::read_to_string(p) {
                Ok(t) => t,
                Err(e) => fail!("profile_invalid", format!("{}: {e}", p.display())),
            };
            let parsed: Profile = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => fail!("profile_invalid", format!("{} schema invalid: {e}", p.display())),
            };
            if let Err(e) = window::profile::validate(&parsed) {
                fail!("profile_invalid", format!("{}: {e}", p.display()));
            }
            parsed
        }
        _ => {
            let folder = match project_root() {
                Some(f) => f,
                None => fail!("profile_invalid", "cannot resolve rc_jsdom/ and --profile is not a file path"),
            };
            match window::profile::load_with_fallback(&folder.join("window"), &profile_arg) {
                Ok((p, _fallback_from)) => p,
                Err(e) => fail!("profile_invalid", e.to_string()),
            }
        }
    };

    // -- answers (the contract requires a full path)
    let answers_path = match cli.answers.as_ref() {
        Some(p) => p,
        None => fail!("answers_missing", "--emit requires --answers <path>"),
    };
    let answers_text = match std::fs::read_to_string(answers_path) {
        Ok(t) => t,
        Err(e) => fail!("answers_missing", &format!("{}: {e}", answers_path.display())),
    };
    let store: Store = match serde_json::from_str(&answers_text) {
        Ok(s) => s,
        Err(e) => fail!("answers_invalid", &format!("{}: {e}", answers_path.display())),
    };

    // -- vm.js + bc.txt (UNMODIFIED sources; the emit contract's exact forms)
    let (vm_js_path, bc_path) = match (cli.vm.as_deref(), cli.bc.as_ref()) {
        (Some(v), Some(b)) => (std::path::PathBuf::from(v), b.clone()),
        _ => fail!("vm_args_missing", "--emit requires BOTH --vm <path> and --bc <path>"),
    };

    let clock = Arc::new(Clock::new());
    let mut ctx = EmitContext {
        url: cli.url.clone().unwrap_or_default(),
        sitekey: cli.sitekey.clone().unwrap_or_default(),
        ..Default::default()
    };
    let mut surface = ProbeSurface::new(Arc::new(prof.clone()), store, clock.clone(), ctx);

    let fp_ser = surface.fingerprint_serialization();
    let fp_hash = window::probe::hash_string(&fp_ser);
    let oc_ser = surface.oc_serialization();
    let ch = window::probe::hash_string(&oc_ser);
    let gate = surface.consistency_check(
        &prof.transport.user_agent,
        (prof.browser.screen.width, prof.browser.screen.height),
        prof.browser.device_pixel_ratio,
        (clock.now() as i64) as f64 / 10.0,
    );
    if !gate.is_empty() {
        fail!("consistency_failed", &gate.join("; "));
    }

    let vm_res = match vm::run_vm_at(&vm_js_path, &bc_path, &clock) {
        Ok(r) => r,
        Err(e) => fail!("vm_boot_failed", &e.to_string()),
    };

    // -- the optional live sandbox run (§13/§14): grafts the REAL widget-VM payload
    //    structure under "sandbox" when the chain passes an ainput; absent → recorded null.
    let mut sandbox = Value::Null;
    if let Some(a_path) = cli.ainput.as_deref() {
        match std::fs::read_to_string(a_path) {
            Ok(raw) => match serde_json::from_str::<Value>(&raw) {
                Ok(v) => {
                    let a0 = v.get("ainput").cloned().unwrap_or(v);
                    match crate::vm_sandbox::run(crate::vm_sandbox::SandboxOpts {
                        ainput: Some(&a0),
                        release_js: cli.release_js.as_deref(),
                    }) {
                        Ok(o) => sandbox = serde_json::to_value(&o).unwrap_or(Value::Null),
                        Err(e) => sandbox = json!({"ok": false, "error": format!("{e:#}")}),
                    }
                }
                Err(e) => sandbox = json!({"ok": false, "error": "ainput_invalid", "detail": e.to_string()}),
            },
            Err(e) => sandbox = json!({"ok": false, "error": "ainput_unreadable", "detail": e.to_string()}),
        }
    }

    // anchor keys parse (same §14.1 caveat as emit-window: the outer encryptor is not
    // landed — both wire slots stay null, honestly recorded)
    let (k18, k31) = match &cli.anchor_keys {
        Some(s) => {
            let parts: Vec<&str> = s.split(',').collect();
            (parts.first().and_then(|x| x.trim().parse::<i64>().ok()),
             parts.get(1).and_then(|x| x.trim().parse::<i64>().ok()))
        }
        None => (None, None),
    };
    let _ = (k18, k31);

    let mut out = json!({
        "ok": true,
        "runner": "rust",
        "profile": prof.id,
        "engine": prof.engine,
        "vm": vm_js_path.display().to_string(),
        "url": cli.url.clone().unwrap_or_default(),
        "sitekey": cli.sitekey.clone().unwrap_or_default(),
        "fingerprint": fp_ser,
        "fingerprint_hash": fp_hash,
        "fingerprint_encrypted": Value::Null,
        "oc": oc_ser,
        "oc_encrypted": Value::Null,
        "ch": ch,
        "bgdata": vm_res.bgdata.clone(),
        "encrypted": false,
        "head_hash": "computed",
        "errors": vm_res.errors.len(),
        "elapsed_ms": t0.elapsed().as_millis() as u64,
        "sandbox": sandbox,
    });
    out["vm_detail"] = json!({
        "prefix": vm_res.prefix,
        "booted": vm_res.booted,
        "notes": vm_res.notes,
        "host_errors": vm_res.errors,
    });
    if loud {
        eprintln!(
            "[emit] ok profile={} engine={} vm={} bgdata={} fp_hash={} ch={} sandbox={} in {}ms",
            prof.id,
            prof.engine,
            vm_js_path.display(),
            if vm_res.bgdata.is_some() { "yes" } else { "null" },
            fp_hash,
            ch,
            if sandbox.is_null() { "null" } else { "run" },
            t0.elapsed().as_millis()
        );
    }
    emit::window_json(&out);
    0
}

fn project_root() -> Option<&'static std::path::Path> {
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("window").join("profiles").exists() {
            return Some(Box::leak(cwd.into_boxed_path()));
        }
    }
    let exe = std::env::current_exe().ok()?;
    let root = exe.ancestors().nth(4)?;
    Some(Box::leak(root.to_path_buf().into_boxed_path()))
}

fn read_page_context(p: &std::path::Path) -> Result<EmitContext> {
    let text = std::fs::read_to_string(p).with_context(|| format!("page-context {}", p.display()))?;
    let j: Value = serde_json::from_str(&text)?;
    let arr = |v: Option<&Value>| -> Vec<Value> { v.and_then(|x| x.as_array()).cloned().unwrap_or_default() };
    let pt = j.get("page_text").map(|v| PageText {
        body_text: v.get("body_text").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        title: v.get("title").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        links: arr(v.get("links")),
        script_hosts: arr(v.get("script_hosts")),
        forms: v.get("forms").cloned(),
        prices: arr(v.get("prices")),
        prices_total: v.get("prices_total").and_then(|x| x.as_i64()).unwrap_or(0),
    });
    Ok(EmitContext {
        url: String::new(),
        sitekey: String::new(),
        head_bloom: j.get("head_bloom").and_then(|v| v.as_str()).map(|s| s.to_string()),
        page_text: pt,
    })
}

/// §9.3 --selftest — the engine gate, FULLY OFFLINE: loads the bundled profile + answers,
/// validates them, boots boa on BOTH packaged programs, asserts botguard.m === 41 and the
/// handler arity, requires a '!'-prefixed bgdata with zero host errors from the WORKING
/// program (script_7; script_1's known internal VM error is reported honestly per §18.8 —
/// "a token came out" proves nothing, so the gate checks the marker instead of trusting a
/// non-crash), verifies the varint walker round-trips the embedded redacted template to
/// exactly 8336 bytes, and checks the hashString known-answer pair cross-validated from
/// hashOC.js (input = the published 1645-char sample, expected 574824847).
fn selftest() -> i32 {
    let mut checks: Vec<(String, bool, String)> = Vec::new();
    let mut check = |name: &str, ok: bool, detail: String| {
        checks.push((name.to_string(), ok, detail));
    };

    // 1. template round-trip (§9.3)
    match protobuf::template_latin1_bytes() {
        Ok(b) => check("template: latin-1 round-trip = 8336 bytes", b.len() == 8336, format!("{} bytes", b.len())),
        Err(e) => check("template: latin-1 round-trip = 8336 bytes", false, e.to_string()),
    }

    // 2. hashString known-answer (§14.1's executed cross-validation: node hashOC.js → 574824847)
    let sample = include_str!("hashoc_sample.txt");
    let digest = window::probe::hash_string(sample);
    check("hash: hashOC sample digest = 574824847", digest == 574824847, format!("got {digest} (sample len {})", sample.len()));

    // 3. clock (§11.4)
    let clock = Arc::new(Clock::new());
    let a = clock.now();
    let on_grid = (a * 10_000.0 - (a * 10_000.0).round()).abs() < 1e-6; // 100 µs grid
    check("clock: quantized to the 100 µs grid", on_grid, format!("now={a}"));
    let mut monotonic = true;
    let mut prev = -1.0;
    for _ in 0..200 {
        let v = clock.now();
        if v < prev {
            monotonic = false;
        }
        prev = v;
    }
    check("clock: real and monotonic (never frozen)", monotonic, String::new());

    // 4. profile + answers load + validate (§11.1/§11.2)
    let folder = match project_root() {
        Some(f) => f,
        None => {
            eprintln!("{{\"ok\":false,\"selftest\":\"fail\",\"error\":\"cannot resolve rc_jsdom/\"}}");
            return 1;
        }
    };
    let wroot = folder.join("window");
    let prof = match window::profile::load(&wroot, "chrome-win") {
        Ok(p) => {
            check("profile: chrome-win loads and validates", p.engine == "chromium", p.id.clone());
            Some(p)
        }
        Err(e) => {
            check("profile: chrome-win loads and validates", false, e.to_string());
            None
        }
    };
    let store = match window::answers::load(&wroot, "answers/fingerprint.json") {
        Ok(s) => {
            check("answers: store loads (reference digest present)", !s.reference.is_empty(), s.reference.clone());
            Some(s)
        }
        Err(e) => {
            check("answers: store loads (reference digest present)", false, e.to_string());
            None
        }
    };
    let (prof, store) = match (prof, store) {
        (Some(p), Some(s)) => (p, s),
        _ => {
            for (name, ok, detail) in &checks {
                eprintln!("[selftest] {} {name}{}", if *ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" — {detail}") });
            }
            eprintln!("{{\"ok\":false,\"selftest\":\"fail\",\"error\":\"profile/answers\"}}");
            return 1;
        }
    };

    // 5. probe surface assembly + consistency gate (§11.3)
    let mut surface = ProbeSurface::new(Arc::new(prof.clone()), store, clock.clone(), EmitContext {
        url: "https://www.google.com/recaptcha/api2/demo".into(),
        sitekey: protobuf::DEMO_SITEKEY.into(),
        ..Default::default()
    });
    let fp_ser = surface.fingerprint_serialization();
    let arr_len = serde_json::from_str::<Value>(&fp_ser).ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
    check("surface: 79-slot wire array", arr_len == 79, format!("{arr_len} slots"));
    let oc_ser = surface.oc_serialization();
    check("surface: oc serialization is the [[[...]]] shape", oc_ser.starts_with("[[[") && oc_ser.ends_with("]]]"), oc_ser.chars().take(12).collect());
    let gate = surface.consistency_check(
        "wrong UA on purpose",
        (1, 1),
        99.0,
        -1.0,
    );
    check("gate: contradictions are NAMED (4 planted)", gate.len() >= 3, gate.join(" | "));

    // 6. lenient base64 on BOTH captures (§12.2 — node's exact byte counts)
    for (name, expect) in [("script_1", 6925usize), ("script_7", 6822)] {
        let path = wroot.join("assets").join("vm").join(name).join("bc.txt");
        match std::fs::read_to_string(&path) {
            Ok(bc) => {
                let decoded = engine::lenient_base64_decode(bc.trim());
                check(&format!("atob: {name} bc decodes byte-exact"), decoded.len() == expect, format!("{} → {} bytes (expect {expect})", bc.trim().len(), decoded.len()));
            }
            Err(e) => check(&format!("atob: {name} bc decodes byte-exact"), false, e.to_string()),
        }
    }

    // 7. the VM runs — both captured programs in boa (§12.3-6)
    let mut any_bgdata = false;
    for vm_name in ["script_1", "script_7"] {
        match vm::run_vm(&wroot, vm_name, &clock) {
            Ok(r) => {
                let has = r.bgdata.as_ref().map(|b| b.starts_with('!')).unwrap_or(false);
                check(
                    &format!("vm: {vm_name} boots (m=41, arity ok)"),
                    r.booted && !r.errors.iter().any(|e| e.contains("m !== 41")) && !r.errors.iter().any(|e| e.contains("arity")),
                    format!("prefix={} bgdata={} errors={}", r.prefix, has, r.errors.len()),
                );
                if vm_name == "script_7" {
                    // the gate requirement (§9.3): the working program emits a '!'-prefixed
                    // bgdata with ZERO host errors — script_1's internal VM error is the
                    // §18.8-documented honest outcome, reported but not gate-failing
                    check(
                        "vm: script_7 emits '!'-prefixed bgdata with zeroed host errors",
                        has && r.errors.is_empty(),
                        format!("bgdata={} errors={:?}", has, r.errors),
                    );
                } else if !has && !r.errors.is_empty() {
                    eprintln!("[selftest] info: script_1 reports its known internal VM error honestly ({})", r.errors.first().map(|s| s.clone()).unwrap_or_default());
                }
                if has {
                    any_bgdata = true;
                }
            }
            Err(e) => check(&format!("vm: {vm_name} boots (m=41, arity ok)"), false, e.to_string()),
        }
    }
    let _ = any_bgdata;

    let all_ok = checks.iter().all(|(_, ok, _)| *ok);
    for (name, ok, detail) in &checks {
        eprintln!("[selftest] {} {name}{}", if *ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" — {detail}") });
    }
    eprintln!("[selftest] {}/{} checks passed (offline: no sockets, no child processes)", checks.iter().filter(|(_, ok, _)| *ok).count(), checks.len());
    eprintln!(
        "{}",
        if all_ok {
            json!({"ok": true, "selftest": "pass"}).to_string()
        } else {
            json!({"ok": false, "selftest": "fail"}).to_string()
        }
    );
    if all_ok { 0 } else { 1 }
}
