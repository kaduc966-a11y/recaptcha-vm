//! Facade mirroring cfsolve `src/vm.rs` module split — boot / feed / invoke / snapshot —
//! realized as REAL execution (deviation 1, DESIGN.md §9.1: the reCAPTCHA capture is a full
//! runnable program, not a register machine to disassemble). The node:vm runner
//! (`window/vm_runner.js`) is the reference statement of the §12 rules; this module ports it.

use std::sync::{Arc, Mutex};

use boa_engine::{JsValue, NativeFunction};
use serde::Serialize;

use crate::engine;
use crate::window::clock::Clock;

/// The §12.4-5 program interface, read from the captures: each bc.txt's first 3 chars name
/// the program entry ("wJo" → botguard.wJo_, "IJO" → botguard.IJO_); botguard.bg routes
/// through it. bg returns {invoke, pe}; the VM calls the arg-1 env function with 4 callbacks
/// during its run (script_7 :243-251); the token is the RETURN of invoke's sync path
/// (script_7's k==d branch builds "!" + base64url) or arrives through the env/collector
/// callbacks asynchronously.
#[derive(Debug, Serialize, Default)]
pub struct VmOutcome {
    pub bgdata: Option<String>,
    pub errors: Vec<String>,
    pub notes: Vec<String>,
    pub prefix: String,
    pub booted: bool,
    pub timer_execs: usize,
}

const MAX_DRAIN_PASSES: usize = 50;
const MAX_DRAIN_EXECS: usize = 20_000;

pub fn run_vm(folder: &std::path::Path, vm_name: &str, clock: &Arc<Clock>) -> anyhow::Result<VmOutcome> {
    // The captured VM recurses deeply; the node:vm reference ran on node's large default
    // stack. Execute on a dedicated thread with an explicit 256 MB stack (the engine
    // selftest and both emit faces run this same path).
    let folder = folder.to_path_buf();
    let vm_name = vm_name.to_string();
    let clock = clock.clone();
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || run_vm_inner(&folder, &vm_name, &clock))
        .expect("spawn the VM thread")
        .join()
        .map_err(|e| anyhow::anyhow!("VM thread panicked: {e:?}"))?
}

/// The --emit contract face (solve_service.py): the chain passes EXPLICIT vm.js/bc.txt
/// paths (folder/window/assets/vm/<name>/{vm.js,bc.txt}), not the folder+name layout
/// run_vm assumes. Same program, same §12 rules — only the acquisition differs.
pub fn run_vm_at(vm_js_path: &std::path::Path, bc_path: &std::path::Path, clock: &Arc<Clock>) -> anyhow::Result<VmOutcome> {
    let vm_js_path = vm_js_path.to_path_buf();
    let bc_path = bc_path.to_path_buf();
    let clock = clock.clone();
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            let vm_js = std::fs::read_to_string(&vm_js_path)
                .map_err(|e| anyhow::anyhow!("vm.js unreadable ({}): {e}", vm_js_path.display()))?;
            let bc = std::fs::read_to_string(&bc_path)
                .map_err(|e| anyhow::anyhow!("bc.txt unreadable ({}): {e}", bc_path.display()))?
                .trim()
                .to_string();
            run_vm_program(vm_js, bc, clock)
        })
        .expect("spawn the VM thread")
        .join()
        .map_err(|e| anyhow::anyhow!("VM thread panicked: {e:?}"))?
}

fn run_vm_inner(folder: &std::path::Path, vm_name: &str, clock: &Arc<Clock>) -> anyhow::Result<VmOutcome> {
    let vm_dir = folder.join("assets").join("vm").join(vm_name);
    let vm_js = std::fs::read_to_string(vm_dir.join("vm.js"))
        .map_err(|e| anyhow::anyhow!("vm.js unreadable ({}): {e}", vm_dir.display()))?; // UNMODIFIED source
    let bc = std::fs::read_to_string(vm_dir.join("bc.txt"))
        .map_err(|e| anyhow::anyhow!("bc.txt unreadable ({}): {e}", vm_dir.display()))?
        .trim()
        .to_string(); // §12.4: utf8, trim only
    run_vm_program(vm_js, bc, clock.clone())
}

fn run_vm_program(vm_js: String, bc: String, clock: Arc<Clock>) -> anyhow::Result<VmOutcome> {
    let prefix = format!("{}_", &bc[..3.min(bc.len())]);

    let mut out = VmOutcome { prefix, booted: false, ..Default::default() };

    let mut realm = engine::boot(&clock)?;

    // §12.3 boot — run the UNMODIFIED source; assert the registration markers
    engine::eval_script(&mut realm.ctx, &format!("{}/vm.js", out.prefix.trim_end_matches('_')), &vm_js)
        .map_err(|e| anyhow::anyhow!("boot: {e}"))?;
    out.booted = true;

    let botguard = realm.ctx
        .global_object()
        .get(boa_engine::JsString::from("botguard"), &mut realm.ctx)
        .map_err(|e| anyhow::anyhow!("read botguard: {e}"))?;
    let botguard_obj = botguard
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("boot: botguard is not an object"))?;
    let m = botguard_obj
        .get(boa_engine::JsString::from("m"), &mut realm.ctx)
        .map_err(|e| anyhow::anyhow!("read botguard.m: {e}"))?;
    if m.as_number() != Some(41.0) {
        anyhow::bail!("boot: botguard.m !== 41 ({:?})", m.as_number());
    }
    let program_fn = botguard_obj
        .get(boa_engine::JsString::from(out.prefix.clone()), &mut realm.ctx)
        .map_err(|e| anyhow::anyhow!("read botguard.{}: {e}", out.prefix))?;
    if program_fn.as_callable().is_none() {
        anyhow::bail!("boot: botguard.{} is not a function (handler arity)", out.prefix);
    }

    // §12.4 arg wiring — the env function is an observe-only recorder; no VM intrinsic or
    // VM function is patched (§12.6). The collector records the async token delivery.
    // SAFETY: the closures capture only Rust state (Arc<Mutex<Vec<…>>> / Arc<Mutex<Option<String>>>
    // holding Strings) — no GC-traceable JsValues — boa's stated from_closure invariant.
    let env_state: Arc<Mutex<Vec<boa_engine::JsObject>>> = Arc::new(Mutex::new(Vec::new()));
    let env_state2 = env_state.clone();
    let env_fn_native = unsafe {
        NativeFunction::from_closure(move |_this, args: &[JsValue], _ctx| {
            for a in args {
                if let Some(o) = a.as_callable() {
                    env_state2.lock().expect("env state").push(o.clone());
                }
            }
            Ok(JsValue::undefined())
        })
    };
    let env_fn = JsValue::from(env_fn_native.to_js_function(realm.ctx.realm()));

    let delivered: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let delivered2 = delivered.clone();
    let collector_native = unsafe {
        NativeFunction::from_closure(move |_this, args: &[JsValue], _ctx| {
            if let Some(s) = args.first().and_then(|v| v.as_string()) {
                let s = s.to_std_string_escaped();
                if s.starts_with('!') {
                    *delivered2.lock().expect("delivered state") = Some(s);
                }
            }
            Ok(JsValue::undefined())
        })
    };
    let collector_fn = JsValue::from(collector_native.to_js_function(realm.ctx.realm()));

    let timing_cb = JsValue::from(
        NativeFunction::from_fn_ptr(|_, _, _| Ok(JsValue::undefined())).to_js_function(realm.ctx.realm()),
    ); // §12.4 arg4 (qC carrier) — observer no-op

    let two_elem = realm.ctx
        .eval(boa_engine::Source::from_bytes(b"[(function(){}),(function(){})]"))
        .map_err(|e| anyhow::anyhow!("build twoElem: {e}"))?; // §12.4 arg5
    let cfg_json = JsValue::from(boa_engine::JsString::from("{\"t\":30000}")); // §12.4 arg6 ({"t": timeoutMs})

    // entry 1 — botguard.bg (the registered program face; script_1's L1 / script_7's $p)
    let bg_args = vec![
        JsValue::from(boa_engine::JsString::from(bc.clone())),
        env_fn.clone(),
        JsValue::undefined(),
        JsValue::undefined(),
        timing_cb.clone(),
        two_elem.clone(),
        cfg_json.clone(),
        JsValue::undefined(),
    ];
    let prog = botguard_obj
        .get(boa_engine::JsString::from("bg"), &mut realm.ctx)
        .map_err(|e| anyhow::anyhow!("read botguard.bg: {e}"))?;
    match prog.as_callable() {
        Some(bg_call) => {
            let prog_val = bg_call
                .call(&JsValue::from(botguard_obj.clone()), &bg_args, &mut realm.ctx)
                .map_err(|e| {
                    out.errors.push(format!("bg entry: {e}"));
                    anyhow::anyhow!("bg entry: {e}")
                })
                .unwrap_or(JsValue::undefined());
            if let Some(prog_obj) = prog_val.as_object() {
                let invoke = prog_obj.get(boa_engine::JsString::from("invoke"), &mut realm.ctx).ok();
                if let Some(invoke_fn) = invoke.and_then(|v| v.as_callable().map(|c| c.clone())) {
                    // sync path (script_1's L1: if(!B) return B=X(z); script_7's k==d builds "!" + …)
                    let sync_args = vec![JsValue::null(), JsValue::undefined(), JsValue::from(boa_engine::JsString::from(""))];
                    match invoke_fn.call(&JsValue::undefined(), &sync_args, &mut realm.ctx) {
                        Ok(tok) => {
                            if let Some(s) = tok.as_string() {
                                let s = s.to_std_string_escaped();
                                if s.starts_with('!') {
                                    out.bgdata = Some(s);
                                } else if s.starts_with("E:") {
                                    // the VM's own error path (VR builds "E:"+msg+":"+stack) —
                                    // "a token came out" proves nothing (§12.6)
                                    out.errors.push(format!("vm-internal: {}", &s[..s.len().min(120)]));
                                    out.notes.push(format!("sync invoke returned the VM error string ({})", &s[..s.len().min(60)]));
                                } else {
                                    out.notes.push(format!("sync invoke returned a string (len {})", s.len()));
                                }
                            } else if !tok.is_undefined() && !tok.is_null() {
                                out.notes.push(format!("sync invoke returned {}", tok.type_of()));
                            }
                        }
                        Err(e) => out.errors.push(format!("invoke-sync: {e}")),
                    }
                    // async path (script_1's f(): F(function(w){…S(w)}, z) — the token is
                    // delivered to the FIRST argument's callback) with event-loop drains,
                    // because the VM scheduler runs its steps via setImmediate
                    if out.bgdata.is_none() {
                        let async_args = vec![JsValue::from(collector_fn.clone()), JsValue::from(true), JsValue::from(boa_engine::JsString::from(""))];
                        if let Err(e) = invoke_fn.call(&JsValue::undefined(), &async_args, &mut realm.ctx) {
                            out.errors.push(format!("invoke-async: {e}"));
                        }
                        for _ in 0..MAX_DRAIN_PASSES {
                            if out.bgdata.is_some() {
                                break;
                            }
                            realm.drain(MAX_DRAIN_EXECS);
                            if let Some(d) = delivered.lock().expect("delivered").clone() {
                                out.bgdata = Some(d);
                            }
                        }
                    }
                    if out.bgdata.is_none() {
                        out.notes.push("bg entry: no \"!\" token after sync + async with drained waits".into());
                    }
                } else {
                    out.notes.push("bg entry returned no invoke() function".into());
                    out.errors.push("vm_handler_arity: bg returned no invoke()".into());
                }
            } else if prog_val.is_undefined() {
                // bg threw above and was recorded; nothing more to do here
            } else {
                out.notes.push(format!("bg entry returned {}", prog_val.type_of()));
            }
        }
        None => {
            out.notes.push("botguard.bg is not a function".into());
            out.errors.push("vm_handler_arity: botguard.bg missing".into());
        }
    }

    // entry 2 — the full-surface `a` entry (XQ/wz with §12.4's traced arg positions)
    if out.bgdata.is_none() {
        let a_args = vec![
            JsValue::from(boa_engine::JsString::from(bc)),
            env_fn,
            JsValue::undefined(),
            JsValue::undefined(),
            timing_cb,
            two_elem,
            cfg_json,
            JsValue::undefined(),
        ];
        let a_fn = botguard_obj.get(boa_engine::JsString::from("a"), &mut realm.ctx).ok();
        match a_fn.and_then(|v| v.as_callable().map(|c| c.clone())) {
            Some(a_call) => {
                let inst = a_call
                    .call(&JsValue::from(botguard_obj.clone()), &a_args, &mut realm.ctx)
                    .map_err(|e| {
                        out.errors.push(format!("a entry: {e}"));
                        anyhow::anyhow!("a entry: {e}")
                    })
                    .unwrap_or(JsValue::undefined());
                let invoke_fn = if let Some(arr) = inst.as_object() {
                    if arr.is_array() {
                        arr.get(0, &mut realm.ctx).ok().and_then(|v| v.as_callable().map(|c| c.clone()))
                    } else {
                        arr.get(boa_engine::JsString::from("invoke"), &mut realm.ctx)
                            .ok()
                            .and_then(|v| v.as_callable().map(|c| c.clone()))
                    }
                } else {
                    None
                };
                if let Some(invoke_fn) = invoke_fn {
                    let collector_args = vec![JsValue::from(collector_fn)];
                    if let Err(e) = invoke_fn.call(&JsValue::undefined(), &collector_args, &mut realm.ctx) {
                        out.errors.push(format!("a-invoke: {e}"));
                    }
                    for _ in 0..MAX_DRAIN_PASSES {
                        if out.bgdata.is_some() {
                            break;
                        }
                        realm.drain(MAX_DRAIN_EXECS);
                        if let Some(d) = delivered.lock().expect("delivered").clone() {
                            out.bgdata = Some(d);
                        }
                    }
                    if out.bgdata.is_none() {
                        out.notes.push("a entry: no \"!\" token after sync + drained waits".into());
                    }
                } else {
                    out.notes.push("a entry returned no invocable function".into());
                    out.errors.push("vm_handler_arity: a entry returned no invoke".into());
                }
            }
            None => {
                out.notes.push("botguard.a is not a function".into());
                out.errors.push("vm_handler_arity: botguard.a missing".into());
            }
        }
    }

    out.timer_execs = realm.drain(MAX_DRAIN_EXECS);
    Ok(out)
}
