//! The boa host (DESIGN.md §9.2 engine/, §12.2 sandbox). Rules identical to the node:vm
//! reference implementation (`window/vm_runner.js` — the reference statement of these rules):
//!
//! - a realm whose global IS `window` (the IIFE is `.call(window)`, script_7/vm.js:774);
//! - `document = { hidden:false, readyState:'complete', addEventListener(){}, … }` — plain
//!   JS, no natives needed (hidden gate :164-168, readyState :255);
//! - `performance = { timeOrigin, timing:{navigationStart}, now() }` — the REAL clock with
//!   the §11.4 resolution faked (native `now` over window/clock.rs);
//! - host `setTimeout`/`setImmediate`/`clearTimeout`/`clearImmediate` on the context global
//!   (the scheduler reads bare identifiers, script_7 :593-604; requestIdleCallback
//!   deliberately ABSENT so setImmediate is chosen, as in any non-browser host);
//! - LENIENT `atob` — strict atob rejects both captured bc.txt files; the string must stay
//!   byte-exact (latin-1 1:1) — any trim/pad shift desynchronizes the ARX keystream
//!   (script_7/vm.js:322-330);
//! - `btoa` present (absent btoa silently degrades the token to hex, :701-704);
//! - trustedTypes left undefined (benign, :148-158); console omitted (optional);
//! - host intrinsics (Math, JSON, Date, Promise, Symbol, Object, eval) are NEVER wrapped or
//!   proxied (§12.6 integrity — `integCheckBypass` metadata lives on functions the VM calls;
//!   a replacement shim lacking it decodes a different call shape and fails into the
//!   error-token path).
//!
//! Timers run on a plain Rust queue drained between phases (boa has no event loop of its
//! own); this mirrors the node runner's setImmediate drains.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use boa_engine::{Context, JsObject, JsResult, JsValue, NativeFunction};

use crate::window::clock::Clock;

/// A scheduled callback queue: FIFO, mirroring setImmediate ordering.
#[derive(Default)]
pub struct TimerQueue {
    next_id: u64,
    pending: VecDeque<(u64, JsObject)>,
    cancelled: HashSet<u64>,
}

pub type SharedTimers = Arc<Mutex<TimerQueue>>;

pub struct Realm {
    pub ctx: Context,
    pub timers: SharedTimers,
}

impl Realm {
    /// Drain pending timer callbacks until the queue is empty (newly scheduled callbacks
    /// run in later passes). Returns the number executed — the honest observable for
    /// "the scheduler actually ran".
    pub fn drain(&mut self, max_execs: usize) -> usize {
        let mut execs = 0usize;
        loop {
            let next = {
                let mut q = self.timers.lock().expect("timer queue poisoned");
                loop {
                    match q.pending.pop_front() {
                        None => return execs,
                        Some((id, f)) => {
                            if q.cancelled.remove(&id) {
                                continue;
                            }
                            break f;
                        }
                    }
                }
            };
            let _ = next.call(&JsValue::undefined(), &[], &mut self.ctx);
            execs += 1;
            if execs >= max_execs {
                return execs;
            }
        }
    }
}

// ── lenient base64 (node Buffer.from semantics; §12.2) ────────────────────────────────

fn b64_sextet(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode like node's `Buffer.from(s, 'base64')`: whitespace ignored, invalid chars
/// skipped, quads emitted as they complete, '=' counts as in-quad padding, and a
/// dangling tail of 2/3 data chars yields 1/2 bytes (1 char → nothing). The §9.3
/// selftest pins the exact byte counts of both captures against node's output.
pub fn lenient_base64_decode(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len() / 4 * 3);
    let mut quad = [0u32; 4];
    let mut qi = 0usize;
    let mut pads = 0usize;
    for ch in s.chars() {
        if ch.is_whitespace() {
            continue;
        }
        if ch == '=' {
            quad[qi] = 0;
            qi += 1;
            pads += 1;
        } else if let Some(v) = b64_sextet(ch as u8) {
            if pads > 0 {
                continue; // data after a pad is ignored until the quad completes
            }
            quad[qi] = v;
            qi += 1;
        } else {
            continue; // invalid chars skipped entirely (node behavior)
        }
        if qi == 4 {
            out.push(((quad[0] << 2 | quad[1] >> 4) & 0xff) as u8);
            if pads < 2 {
                out.push(((quad[1] << 4 | quad[2] >> 2) & 0xff) as u8);
            }
            if pads < 1 {
                out.push(((quad[2] << 6 | quad[3]) & 0xff) as u8);
            }
            qi = 0;
            pads = 0;
        }
    }
    // tail without a completing quad: only REAL data sextets count (qi - pads) —
    // "XX=" (2 data + 1 pad) yields 1 byte, "XYZ" yields 2, a lone char yields 0.
    let valid = qi.saturating_sub(pads);
    if valid >= 2 {
        out.push(((quad[0] << 2 | quad[1] >> 4) & 0xff) as u8);
    }
    if valid >= 3 {
        out.push(((quad[1] << 4 | quad[2] >> 2) & 0xff) as u8);
    }
    out
}

/// Encode a latin-1 (byte-per-char) string — node `Buffer.from(s,'binary').toString('base64')`.
pub fn btoa_bin(s: &str) -> String {
    use base64::Engine as _;
    let bytes: Vec<u8> = s.chars().map(|c| u32::from(c) as u8).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn latin1_from_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

// ── the realm boot (§12.2) ────────────────────────────────────────────────────────────

/// Evaluate a script and discard the value; errors carry the script name for diagnostics.
pub fn eval_script(ctx: &mut Context, name: &str, src: &str) -> JsResult<()> {
    ctx.eval(boa_engine::Source::from_bytes(src.as_bytes()))
        .map(|_| ())
        .map_err(|e| {
            eprintln!("[js] eval {name} failed: {e}");
            e
        })
}

pub fn boot(clock: &Arc<Clock>) -> anyhow::Result<Realm> {
    let mut ctx = Context::default();
    let timers: SharedTimers = Arc::new(Mutex::new(TimerQueue::default()));

    // SAFETY: every closure below captures ONLY Rust state (Arc<Mutex<TimerQueue>>,
    // Arc<Clock>) — no GC-traceable JsValues — which is exactly boa's stated invariant
    // for `from_closure` (boa_engine-0.20.0 native_function.rs:276-283).
    macro_rules! stateful {
        ($captures:expr, $f:expr) => {
            unsafe { NativeFunction::from_closure({
                let cap = $captures;
                move |this, args, ctx| $f(this, args, &cap, ctx)
            }) }
        };
    }

    {
        let q = timers.clone();
        define(
            &mut ctx,
            "setTimeout",
            stateful!(q, |_, args: &[JsValue], timers: &SharedTimers, _| {
                schedule(args, timers)
            }),
            2,
        )?;
    }
    {
        let q = timers.clone();
        define(
            &mut ctx,
            "setImmediate",
            stateful!(q, |_, args: &[JsValue], timers: &SharedTimers, _| {
                schedule(args, timers)
            }),
            1,
        )?;
    }
    {
        let q = timers.clone();
        define(
            &mut ctx,
            "clearTimeout",
            stateful!(q, |_, args: &[JsValue], timers: &SharedTimers, _| {
                cancel(args, timers);
                Ok(JsValue::undefined())
            }),
            1,
        )?;
    }
    {
        let q = timers.clone();
        define(
            &mut ctx,
            "clearImmediate",
            stateful!(q, |_, args: &[JsValue], timers: &SharedTimers, _| {
                cancel(args, timers);
                Ok(JsValue::undefined())
            }),
            1,
        )?;
    }

    // lenient atob / btoa (stateless — fn pointers)
    define(&mut ctx, "atob", NativeFunction::from_fn_ptr(native_atob), 1)?;
    define(&mut ctx, "btoa", NativeFunction::from_fn_ptr(native_btoa), 1)?;

    // the clock native — real clock, §11.4 resolution
    {
        let c = clock.clone();
        define(
            &mut ctx,
            "__clock_now_ms",
            stateful!(c, |_, _: &[JsValue], clock: &Arc<Clock>, _| Ok(JsValue::from(clock.now()))),
            0,
        )?;
    }

    // the sandbox globals as exact JS (§12.2 — document/performance shapes are static;
    // window IS the realm global; the IIFE runs `.call(window)`)
    let t0 = clock.time_origin();
    eval_script(
        &mut ctx,
        "sandbox-bootstrap",
        &format!(
            r#"
        globalThis.window = globalThis;
        globalThis.self = globalThis;
        globalThis.document = {{
            hidden: false,
            readyState: 'complete',
            addEventListener: function () {{}},
            removeEventListener: function () {{}},
        }};
        globalThis.performance = {{
            timeOrigin: {t0},
            timing: {{ navigationStart: {t0} }},
            now: __clock_now_ms,
        }};
        "#
        ),
    )
    .map_err(|e| anyhow::anyhow!("sandbox bootstrap: {e}"))?;

    Ok(Realm { ctx, timers })
}

fn define(ctx: &mut Context, name: &str, f: NativeFunction, length: usize) -> anyhow::Result<()> {
    ctx.register_global_builtin_callable(boa_engine::JsString::from(name), length, f)
        .map_err(|e| anyhow::anyhow!("register {name}: {e}"))?;
    Ok(())
}

fn schedule(args: &[JsValue], timers: &SharedTimers) -> JsResult<JsValue> {
    let cb = args.first().cloned().unwrap_or_default();
    let f = match cb.as_callable() {
        Some(o) => o.clone(),
        None => return Ok(JsValue::from(0.0)), // no callback → nothing to schedule
    };
    let mut q = timers.lock().expect("timer queue poisoned");
    q.next_id += 1;
    let id = q.next_id;
    q.pending.push_back((id, f));
    Ok(JsValue::from(id as f64))
}

fn cancel(args: &[JsValue], timers: &SharedTimers) {
    let id = args.first().and_then(|v| v.as_number()).unwrap_or(0.0) as u64;
    if id == 0 {
        return;
    }
    let mut q = timers.lock().expect("timer queue poisoned");
    q.cancelled.insert(id);
}

fn native_atob(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    use boa_engine::JsArgs;
    let s = args.get_or_undefined(0);
    let text = s.to_string(ctx)?.to_std_string_escaped();
    let bytes = lenient_base64_decode(&text);
    Ok(JsValue::from(boa_engine::JsString::from(latin1_from_bytes(&bytes))))
}

fn native_btoa(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    use boa_engine::JsArgs;
    let s = args.get_or_undefined(0);
    let text = s.to_string(ctx)?.to_std_string_escaped();
    Ok(JsValue::from(boa_engine::JsString::from(btoa_bin(&text))))
}
