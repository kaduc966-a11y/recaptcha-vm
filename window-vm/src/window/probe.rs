//! §11.3 the probe surface — the 51-Signal + 23-VM-key registry + the undocumented
//! scheduler filler slots (the `window/probe_surface.js` port, which is the reference
//! statement of this registry; per-entry provenance from the answers store §11.2).
//!
//! Treatments: replayed (recorded device facts, byte-faithful) | computed
//! (sitekey/session/page-derived, answered at emit time) | unobserved-filler (scheduler
//! slots 43/48/66/79 — the README.md:783-787 missing-signal filler shape).
//!
//! HONEST LIMITS (§13.1 caveat): the reload-f16 encryptor has NO implementation anywhere,
//! so fingerprint_encrypted/oc_encrypted stay null with encrypted:false; the emit carries
//! the serialized PLAINTEXT arrays and the two real hashString digests.

use crate::window::answers::Store;
use crate::window::clock::Clock;
use crate::window::profile::Profile;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Real local timezone offset, minutes west of UTC — the `new Date().getTimezoneOffset()`
/// the node runner answers. std has no tz API; chrono is the one-line honest source.
fn tz_offset_minutes_west() -> i64 {
    -(chrono::Local::now().offset().local_minus_utc() as i64) / 60
}

/// recaptcha-main/README.md:444-779 counted 51; :872-1230 counted 23.
pub const SIGNAL_IDS: &[u32] = &[
    4, 5, 16, 17, 18, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 44, 45, 46,
    47, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 67, 68, 69, 70, 71,
    72, 73, 77, 78,
];
/// Scheduler-only slots (README.md:309's 35-entry scheduler carries 43/48/66/79 with no
/// catalog entry). The captured wire layout is exactly 79 slots (indices 0-78) — collector
/// 79 has no slot in the captured serialization, so only in-array fillers are emitted.
pub const FILLER_IDS: &[u32] = &[43, 48, 66, 79];
/// recaptcha-main/README.md:793-807 — VM keys serialize as [null, collector, encrypt, value].
pub const VM_KEYS: &[u32] = &[
    417, 727, 150, 545, 370, 779, 659, 959, 895, 1092, 41, 43, 549, 352, 360, 1278, 1422, 614,
    2033, 1313, 1994, 1310, 291,
];
/// The 35-entry scheduler of README.md:309.
pub const SCHEDULER: &[u32] = &[
    42, 45, 53, 30, 28, 54, 29, 31, 32, 33, 34, 35, 37, 36, 38, 39, 43, 40, 41, 46, 48, 57, 58,
    60, 61, 62, 63, 64, 66, 68, 69, 71, 72, 79, 55,
];

/// hashFingerprint.js:8-19 / hashOC.js:8-14 — the Java-style 31·hash+c hashString, signed 32.
pub fn hash_string(data: &str) -> i32 {
    hash_string_num(data, 0)
}

pub fn hash_string_num(data: &str, num_at: i32) -> i32 {
    let mut h = num_at;
    for ch in data.chars() {
        // ((h << 5) - h + code) >>> 0 then signed-32, exactly as the JS
        let v = (h
            .wrapping_shl(5)
            .wrapping_sub(h)
            .wrapping_add(ch as i32)) as u32;
        h = if v >= 0x8000_0000 { (v as i64 - 0x1_0000_0000) as i32 } else { v as i32 };
    }
    h
}

/// Per-session `rc::a` seed (README.md:444-448 — randomly generated base64).
fn seed_rc_a() -> String {
    use base64::Engine as _;
    use rand::Rng;
    let mut b = [0u8; 9];
    rand::thread_rng().fill(&mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Idx 4: HMAC-SHA256(siteKey) keyed by (rc::a + "6d") bytes, first 4 hex chars
/// (README.md:444-448). Sitekey-dependent by definition — the kogama-recorded head is wrong
/// for any other target, hence `computed`.
fn signal4(sitekey: &str, rc_a: &str) -> String {
    use base64::Engine as _;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(format!("{rc_a}6d").as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(sitekey.as_bytes());
    let out = mac.finalize().into_bytes();
    out.iter().map(|b| format!("{b:02x}")).collect::<String>()[..4].to_string()
}

/// The missing-signal filler of README.md:783-787: fresh random base64 + derived key + elapsed.
fn filler(elapsed: i64) -> Value {
    use base64::Engine as _;
    use rand::Rng;
    let mut b = [0u8; 11];
    rand::thread_rng().fill(&mut b);
    let key: u32 = rand::thread_rng().gen_range(0..0x7fff_ffffu32);
    json!([base64::engine::general_purpose::STANDARD.encode(b), key, elapsed])
}

/// Emit-time context (url/sitekey always present; page material only when the caller
/// scraped a DOM — else the recorded/replayed values stand, §9.2's --page-context note).
#[derive(Clone, Default)]
pub struct EmitContext {
    pub url: String,
    pub sitekey: String,
    pub head_bloom: Option<String>,
    pub page_text: Option<PageText>,
}

#[derive(Clone, Default)]
pub struct PageText {
    pub body_text: String,
    pub title: String,
    pub links: Vec<Value>,
    pub script_hosts: Vec<Value>,
    pub forms: Option<Value>,
    pub prices: Vec<Value>,
    pub prices_total: i64,
}

pub struct ProbeSurface {
    pub profile: Arc<Profile>,
    pub store: Store,
    pub clock: Arc<Clock>,
    pub ctx: EmitContext,
    rc_a: String,
    marks: Vec<(i64, i64, i64)>,
    pub replayed: usize,
    pub computed: usize,
    pub filler: usize,
}

fn count_keywords(text: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    let lower = text.to_lowercase();
    ["try again", "incorrect", "invalid", "declined"]
        .iter()
        .map(|k| lower.matches(k).count() as i64)
        .sum()
}

impl ProbeSurface {
    pub fn new(profile: Arc<Profile>, store: Store, clock: Arc<Clock>, ctx: EmitContext) -> Self {
        let marks = crate::window::clock::probe_marks(
            &clock,
            SCHEDULER.len(),
            profile.timing.startup_ms,
            profile.timing.pending_ms,
        );
        ProbeSurface {
            profile,
            store,
            clock,
            ctx,
            rc_a: seed_rc_a(),
            marks,
            replayed: 0,
            computed: 0,
            filler: 0,
        }
    }

    fn elapsed(&self, i: u32) -> i64 {
        let m = self.marks.get((i as usize) % self.marks.len().max(1));
        match m {
            Some((_, _, d)) => (*d).max(1),
            None => 1,
        }
    }

    /// The 51 Signals (+ in-array fillers) → the 79-slot wire-shaped array.
    pub fn signals_array(&mut self) -> Vec<Value> {
        let mut arr: Vec<Value> = vec![Value::Null; 79];
        for &id in SIGNAL_IDS {
            let entry = self.store.signals.get(&id.to_string()).cloned();
            let el = self.elapsed(id);
            if let Some(e) = &entry {
                if e.is_replayed() {
                    self.replayed += 1;
                    arr[id as usize] = match (&e.key, &e.elapsed) {
                        (Some(k), _) => json!([
                            e.value.clone().unwrap_or(Value::Null),
                            k,
                            e.elapsed.unwrap_or(el)
                        ]),
                        (None, _) => e.value.clone().unwrap_or(Value::Null),
                    };
                    continue;
                }
            }
            self.computed += 1;
            arr[id as usize] = self.computed_signal(id, el);
        }
        for &id in FILLER_IDS {
            if (id as usize) < arr.len() {
                self.filler += 1;
                let el = self.elapsed(id);
                arr[id as usize] = filler(el);
            }
        }
        arr
    }

    fn page(&self) -> PageText {
        self.ctx.page_text.clone().unwrap_or_default()
    }

    fn computed_signal(&self, id: u32, _el: i64) -> Value {
        let p = self.profile.clone();
        let u = &self.ctx.url;
        let now_epoch = self.clock.epoch_ms();
        let now_ms = self.clock.now();
        let page = self.page();
        match id {
            4 => json!(signal4(&self.ctx.sitekey, &self.rc_a)), // README.md:444-448
            5 => json!(11),                                     // localStorage.length*2 (seeded session)
            16 => json!(self.ctx.head_bloom.clone().unwrap_or_else(|| "yM5Us/j/fn6EDgtmPlP4Pxj605nMJN9dRYHyy5Mn".into())),
            17 => json!(2),          // hasStorageAccess — recorded default
            18 => { use base64::Engine as _; json!(base64::engine::general_purpose::STANDARD.encode(self.rc_a.as_bytes())) }
            27 => json!(serde_json::to_string(u).unwrap_or_default()), // quoted URL string (recorded shape)
            28 => json!("false"),    // parent/frameElement check
            29 => json!("\"e2a3cd70\""), // grecaptcha.execute body hash — recorded (widget never boots)
            30 => json!(0),          // recaptcha script index (api.js stripped)
            31 => json!("\"d41d8cd9\""), // document.cookie keys hash — empty-jar shape
            32 => json!(serde_json::to_string("").unwrap_or_default()), // referrer — direct entry
            33 => json!(0),          // recaptcha box element (absent pre-render)
            34 => json!("\"d754d2d3\""),
            35 => json!("\"bA==\""),
            36 => json!("h2"),
            37 => json!(now_ms.round() as i64),        // unloadEventStart — fake clock
            38 => json!(std::cmp::max(0, (now_ms / 10.0).round() as i64)), // DNS delta
            39 => json!(0),
            40 => json!(0),          // scrollY
            41 => json!("\"bA==\""),
            42 => json!("\"bXVkLTQ=\""),
            44 => json!("[\"bCBvtfE9rMP2jG1FT\",0,0,\"-1,-1\"]"),
            45 => json!(1),          // history.length
            46 => json!("0:0"),
            47 => json!(0),          // selection length
            49 => json!("h2-0"),
            50 => json!([[0, now_epoch]]), // behavior accumulator, fresh timestamps
            51 => json!(count_keywords(&page.body_text)),
            52 => json!(0),          // userActivation
            53 => json!(u.chars().take(100).count() as i64), // locationLengthParity
            54 => json!(false),      // document.hidden
            55 => json!("[]"),
            56 => json!("-1,-1"),
            57 => json!(page.script_hosts),
            58 => json!(""),
            59 => json!(""),
            60 => json!([]),
            61 => json!([]),
            62 => json!(page.title),
            63 => json!([]),         // cookie timestamps
            64 => json!(now_ms.round() as i64),
            65 => json!(""),
            67 => json!([p.browser.screen.width, p.browser.screen.height, p.browser.inner_width, p.browser.outer_height]),
            68 => json!([tz_offset_minutes_west(), Value::Null, now_epoch]),
            69 => Value::Null,       // session token — never shipped (rule 2)
            70 => json!([]),         // monetary amounts
            71 => json!([(4_300_000.0 + self.clock.raw_ms() * 1000.0).round() as i64, 1_200_000_000i64, 380_000_000i64]),
            72 => json!([[["Not_A Brand", "8"], ["Chromium", "120"], ["Google Chrome", "120"]], 0, if p.navigator.platform == "Win32" { "Windows" } else { "macOS" }]),
            73 => json!([[Value::Null, 3, 0, p.transport.user_agent], Value::Null, Value::Null]),
            77 => json!(now_epoch),
            78 => json!(serde_json::to_string("").unwrap_or_default()),
            _ => Value::Null,
        }
    }

    /// The 23 VM keys — [null, collectorElapsed, encryptElapsed, value] (README.md:793-807).
    pub fn vm_signals(&mut self) -> Vec<Value> {
        let mut out = Vec::with_capacity(VM_KEYS.len());
        for &k in VM_KEYS {
            let entry = self.store.vm_keys.get(&k.to_string()).cloned();
            let ce = self.elapsed(k);
            let ee = std::cmp::max(1, ce / 10);
            let value = match &entry {
                Some(e) if e.is_replayed() => {
                    self.replayed += 1;
                    e.value.clone().unwrap_or(Value::Null)
                }
                _ => {
                    self.computed += 1;
                    self.computed_vm_key(k)
                }
            };
            out.push(json!([Value::Null, ce, ee, value]));
        }
        out
    }

    fn computed_vm_key(&self, k: u32) -> Value {
        let p = self.profile.clone();
        let page = self.page();
        match k {
            417 => json!(p.transport.user_agent),
            545 => json!(false),
            370 => json!(p.navigator.max_touch_points),
            1278 => json!((self.clock.now() as i64) / 10), // README.md:1173 trunc(performance.now())/10
            1092 => json!([
                self.clock.now().round() as i64,
                (self.clock.now() + 1.2).round() as i64,
                (self.clock.now() + 40.0).round() as i64,
                (self.clock.now() + 90.0).round() as i64,
                0
            ]),
            659 => json!([[], [], 0, 0]),          // pressed elements — minimal shape
            959 => json!([]),                      // scroll movements — minimal shape
            352 => json!([]),                      // behavior array — minimal shape
            779 => page.forms.unwrap_or_else(|| json!([Value::Null, Value::Null, Value::Null, Value::Null, "false"])),
            727 => json!(page.prices),             // live page (volatile)
            150 => json!(page.links),              // live page (volatile)
            360 => json!(page.prices_total),       // live page (volatile)
            41 => json!(0),                        // clearTimeout counts (VM runtime)
            43 => json!(0),
            549 => json!([]),                      // keyboard events — none in a headless emit
            895 => json!([[[true, self.clock.epoch_ms()]]]), // VisibilityStateEntry
            1422 => json!([]),                     // OTP fields — none
            614 => json!([0.87, true, 0, 0]),      // battery — synthesized
            1313 => json!(["undefined", 0]),       // window.android / chrome absent in the realm
            1994 => json!([p.navigator.hardware_concurrency, p.navigator.device_memory, 0]),
            1310 => json!([p.webgl.renderer, p.webgl.vendor, 0]),
            291 => json!({}),                      // proto hashes — computed over the realm at boot
            2033 => json!(["0", -1, -1, 999]),     // VM constants + runtime timing
            _ => Value::Null,
        }
    }

    /// The reload-idx-16 plaintext — JSON.stringify of the 79-slot array.
    pub fn fingerprint_serialization(&mut self) -> String {
        serde_json::to_string(&self.signals_array()).expect("array serialization cannot fail")
    }

    /// The userverify `oc` plaintext — the hashOC.js [[[...]]] shape over 23 VM entries.
    pub fn oc_serialization(&mut self) -> String {
        let vm = self.vm_signals();
        serde_json::to_string(&json!([[vm]])).expect("array serialization cannot fail")
    }

    /// The emit-time consistency gate (§11.3 end — rule 7 discipline): contradictions are
    /// NAMED, never silently shipped.
    pub fn consistency_check(&self, profile_ua_answer: &str, screen_answer: (u32, u32), dpr_answer: f64, clock_answer: f64) -> Vec<String> {
        let p = &self.profile;
        let mut errs = Vec::new();
        if profile_ua_answer != p.transport.user_agent {
            errs.push("Idx-417 UA answer != profile transport.user_agent".into());
        }
        if screen_answer.0 != p.browser.screen.width || screen_answer.1 != p.browser.screen.height {
            errs.push("Idx-67 screen answer != profile browser.screen".into());
        }
        if (dpr_answer - p.browser.device_pixel_ratio).abs() > f64::EPSILON {
            errs.push("device_pixel_ratio answer != profile".into());
        }
        if !clock_answer.is_finite() || clock_answer < 0.0 {
            errs.push("Idx-1278 clock answer is not a non-negative number".into());
        }
        errs
    }
}
