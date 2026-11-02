'use strict';
/**
 * vm_runner.js — the node:vm runner for the captured BotGuard VM (DESIGN.md §12) and the
 * emit assembler for the §13.1 JSON contract.
 *
 * Sandbox surface (§12.2 — every item verified against the captures):
 *   - window self-reference (sandbox.window = sandbox; sandbox.self = sandbox) — the IIFE is
 *     .call(window) (script_7/vm.js:774) and every later global read goes through B/M = this||self.
 *   - document = { hidden:false, readyState:'complete', addEventListener(){}, removeEventListener(){} }
 *     (hidden gate script_7/vm.js:164-168; readyState :255 / script_1's rz branch).
 *   - performance = { timeOrigin, timing:{navigationStart}, now: clampedClock } (script_7 :443-449,
 *     script_1's Z.i / Ya origin read — real clock, §11.4 resolution).
 *   - host setTimeout/setImmediate/clearTimeout ON THE CONTEXT (the scheduler tP/Wg reads
 *     B.requestIdleCallback ? ... : B.setImmediate ? ... : setTimeout(D,0) — script_7 :593-604;
 *     script_1's Wg; requestIdleCallback deliberately ABSENT so setImmediate is chosen, as in
 *     any non-browser host; bare identifiers resolve on the context global).
 *   - lenient atob backed by Buffer.from(s,'base64') — strict atob rejects BOTH captured bc.txt
 *     files for two different reasons (script_1 len 9235 mod 4 = 3 with a trailing '=';
 *     script_7 len 9099 with a '==' tail → mod 4 = 1); the string stays byte-exact (latin-1),
 *     any trim/pad shift desynchronizes the ARX keystream (script_7/vm.js:322-330).
 *   - btoa present (absent btoa silently degrades the token to hex, script_7 :701-704 /
 *     script_1's Z.UJ else-branch).
 *   - trustedTypes left undefined (benign: script_7 :148-158 returns null; script_1's cg()).
 *   - Node intrinsics (Math, JSON, Date, Promise, Symbol, Object, eval) come with the context
 *     realm and are NEVER wrapped or proxied.
 *
 * Integrity traps (§12.6) — satisfied by construction: the captured vm.js runs UNMODIFIED in
 * a single realm (Symbol(jas) tags survive); no cloning of VM objects across realms; no JSON
 * serialization of VM state mid-run; no monkey-patching of intrinsics; only missing globals
 * are shimmed (document/performance/timers/atob/btoa).
 *
 * Program interface (read from the captures, §12.4-5): each bc.txt's first 3 chars name the
 * program entry ("wJo" → botguard.wJo_, "IJO" → botguard.IJO_); botguard.bg routes through it
 * (XQ/wz: `L[D.substring(0,3)+"_"]`). bg returns {invoke, pe}; the VM calls the arg-1 env
 * function with 4 callbacks during its run (script_7 :243-251, script_1's JG branch); the
 * token is the RETURN of invoke's sync path (script_7's k==d branch builds "!" + base64url;
 * script_1's GG branch: r = "!" + this.UJ(Q)) or arrives through the env callbacks
 * asynchronously. The runner drives the sync path first, then the async path with event-loop
 * drains, then the full-surface `a` entry (§12.4's traced arg positions) — and reports
 * honestly which produced what. "A token came out" proves nothing (§12.6): the runner
 * asserts the '!' marker and counts host-observed errors instead.
 *
 * The buffer-304/180 error counters are VM-INTERNAL state (reachable only through the VM's
 * own dispatcher messages) — the emit's `errors` counts HOST-observed anomalies (throws,
 * missing markers), which is the honest observable. Stated in the README.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { Clock } = require('./timing.js');
const { ProbeSurface, hashString } = require('./probe_surface.js');

// the one wire UA (rule 7) — the profile UA must equal it (§11.1 cross-check)
const CHAIN_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const diag = (...a) => console.error('[vm_runner]', ...a);

// ── profile load + validate-before-anything (§11.1, browser.rs:300-404 discipline) ─────
function loadProfile(profileId, folder) {
  const p = path.join(folder, 'profiles', `${profileId}.json`);
  let prof;
  try {
    prof = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    throw Object.assign(new Error(`profile ${profileId}: unreadable (${e.message})`), { field: 'file' });
  }
  const need = (cond, field, detail) => {
    if (!cond) throw Object.assign(new Error(`profile ${profileId}: invalid field ${field} — ${detail || 'missing/invalid'}`), { field });
  };
  need(typeof prof.id === 'string' && prof.id, 'id');
  need(prof.engine === 'chromium' || prof.engine === 'webkit', 'engine');
  need(prof.transport && typeof prof.transport.user_agent === 'string', 'transport.user_agent');
  need(typeof prof.transport.impersonate === 'string', 'transport.impersonate');
  need(prof.browser && typeof prof.browser.screen === 'object', 'browser.screen');
  need(prof.navigator && typeof prof.navigator.hardware_concurrency === 'number', 'navigator.hardware_concurrency');
  need(prof.timing && prof.timing.startup_ms >= 0 && prof.timing.pending_ms >= 0, 'timing.*');
  need(prof.transport.user_agent === CHAIN_UA, 'transport.user_agent',
    'must equal the chain UA (rule 7) — a profile whose UA the chain never sends fails validation and the runner falls back to chrome-win (§11.1)');
  return prof;
}

// ── the lenient base64 pair (§12.2) ────────────────────────────────────────────────────
function lenientAtob(s) {
  return Buffer.from(String(s), 'base64').toString('binary');   // byte-exact latin-1 string
}
function btoaBin(s) {
  return Buffer.from(String(s), 'binary').toString('base64');
}

// ── the §12.2 sandbox ──────────────────────────────────────────────────────────────────
function buildSandbox(clock) {
  const t0 = clock.originMs;
  const sandbox = {};
  sandbox.window = sandbox;          // self-reference (§12.2 item 1)
  sandbox.self = sandbox;
  sandbox.document = {
    hidden: false,                   // the hidden gate MUST see 0 (script_7 :164-168)
    readyState: 'complete',
    addEventListener() {},
    removeEventListener() {},
  };
  sandbox.performance = {
    timeOrigin: t0,
    timing: { navigationStart: t0 },
    now: () => clock.now(),
  };
  sandbox.setTimeout = setTimeout;   // host timers on the context (§12.2)
  sandbox.clearTimeout = clearTimeout;
  sandbox.setImmediate = setImmediate;
  sandbox.clearImmediate = clearImmediate;
  // requestIdleCallback deliberately ABSENT → the scheduler picks setImmediate
  sandbox.atob = lenientAtob;        // lenient atob — strict atob rejects both captures
  sandbox.btoa = btoaBin;            // btoa present — else the token degrades to hex
  // trustedTypes left undefined (§12.2); console omitted (optional).
  // Math/JSON/Date/Promise/Symbol/Object/eval come with the context realm untouched.
  return sandbox;
}

// ── VM boot + feed + drive (§12.3-6) ───────────────────────────────────────────────────
async function runVm(folder, vmName, clock) {
  const vmDir = path.join(folder, 'assets', 'vm', vmName);
  const vmJs = fs.readFileSync(path.join(vmDir, 'vm.js'), 'utf8');     // UNMODIFIED source
  const bc = fs.readFileSync(path.join(vmDir, 'bc.txt'), 'utf8').trim(); // §12.4: utf8, trim only
  const prefix = bc.slice(0, 3) + '_';

  const sandbox = buildSandbox(clock);
  const ctx = vm.createContext(sandbox);

  const errors = [];
  let botguard = null;
  // §12.3 boot — assert the registration markers
  vm.runInContext(vmJs, ctx, { filename: `${vmName}/vm.js` });
  botguard = sandbox.botguard;
  if (!botguard || botguard.m !== 41) {
    throw Object.assign(new Error(`boot: botguard.m !== 41 (${botguard && botguard.m})`), { tag: 'vm_boot_failed' });
  }
  if (typeof botguard[prefix] !== 'function') {
    throw Object.assign(new Error(`boot: botguard.${prefix} is not a function (have: ${Object.keys(botguard).join(',')})`),
      { tag: 'vm_handler_arity' });
  }

  // the env function (§12.4 arg1): through bg it is only SCHEDULED (tP(P)) and through the
  // `a` entry it is the boot-error callback — the VM may also call it with callbacks. It is
  // an observe-only recorder: no VM intrinsic or VM function is patched (§12.6).
  const env = { callbacks: [], called: 0 };
  const envFn = function () {
    env.called++;
    for (let i = 0; i < arguments.length; i++) {
      if (typeof arguments[i] === 'function') env.callbacks.push(arguments[i]);
    }
  };

  const timingCb = function () {};                     // §12.4 arg4 (qC carrier) — observer no-op
  const twoElem = [function () {}, function () {}];    // §12.4 arg5
  const cfgJson = JSON.stringify({ t: 30000 });        // §12.4 arg6 ({"t": timeoutMs})

  const drain = () => new Promise((r) => setImmediate(r));
  let bgdata = null;
  const notes = [];
  let delivered = null;
  const collector = (w) => { if (typeof w === 'string' && w[0] === '!') delivered = w; };

  // entry 1 — botguard.bg (the registered program face; script_1's L1 / script_7's $p)
  try {
    const prog = botguard.bg(bc, envFn, undefined, undefined, timingCb, twoElem, cfgJson, undefined);
    if (prog && typeof prog.invoke === 'function') {
      // sync path (script_1's L1: if(!B) return B=X(z); script_7's k==d return builds "!" + …)
      let tok = null;
      try { tok = prog.invoke(null, undefined, ''); } catch (e) { errors.push(`invoke-sync: ${e && e.message}`); }
      if (typeof tok === 'string' && tok[0] === '!') bgdata = tok;
      else if (typeof tok === 'string' && tok.startsWith('E:')) {
        // the VM's own error path (VR builds "E:"+message+":"+stack) — "a token came out"
        // proves nothing; this is an observed VM-internal error, not a success (§12.6)
        errors.push(`vm-internal: ${tok.slice(0, 120)}`);
        notes.push(`sync invoke returned the VM error string (${tok.slice(0, 60)})`);
      } else if (tok != null) {
        notes.push(`sync invoke returned ${typeof tok} (${String(tok).slice(0, 24)})`);
      }
      // async path (script_1's f(): F(function(w){Wg(function(){S(w)})}, z) — the token is
      // delivered to the FIRST argument's callback) with event-loop drains, because the VM
      // scheduler runs its steps via setImmediate
      if (!bgdata) {
        try { prog.invoke(collector, true, ''); } catch (e) { errors.push(`invoke-async: ${e && e.message}`); }
        for (let i = 0; i < 50 && !bgdata; i++) {
          await drain();
          if (delivered) bgdata = delivered;
        }
      }
      if (!bgdata) notes.push('bg entry: no "!" token after sync + async with drained waits');
    } else {
      notes.push('bg entry returned no invoke() function');
      errors.push('vm_handler_arity: bg returned no invoke()');
    }
  } catch (e) {
    errors.push(`bg entry: ${e && e.message}`);
  }

  // entry 2 — the full-surface `a` entry (XQ/wz with §12.4's traced arg positions)
  if (!bgdata) {
    delivered = null;
    try {
      const inst = botguard.a(bc, envFn, undefined, undefined, timingCb, twoElem, cfgJson, undefined);
      const invokeFn = Array.isArray(inst) ? inst[0] : (inst && inst.invoke);
      if (typeof invokeFn === 'function') {
        let tok = null;
        try { tok = invokeFn(collector); } catch (e) { errors.push(`a-invoke: ${e && e.message}`); }
        if (typeof tok === 'string' && tok[0] === '!') bgdata = tok;
        for (let i = 0; i < 50 && !bgdata; i++) {
          await drain();
          if (delivered) bgdata = delivered;
        }
        if (!bgdata) notes.push('a entry: no "!" token after sync + drained waits');
      } else {
        notes.push('a entry returned no invocable function');
        errors.push('vm_handler_arity: a entry returned no invoke');
      }
    } catch (e) {
      errors.push(`a entry: ${e && e.message}`);
    }
  }

  return { bgdata, errors, notes, prefix, booted: true };
}

// ── the emit assembler (§13.1) ─────────────────────────────────────────────────────────
async function emit(opts = {}) {
  const t0 = Date.now();
  const folder = __dirname;
  let profileId = opts.profile || 'chrome-win';
  const vmName = opts.vm || 'script_1';
  const out = {
    ok: false, runner: 'node-vm', profile: profileId, engine: null, vm: vmName,
    url: opts.url || '', sitekey: opts.sitekey || '',
    fingerprint: null, fingerprint_hash: null, fingerprint_encrypted: null,
    oc: null, oc_encrypted: null, ch: null, bgdata: null,
    encrypted: false, head_hash: 'recorded', errors: 0, elapsed_ms: 0,
  };
  const fail = (tag, msg) => {
    out.error = tag;
    out.detail = String(msg || tag).slice(0, 300);
    out.elapsed_ms = Date.now() - t0;
    diag(`emit failed: ${tag} — ${out.detail}`);
    return out;
  };

  let profile;
  try {
    profile = loadProfile(profileId, folder);
  } catch (e) {
    if (profileId !== 'chrome-win' && e.field === 'transport.user_agent') {
      // §11.1: the runner falls back to chrome-win if the selected profile fails validation
      diag(`profile ${profileId} failed validation (${e.message}) — falling back to chrome-win`);
      out.fallback_from = profileId;
      profileId = 'chrome-win';
      out.profile = profileId;
      try { profile = loadProfile(profileId, folder); } catch (e2) { return fail('profile_invalid', e2.message); }
    } else {
      return fail('profile_invalid', e.message);
    }
  }
  out.engine = profile.engine;

  let store;
  try {
    store = JSON.parse(fs.readFileSync(path.join(folder, profile.answers || 'answers/fingerprint.json'), 'utf8'));
  } catch (e) {
    return fail('answers_missing', `answers store unreadable: ${e.message}`);
  }

  const clock = new Clock();
  let surface, fingerprintSer, ocSer;
  try {
    surface = new ProbeSurface(profile, store, clock, {
      url: opts.url, sitekey: opts.sitekey,
      headBloom: opts.headBloom || null,
      pageText: opts.pageText || null,
    });
    out.head_hash = opts.headBloom ? 'computed' : 'recorded';
    fingerprintSer = surface.fingerprintSerialization();
    ocSer = surface.ocSerialization();
  } catch (e) {
    return fail('consistency_failed', `probe assembly: ${e.message}`);
  }

  const built = {
    profileUaAnswer: profile.transport.user_agent,
    screenAnswer: [profile.browser.screen.width, profile.browser.screen.height],
    dprAnswer: profile.browser.device_pixel_ratio,
    clockAnswer: Math.trunc(clock.now()) / 10,
  };
  const gateErrs = surface.consistencyCheck(built);
  if (gateErrs.length) return fail('consistency_failed', gateErrs.join('; '));

  // the VM run — a failure here degrades bgdata only; the window material above is real
  let vmRes = { bgdata: null, errors: [], notes: [], booted: false, prefix: null };
  try {
    vmRes = await runVm(folder, vmName, clock);
  } catch (e) {
    return fail(e.tag || 'vm_boot_failed', e.message);
  }

  out.ok = true;
  out.fingerprint = fingerprintSer;
  out.fingerprint_hash = hashString(fingerprintSer);
  out.fingerprint_encrypted = null;   // §13.1 caveat: the reload-f16 encryptor has no implementation
  out.oc = ocSer;
  out.oc_encrypted = null;            // same caveat — an unencrypted plaintext oc has no wire slot
  out.ch = hashString(ocSer);
  out.bgdata = vmRes.bgdata || null;
  out.errors = vmRes.errors.length;
  out.vm_detail = { prefix: vmRes.prefix, booted: vmRes.booted, notes: vmRes.notes, host_errors: vmRes.errors };
  out.elapsed_ms = Date.now() - t0;
  diag(`emit ok profile=${profileId} engine=${profile.engine} vm=${vmName} (prefix ${vmRes.prefix}) ` +
       `bgdata=${vmRes.bgdata ? 'yes(len=' + vmRes.bgdata.length + ')' : 'null'} errors=${out.errors} ` +
       `fp_hash=${out.fingerprint_hash} ch=${out.ch} in ${out.elapsed_ms}ms`);
  return out;
}

module.exports = { emit, loadProfile, buildSandbox, runVm, lenientAtob, btoaBin, CHAIN_UA };
