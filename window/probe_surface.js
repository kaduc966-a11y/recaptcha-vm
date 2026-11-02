'use strict';
/**
 * probe_surface.js — the 51-Signal + 23-VM-key registry + the 4 undocumented scheduler
 * filler slots (DESIGN.md §11.3), plus the fingerprint/oc serialization and the emit-time
 * consistency gate. The cfsolve registry.rs treatment split (replayed vs computed), with
 * per-entry provenance from the answers store (§11.2).
 *
 * Treatments:
 *   replayed — byte-faithful recorded device facts from the store (never re-derived);
 *   computed — sitekey/session/page-derived, answered at emit time;
 *   unobserved-filler — the scheduler slots 43/48/66/79 with no catalog entry, serialized
 *     as the README's own missing-signal filler (README.md:783-787): a fresh random
 *     base64 value with its own derived key + elapsed.
 *
 * HONEST LIMITS (§13.1 caveat / §18.3): the per-value encryption pipeline and the
 * whole-payload reload-f16 encryption have NO implementation in this workspace, so the
 * emit carries the serialized PLAINTEXT signal array (exactly the §13.1 contract's
 * "serialized plaintext signal array — the reload-idx-16 plaintext") and
 * fingerprint_encrypted/oc_encrypted stay null with encrypted:false. fingerprint_hash /
 * ch are real hashString results over the real serializations (the cross-validated
 * hashFingerprint.js:8-19 / hashOC.js:8-14 algorithm).
 */

const crypto = require('crypto');
const { probeMarks } = require('./timing.js');

// ── the catalog (recaptcha-main/README.md:444-779 counted 51; :872-1230 counted 23) ────
const SIGNAL_IDS = [4, 5, 16, 17, 18, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 44, 45, 46, 47, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
  65, 67, 68, 69, 70, 71, 72, 73, 77, 78];
const FILLER_IDS = [43, 48, 66, 79];   // scheduler-only slots, README.md:783-787 filler shape
const VM_KEYS = [417, 727, 150, 545, 370, 779, 659, 959, 895, 1092, 41, 43, 549, 352, 360,
  1278, 1422, 614, 2033, 1313, 1994, 1310, 291];
// the 35-entry scheduler of README.md:309 (covers all 35 serialization positions)
const SCHEDULER = [42, 45, 53, 30, 28, 54, 29, 31, 32, 33, 34, 35, 37, 36, 38, 39, 43, 40, 41,
  46, 48, 57, 58, 60, 61, 62, 63, 64, 66, 68, 69, 71, 72, 79, 55];

// ── hashFingerprint.js:8-19 / hashOC.js:8-14 — the cross-validated hashString port ─────
function toSigned32(n) {
  n = n >>> 0;
  if (n >= 0x80000000) n -= 0x100000000;
  return n;
}
function hashString(data, numAt = 0) {
  for (let i = 0; i < data.length; i++) {
    numAt = toSigned32((((numAt << 5) - numAt) + data.charCodeAt(i)) >>> 0);
  }
  return numAt;
}

// per-session rc::a seed (README.md:444-448 — "randomly generated base64"); the real value
// is set by api.js in a real browser; the window seeds its own per emit session.
function seedRcA() {
  return crypto.randomBytes(9).toString('base64');
}

// Idx 4: HMAC-SHA256(siteKey) keyed by (rc::a + "6d") bytes, first 4 hex chars.
function signal4(sitekey, rcA) {
  const key = Buffer.from(String(rcA) + '6d', 'utf8');
  return crypto.createHmac('sha256', key).update(String(sitekey), 'utf8').digest('hex').slice(0, 4);
}

// the missing-signal filler of README.md:783-787: fresh random base64 + derived key + elapsed.
function filler(clock, marks) {
  const value = crypto.randomBytes(11).toString('base64');
  const m = marks.length ? marks[Math.floor(Math.random() * marks.length)] : { duration: 1 };
  return [value, (Math.floor(Math.random() * 0x7fffffff) >>> 0), m.duration + 1];
}

class ProbeSurface {
  /**
   * @param profile   validated profile object (§11.1)
   * @param store     the answers store (§11.2, window/answers/fingerprint.json)
   * @param clock     the timing.Clock
   * @param ctx  { url, sitekey, pageText?: {bodyText?:string, links?:string[], forms?:array},
   *               headBloom?:string } — emit-time context (url/sitekey always present;
   *               page material only when the caller scraped a DOM — else recorded/replayed)
   */
  constructor(profile, store, clock, ctx) {
    this.profile = profile;
    this.store = store || { signals: {}, vm_keys: {} };
    this.clock = clock;
    this.ctx = ctx || {};
    this.rcA = seedRcA();
    this.marks = probeMarks(clock, SCHEDULER.length, profile.timing || {});
    this.computedCount = 0;
    this.replayedCount = 0;
    this.fillerCount = 0;
  }

  _elapsed(i) {
    const m = this.marks[i % this.marks.length] || { duration: 1 };
    return Math.max(1, Math.round(m.duration));
  }

  // ── the 51 Signals (+ fillers) — returns the 79-slot wire-shaped array ───────────────
  signalsArray() {
    const arr = new Array(79).fill(null);
    const store = this.store.signals || {};
    for (const id of SIGNAL_IDS) {
      const e = store[String(id)];
      const el = this._elapsed(id);
      if (e && e.treatment === 'replayed' && e.value !== null && e.value !== undefined) {
        this.replayedCount++;
        // recorded device fact — byte-faithful triple [value, key, elapsed]
        arr[id] = (e.key !== undefined)
          ? [e.value, e.key, e.elapsed != null ? e.elapsed : el]
          : e.value;
        continue;
      }
      // computed (or replay-requested but volatile/absent) — live per §11.3
      this.computedCount++;
      arr[id] = this._computedSignal(id, el);
    }
    for (const id of FILLER_IDS) {
      // the captured wire layout (decrypted_values.json AND the hashFingerprint.js sample)
      // is exactly 79 slots (indices 0-78) — the scheduler's collector 79 has no slot in
      // the captured serialization, so only in-array fillers are emitted (43/48/66);
      // collector 79 is documented as out-of-capture-layout in the store + README
      if (id < arr.length) {
        this.fillerCount++;
        arr[id] = filler(this.clock, this.marks);   // README.md:783-787 missing-signal filler
      }
    }
    return arr;
  }

  _computedSignal(id, el) {
    const p = this.profile;
    const u = this.ctx.url || '';
    const nowEpoch = Math.round(this.clock.epochMs());
    switch (id) {
      case 4: return signal4(this.ctx.sitekey || '', this.rcA);            // README.md:444-448
      case 5: return 11;                                                   // localStorage.length*2 (seeded session)
      case 16: return this.ctx.headBloom || 'yM5Us/j/fn6EDgtmPlP4Pxj605nMJN9dRYHyy5Mn'; // recorded unless the caller scraped a head
      case 17: return 2;                                                   // hasStorageAccess — recorded default
      case 18: return Buffer.from(this.rcA).toString('base64');            // random base64 (README.md:459)
      case 27: return JSON.stringify(u);                                   // Website URL (recorded shape is a quoted string)
      case 28: return 'false';                                             // parent/frameElement check
      case 29: return '"e2a3cd70"';                                        // grecaptcha.execute body hash — recorded (widget never boots)
      case 30: return 0;                                                   // recaptcha script index (api.js stripped, §5.3)
      case 31: return '"d41d8cd9"';                                        // document.cookie keys hash — empty jar shape
      case 32: return JSON.stringify('');                                  // referrer — direct entry, no referrer chain
      case 33: return 0;                                                   // recaptcha box element (absent pre-render)
      case 34: return '"d754d2d3"';                                        // input attribute-name hash — recorded shape
      case 35: return '"bA=="';                                            // activeElement purchase-parse — recorded shape
      case 36: return 'h2';                                                // nextHopProtocol (timing.js resource entry)
      case 37: return Math.round(this.clock.now());                        // unloadEventStart — fake clock
      case 38: return Math.max(0, Math.round(this.clock.now() / 10));      // DNS delta — fake clock
      case 39: return 0;                                                   // navigation.type (direct navigation)
      case 40: return 0;                                                   // scrollY
      case 41: return '"bA=="';                                            // hovered element hash — recorded shape
      case 42: return '"bXVkLTQ="';                                        // random script hash+index — recorded shape
      case 44: return '["bCBvtfE9rMP2jG1FT",0,0,"-1,-1"]';                 // composite hover/input/url/scroll — recorded shape
      case 45: return 1;                                                   // history.length
      case 46: return '0:0';                                               // script error line:column (none observed)
      case 47: return 0;                                                   // selection length
      case 49: return 'h2-0';                                              // protocol-isZero for the recaptcha resource entry
      case 50: return [[0, Math.round(this.clock.epochMs())]];             // behavior/hover accumulator, fresh timestamps
      case 51: return this.ctx.pageText ? countKeywords(this.ctx.pageText.bodyText || '') : 0;
      case 52: return 10 * 0 + 0;                                          // userActivation.isActive/hasBeenActive
      case 53: return u.slice(0, 100).length;                              // locationLengthParity
      case 54: return false;                                               // document.hidden
      case 55: return '[]';                                                // signal-code ordering (empty at this stage)
      case 56: return '-1,-1';                                             // window.opener check
      case 57: return this.ctx.pageText ? (this.ctx.pageText.scriptHosts || []) : [];
      case 58: return '';                                                  // sampled localStorage key (session)
      case 59: return '';                                                  // window.name
      case 60: return [];                                                  // message-event URLs
      case 61: return [];                                                  // MutationObserver records
      case 62: return this.ctx.pageText ? (this.ctx.pageText.title || '') : '';
      case 63: return [];                                                  // cookie timestamps
      case 64: return Math.round(this.clock.now());                        // anchor→reload execution time
      case 65: return '';                                                  // api.js integrity (stripped, §5.3)
      case 67: return [p.browser.screen.width, p.browser.screen.height, p.browser.inner_width, p.browser.outer_height];
      case 68: return [new Date().getTimezoneOffset(), null, nowEpoch];
      case 69: return null;                                                // session token — never shipped (rule 2)
      case 70: return [];                                                  // monetary amounts
      case 71: return [Math.round(4.3e6 + this.clock.rawMs() * 1000), 1.2e9, 3.8e8]; // JS heap — synthesized from the clock
      case 72: {                                                           // userAgentData array + mobile + platform
        const brands = [['Not_A Brand', '8'], ['Chromium', '120'], ['Google Chrome', '120']];
        return [brands, 0, p.navigator.platform === 'Win32' ? 'Windows' : 'macOS'];
      }
      case 73: return [[null, 3, 0, p.transport.user_agent], null, null];  // VM-encrypted UA wrapper — recorded shape
      case 77: return nowEpoch;                                            // unix timestamp
      case 78: return JSON.stringify('');                                  // GA cookie — absent
      default: return null;
    }
  }

  // ── the 23 VM keys — [null, collectorElapsed, encryptElapsed, value] (README.md:793-807) ──
  vmSignals() {
    const store = this.store.vm_keys || {};
    const out = [];
    for (const k of VM_KEYS) {
      const e = store[String(k)] || {};
      const ce = this._elapsed(k);
      const ee = Math.max(1, Math.round(ce / 10));
      let value = null;
      if (e.treatment === 'replayed' && e.value !== null && e.value !== undefined) {
        this.replayedCount++;
        value = e.value;
      } else {
        this.computedCount++;
        value = this._computedVmKey(k);
      }
      out.push([null, ce, ee, value]);   // the VM-signal base format
    }
    return out;
  }

  _computedVmKey(k) {
    const p = this.profile;
    const page = this.ctx.pageText || {};
    switch (k) {
      case 417: return p.transport.user_agent;
      case 545: return false;
      case 370: return p.navigator.max_touch_points;
      case 1278: return Math.trunc(this.clock.now()) / 10;                 // README.md:1173
      case 1092: return [Math.round(this.clock.now()), Math.round(this.clock.now() + 1.2),
        Math.round(this.clock.now() + 40), Math.round(this.clock.now() + 90), 0];
      case 659: return [[], [], 0, 0];                                     // pressed elements — minimal shape
      case 959: return [];                                                 // scroll movements — minimal shape
      case 352: return [];                                                 // behavior array — minimal shape
      case 779: return page.forms || [null, null, null, null, 'false'];    // form scrape — recorded null shape
      case 727: return page.prices || [];                                  // live page (volatile)
      case 150: return page.links || [];                                   // live page (volatile)
      case 360: return page.pricesTotal || 0;                              // live page (volatile)
      case 41: return 0;                                                   // clearTimeout counts (VM runtime)
      case 43: return 0;                                                   // clearTimeout counts (VM runtime)
      case 549: return [];                                                 // keyboard events — none in headless emit
      case 895: return [[[true, Math.round(this.clock.epochMs())]]];       // VisibilityStateEntry
      case 1422: return [];                                                // OTP fields — none
      case 614: return [0.87, true, 0, 0];                                 // battery — synthesized
      case 1313: return ['undefined', 0];                                  // window.android absent, chrome absent in jsdom
      case 1994: return [p.navigator.hardware_concurrency, p.navigator.device_memory, 0];
      case 1310: return [p.webgl.renderer, p.webgl.vendor, 0];
      case 291: return {};                                                 // proto hashes — computed over the realm at boot
      case 2033: return ['0', -1, -1, 999];                                // VM constants + runtime timing
      default: return null;
    }
  }

  // ── serialization ─────────────────────────────────────────────────────────────────────
  fingerprintSerialization() {
    return JSON.stringify(this.signalsArray());
  }

  /** oc plaintext — the hashOC.js shape: [[[27 VM-signal entries]]]. */
  ocSerialization() {
    const vm = this.vmSignals();
    return JSON.stringify([[vm]]);
  }

  // ── the emit-time consistency gate (§11.3 end — rule 7 discipline) ───────────────────
  consistencyCheck(built) {
    const p = this.profile;
    const errs = [];
    if (built.profileUaAnswer !== undefined && built.profileUaAnswer !== p.transport.user_agent) {
      errs.push('Idx-417 UA answer != profile transport.user_agent');
    }
    if (built.screenAnswer && (built.screenAnswer[0] !== p.browser.screen.width ||
        built.screenAnswer[1] !== p.browser.screen.height)) {
      errs.push('Idx-67 screen answer != profile browser.screen');
    }
    if (built.dprAnswer !== undefined && built.dprAnswer !== p.browser.device_pixel_ratio) {
      errs.push('device_pixel_ratio answer != profile');
    }
    const t = p.timing || {};
    if ((t.startup_ms != null && t.startup_ms < 0) || (t.pending_ms != null && t.pending_ms < 0)) {
      errs.push('profile timing.* must be non-negative');
    }
    // timing answers must lie within the fake clock's resolution (100 µs clamp ⇒ ms-level)
    if (built.clockAnswer != null && (!Number.isFinite(built.clockAnswer) || built.clockAnswer < 0)) {
      errs.push('Idx-1278 clock answer is not a non-negative number');
    }
    return errs;
  }
}

function countKeywords(text) {
  if (!text) return 0;
  const m = text.match(/try again|incorrect|invalid|declined/gi);
  return m ? m.length : 0;
}

module.exports = {
  ProbeSurface, SIGNAL_IDS, FILLER_IDS, VM_KEYS, SCHEDULER,
  hashString, toSigned32, signal4, seedRcA, countKeywords,
};
