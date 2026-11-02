'use strict';
/**
 * timing.js — the timing fakes (DESIGN.md §11.4), ported from cfsolve's performance_clock.rs /
 * resource_timing.rs / session/timing.rs (external checkout, per §1's provenance note).
 *
 *  1. Blink 100 µs clamp for performance.now() (performance_clock.rs:113-153): readings are
 *     quantized to 100 µs (INTERVAL_US=100) boundaries — round DOWN until a per-boundary
 *     pseudorandom threshold (murmur3-fmix64 of boundary ^ process secret, top-53-bit
 *     fraction), then round UP. The origin is clamped the same way (:69-78). The secret is
 *     drawn once per emit process from OS entropy (crypto.randomBytes). This reproduces
 *     Chrome's float precision loss from absolute monotonic microseconds. The clock stays
 *     REAL (never frozen — the VM's Xn histogram and checksum depend on real deltas,
 *     script_7/vm.js:550/:694); only the resolution is faked.
 *  2. Resource-timing entries (resource_timing.rs:48-70): when only a total duration is
 *     known — phase fractions from the profile's resource_timing section; transferSize =
 *     encodedBodySize + 300 (ASSUMED_HEADER_BYTES); nextHopProtocol always "h2";
 *     cross-origin rows without Timing-Allow-Origin are restricted (requestStart 0,
 *     sizes 0, responseEnd = end).
 *  3. Reverse-scheduled probe marks (session/timing.rs:86-108 pattern): each probe's
 *     start/end marks placed startup_ms after window boot, duration+1 ms apart, ending
 *     pending_ms before the emit send time.
 *  4. Date.now()/performance.timeOrigin: real epoch, origin-anchored (the VM reads
 *     timeOrigin || timing.navigationStart, script_7/vm.js:443-449).
 */

const crypto = require('crypto');

const INTERVAL_US = 100;          // performance_clock.rs:30 — the Blink clamp quantum
const ASSUMED_HEADER_BYTES = 300; // resource_timing.rs:7

// murmur3-fmix64 finalizer over BigInt (performance_clock.rs:140-153 analogue).
function fmix64(h) {
  let x = BigInt.asUintN(64, BigInt(h));
  x ^= x >> 33n;
  x = BigInt.asUintN(64, x * 0xff51afd7ed558ccdn);
  x ^= x >> 33n;
  x = BigInt.asUintN(64, x * 0xc4ceb9fe1a85ec53n);
  x ^= x >> 33n;
  return x;
}

class Clock {
  /**
   * @param {object} opts { timeOriginMs?: number, secretHex?: string }
   * timeOriginMs anchors the REAL epoch (default: actual Date.now() at construction —
   * real epoch, origin-anchored per §11.4.4). secretHex is the per-process secret.
   */
  constructor(opts = {}) {
    this._secret = opts.secretHex
      ? BigInt('0x' + opts.secretHex)
      : BigInt.asUintN(64, BigInt('0x' + crypto.randomBytes(8).toString('hex')));
    // real monotonic µs since process start
    this._t0 = process.hrtime.bigint();
    // the origin itself is clamped (performance_clock.rs:69-78)
    this._originUs = this._clampUs(this._rawNowUs());
    this.timeOriginMs = opts.timeOriginMs != null ? opts.timeOriginMs : Date.now();
  }

  _rawNowUs() {
    return Number((process.hrtime.bigint() - this._t0) / 1000n);
  }

  /** Blink clamp: round to the 100 µs grid, up/down per a per-boundary threshold. */
  _clampUs(us) {
    const base = Math.floor(us / INTERVAL_US) * INTERVAL_US;
    const frac = (us - base) / INTERVAL_US;              // 0..1 inside the boundary
    const thr = Number(fmix64(BigInt(base) ^ this._secret) & ((1n << 53n) - 1n)) / Math.pow(2, 53);
    return frac < thr ? base : base + INTERVAL_US;
  }

  /** Clamped monotonic ms since the (clamped) origin — performance.now(). */
  now() {
    const clampedUs = this._clampUs(this._rawNowUs());
    return Math.max(0, clampedUs - this._originUs) / 1000;
  }

  /** Real epoch ms, origin-anchored: timeOrigin + monotonic. */
  epochMs() {
    return this.timeOriginMs + this.now();
  }

  get originMs() {
    return this.timeOriginMs;
  }

  /** Raw (unclamped) elapsed ms — for pacing internals only, never exposed to the VM. */
  rawMs() {
    return this._rawNowUs() / 1000;
  }
}

/**
 * Build a PerformanceResourceTiming-shaped entry when only the total duration is known
 * (resource_timing.rs:48-70). Fractions come from the profile's resource_timing section.
 */
function resourceTiming(clock, { name = 'https://www.gstatic.com/', durationMs, encodedBodySize = 0,
                                  profile, crossOrigin = true, startTimeMs = 0 }) {
  const rt = (profile && profile.resource_timing) || { redirect: 0, dns: 0.02, connect: 0.08, ttfb: 0.55, download: 0.35 };
  const d = Math.max(0, durationMs);
  const dnsEnd = startTimeMs + d * (rt.redirect + rt.dns);
  const connectEnd = dnsEnd + d * rt.connect;
  const responseStart = connectEnd + d * rt.ttfb;   // ttfb boundary
  const responseEnd = startTimeMs + d;
  const entry = {
    name,
    entryType: 'resource',
    startTime: startTimeMs,
    duration: d,
    initiatorType: 'script',
    nextHopProtocol: 'h2',                           // resource_timing.rs:9 — always h2
    workerStart: 0,
    redirectStart: 0,
    redirectEnd: 0,
    fetchStart: startTimeMs,
    domainLookupStart: startTimeMs + d * rt.redirect,
    domainLookupEnd: dnsEnd,
    connectStart: dnsEnd,
    secureConnectionStart: connectEnd - d * 0.04,
    connectEnd,
    requestStart: crossOrigin ? 0 : responseStart,   // :62-70 cross-origin restriction
    responseStart: crossOrigin ? 0 : responseStart,
    responseEnd,
    transferSize: crossOrigin ? 0 : encodedBodySize + ASSUMED_HEADER_BYTES,
    encodedBodySize: crossOrigin ? 0 : encodedBodySize,
    decodedBodySize: crossOrigin ? 0 : encodedBodySize,
  };
  return entry;
}

/**
 * Reverse-scheduled probe marks (session/timing.rs:86-108 pattern): `count` probes whose
 * [start, end] marks sit startup_ms after boot, duration+1 ms apart, ending pending_ms
 * before the emit send time. Returns [{start, end, duration}] in clock-ms.
 */
function probeMarks(clock, count, { startupMs = 119, pendingMs = 227 } = {}) {
  const emitAt = clock.now();
  const lastEnd = emitAt - pendingMs;
  const marks = [];
  let end = lastEnd;
  for (let i = 0; i < count; i++) {
    const step = 1 + Math.max(1, Math.round(clock.rawMs() / Math.max(1, count))); // duration+1 spacing
    const start = Math.max(startupMs, end - step);
    marks.push({ start, end, duration: end - start });
    end = start - 1;
    if (start <= startupMs) break;
  }
  return marks.reverse();
}

module.exports = { Clock, INTERVAL_US, ASSUMED_HEADER_BYTES, fmix64, resourceTiming, probeMarks };
