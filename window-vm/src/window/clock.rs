//! §11.4 timing fakes — the `window/timing.js` port (cfsolve performance_clock.rs analogue).
//! Blink 100 µs clamp for `performance.now()`: readings quantized to 100 µs boundaries —
//! round DOWN until a per-boundary pseudorandom threshold (murmur3-fmix64 of
//! `boundary ^ secret`, top-53-bit fraction), then round UP. The origin is clamped too.
//! The clock stays REAL (never frozen — the VM's Xn histogram depends on real deltas); only
//! the resolution is faked.

use rand::RngCore;
use std::time::Instant;

pub const INTERVAL_US: u64 = 100; // performance_clock.rs:30 / timing.js INTERVAL_US

/// murmur3-fmix64 finalizer — timing.js fmix64 over BigInt, plain u64 here.
pub fn fmix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    x
}

fn clamp_us_raw(us: u64, secret: u64) -> u64 {
    let base = us / INTERVAL_US * INTERVAL_US;
    let frac = (us - base) as f64 / INTERVAL_US as f64;
    let thr = (fmix64(base ^ secret) & ((1u64 << 53) - 1)) as f64 / (1u64 << 53) as f64;
    if frac < thr { base } else { base + INTERVAL_US }
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct Clock {
    secret: u64,
    made_at: Instant,
    origin_us: u64, // the clamped origin
    time_origin_ms: u64,
}

impl Clock {
    /// The per-process secret is drawn once from OS entropy (§11.4.1).
    pub fn new() -> Self {
        let secret = rand::thread_rng().next_u64();
        Self::with_secret(secret)
    }

    pub fn with_secret(secret: u64) -> Self {
        let made_at = Instant::now();
        let origin_us = clamp_us_raw(0, secret);
        Clock { secret, made_at, origin_us, time_origin_ms: now_epoch_ms() }
    }

    fn raw_now_us(&self) -> u64 {
        self.made_at.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }

    /// Blink clamp: round to the 100 µs grid, up/down per the per-boundary threshold.
    fn clamp(&self, us: u64) -> u64 {
        clamp_us_raw(us, self.secret)
    }

    /// Clamped monotonic ms since the (clamped) origin — `performance.now()`.
    pub fn now(&self) -> f64 {
        let clamped = self.clamp(self.raw_now_us());
        (clamped.saturating_sub(self.origin_us)) as f64 / 1000.0
    }

    /// Real epoch ms, origin-anchored: timeOrigin + monotonic (§11.4.4).
    pub fn epoch_ms(&self) -> u64 {
        self.time_origin_ms.saturating_add(self.now() as u64)
    }

    pub fn time_origin(&self) -> u64 {
        self.time_origin_ms
    }

    /// Raw (unclamped) elapsed ms — pacing internals only, never exposed to the VM.
    pub fn raw_ms(&self) -> f64 {
        self.raw_now_us() as f64 / 1000.0
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

/// Reverse-scheduled probe marks (session/timing.rs:86-108 pattern; timing.js probeMarks):
/// each probe's start/end marks sit `startup_ms` after boot, `duration+1` ms apart, ending
/// `pending_ms` before the emit send time. Returns [(start, end, duration)] in clock-ms.
pub fn probe_marks(clock: &Clock, count: usize, startup_ms: i64, pending_ms: i64) -> Vec<(i64, i64, i64)> {
    let emit_at = clock.now() as i64;
    let mut end = emit_at - pending_ms;
    let mut marks = Vec::with_capacity(count);
    for _ in 0..count {
        let step = 1 + std::cmp::max(1, (clock.raw_ms() as i64 / count as i64).max(1));
        let start = std::cmp::max(startup_ms, end - step);
        marks.push((start, end, end - start));
        end = start - 1;
        if start <= startup_ms {
            break;
        }
    }
    marks.reverse();
    marks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantized_to_the_100us_grid() {
        let c = Clock::with_secret(0x0011_2233_4455_6677);
        for _ in 0..200 {
            let ms = c.now();
            let us = ms * 1000.0;
            assert!((us - (us / 100.0).round() * 100.0).abs() < 1e-6, "not on grid: {us}");
        }
    }

    #[test]
    fn monotonic_never_frozen() {
        let c = Clock::with_secret(0xaabb_ccdd_eeff_0011);
        let mut prev = -1.0f64;
        for _ in 0..200 {
            let v = c.now();
            assert!(v >= prev, "clock went backwards");
            prev = v;
        }
    }
}
