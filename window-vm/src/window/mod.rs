//! §9.4 the fake window surface in Rust — profile, answers, probe, clock. The "window" is
//! DATA (cfsolve's method): a validated profile plus a stored-answer record per probe,
//! everything cross-checked before any network request (§11).

pub mod answers;
pub mod clock;
pub mod probe;
pub mod profile;
