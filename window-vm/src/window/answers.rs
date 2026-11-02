//! §11.2 the recorded-answer store — `window/answers/fingerprint.json` (already seeded).
//! Per-entry provenance is explicit: `recorded` = byte-faithful from the captures,
//! `profile` = derived from the profile, `computed` = live-derived at emit time.
//! The store is READ here; the add-only merge discipline lives in the seeding tooling.

use anyhow::{Context as _, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub reference: String,
    #[serde(default)]
    pub seed_note: String,
    #[serde(default)]
    pub signals: BTreeMap<String, SignalEntry>,
    #[serde(default)]
    pub vm_keys: BTreeMap<String, SignalEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignalEntry {
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub key: Option<i64>,
    #[serde(default)]
    pub elapsed: Option<i64>,
    #[serde(default)]
    pub hashed: Option<bool>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub treatment: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl SignalEntry {
    /// `replayed` with a real value → the recorded triple replays byte-faithful (§11.3).
    /// Absent or null values are volatile-blanked at seed time and answered live instead.
    pub fn is_replayed(&self) -> bool {
        self.treatment.as_deref() == Some("replayed")
            && !matches!(self.value, None | Some(serde_json::Value::Null))
    }
}

pub fn load(folder: &std::path::Path, answers_rel: &str) -> Result<Store> {
    let path = folder.join(answers_rel);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("answers store unreadable: {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("answers store invalid: {}", path.display()))
}
