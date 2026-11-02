//! §11.1 profile load + validate-before-anything (the browser.rs:300-404 discipline).
//! Field-naming errors BEFORE anything runs; the UA cross-check (rule 7) is hard.

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;

/// The one wire UA of the whole folder (rule 7) — every profile must agree with it.
pub const CHAIN_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub engine: String, // chromium | webkit
    pub transport: Transport,
    pub browser: Browser,
    pub navigator: Navigator,
    pub webgl: WebGl,
    pub interaction: Interaction,
    pub timing: Timing,
    #[serde(default)]
    pub resource_timing: Option<ResourceTiming>,
    #[serde(default)]
    pub answers: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    pub impersonate: String,
    pub user_agent: String,
    #[serde(default)]
    pub sec_ch_ua: String,
    #[serde(default)]
    pub sec_ch_ua_mobile: String,
    #[serde(default)]
    pub sec_ch_ua_platform: String,
    pub accept_language: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Browser {
    pub inner_width: u32,
    pub inner_height: u32,
    pub outer_height: u32,
    pub screen: Screen,
    pub device_pixel_ratio: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Screen {
    pub width: u32,
    pub height: u32,
    pub avail_height: u32,
    pub color_depth: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Navigator {
    pub platform: String,
    pub languages: Vec<String>,
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    pub max_touch_points: u32,
    pub webdriver: bool,
    #[serde(default)]
    pub pdf_viewer_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebGl {
    pub vendor: String,
    pub renderer: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interaction {
    pub ready_delay_ms: u32,
    pub touch: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timing {
    pub startup_ms: i64,
    pub pending_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTiming {
    #[serde(default)]
    pub redirect: f64,
    #[serde(default)]
    pub dns: f64,
    #[serde(default)]
    pub connect: f64,
    #[serde(default)]
    pub ttfb: f64,
    #[serde(default)]
    pub download: f64,
}

pub fn load(folder: &std::path::Path, profile_id: &str) -> Result<Profile> {
    let path = folder.join("profiles").join(format!("{profile_id}.json"));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("profile {}: unreadable", path.display()))?;
    let prof: Profile = serde_json::from_str(&text)
        .with_context(|| format!("profile {}: schema invalid", path.display()))?;
    validate(&prof)?;
    Ok(prof)
}

/// Cross-checks on load — a failure names the field (browser.rs:170-194 pattern).
pub fn validate(p: &Profile) -> Result<()> {
    if p.engine != "chromium" && p.engine != "webkit" {
        bail!("profile {}: engine must be chromium|webkit (got {})", p.id, p.engine);
    }
    if p.transport.user_agent != CHAIN_UA {
        bail!(
            "profile {}: transport.user_agent must equal the chain UA (rule 7) — a profile whose UA the chain never sends fails validation and the runner falls back to chrome-win",
            p.id
        );
    }
    if p.transport.impersonate.is_empty() {
        bail!("profile {}: transport.impersonate missing", p.id);
    }
    if p.timing.startup_ms < 0 || p.timing.pending_ms < 0 {
        bail!("profile {}: timing.* must be non-negative", p.id);
    }
    Ok(())
}

/// The §11.1 fallback: the selected profile fails validation → chrome-win.
pub fn load_with_fallback(folder: &std::path::Path, profile_id: &str) -> Result<(Profile, Option<String>)> {
    match load(folder, profile_id) {
        Ok(p) => Ok((p, None)),
        Err(e) if profile_id != "chrome-win" => {
            let fallback = load(folder, "chrome-win")
                .with_context(|| format!("selected profile {profile_id} failed AND chrome-win fallback failed: {e}"))?;
            Ok((fallback, Some(profile_id.to_string())))
        }
        Err(e) => Err(e),
    }
}
