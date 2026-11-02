//! §10.1 the transport — the cfsolve `BrowserClient` analogue over wreq (BoringSSL-backed):
//! ONE client per solve, shared by every chain request to preserve cookies and transport
//! settings (cfsolve src/http/client.rs:23-31 discipline). Built from the published
//! `wreq-util` `Emulation::Chrome120` — the profile every genuine rresp replay in this
//! workspace ran under and the one rule 7 mandates (§9.1 deviation 2: NO vendor patch; we
//! send no Chrome-154-specific hello). §0 historically shipped NO proxy plumbing; an
//! OPT-IN `--proxy <url>` face was added later at user request — the DEFAULT remains the
//! direct client, the env is never read for proxies, and a proxy failure surfaces as a
//! controlled step failure (never a silent retry through the direct client).
//!
//! Header ORDER: curl_cffi's lesson (net_bridge_server.py) and cfsolve's header_order.rs
//! converge on the same fact — insertion order of the per-request header map decides the
//! wire order. Each builder in requests.rs pushes headers in Chrome order.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use wreq::Client;
use wreq::cookie::Jar;
use wreq_util::Emulation;

use crate::window::profile::CHAIN_UA;

pub struct Transport {
    pub client: Client,
    pub jar: Arc<Jar>,
}

impl Transport {
    pub fn build() -> Result<Self> {
        Self::build_with_proxy(None)
    }

    /// `proxy: Some("http://host:port") | "socks5://…"` routes EVERY chain request through
    /// it (one shared client — cookies and the emulated TLS hello are preserved; wreq
    /// honors Proxy::all for http/https). None = the §0 direct client.
    pub fn build_with_proxy(proxy: Option<&str>) -> Result<Self> {
        let jar = Arc::new(Jar::default());
        let mut b = Client::builder()
            .emulation(Emulation::Chrome120)
            .cookie_provider(jar.clone())
            .timeout(Duration::from_secs(30))
            // §10.1: certificates stay VERIFIED — wreq 0.16.1 has no accept-invalid-certs
            // toggle; its default is verification, which is what the design mandates.
            ;
        if let Some(p) = proxy {
            let wreq_proxy = wreq::Proxy::all(p).with_context(|| format!("proxy spec invalid: {p}"))?;
            b = b.proxy(wreq_proxy);
        }
        let client = b.build().context("wreq Client build (BoringSSL backend)")?;
        Ok(Transport { client, jar })
    }

    /// Shared header set of every chain request (rule 7 — the single wire UA).
    pub fn base_headers() -> Vec<(&'static str, String)> {
        vec![("user-agent", CHAIN_UA.to_string())]
    }
}
