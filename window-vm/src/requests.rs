//! §10.2 per-step request builders — recap step → cfsolve machinery → this builder, ported
//! from solve_service.py's verified curl_cffi calls (do_anchor/do_reload/do_payload/
//! do_userverify/post_check_captcha). Headers are pushed in Chrome XHR order (pseudo >
//! content-type > accept > sec-ch-ua* > ua > origin > sec-fetch-* > referer).

use anyhow::Result;

use crate::protobuf::{derive_co, X_BROWSER_VALIDATION, VER};
use crate::transport::Transport;
use crate::window::profile::CHAIN_UA;

/// §10.4 step 0 — cookie warm-up: plain GET https://www.google.com/ KEEPING Set-Cookie.
/// Rationale is the workspace's own (audio_solve.py:545-566): skipping this triggers the
/// "automated queries" audio block nearly 100% of the time.
pub async fn warmup(t: &Transport) -> Result<u64> {
    let resp = t
        .client
        .get("https://www.google.com/")
        .header("user-agent", CHAIN_UA)
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .send()
        .await?;
    let status = resp.status().as_u16();
    let len = resp.content_length().unwrap_or(0);
    eprintln!("[warmup] -> {status} | jar seeded");
    Ok(len)
}

/// anchor GET (e2e.py:40 builder; param table README:179-190) → (status, html).
pub async fn anchor(t: &Transport, page_url: &str, sitekey: &str) -> Result<(u16, String)> {
    let cb = format!("{:013}", rand::Rng::gen_range(&mut rand::thread_rng(), 10u64.pow(12)..10u64.pow(13)));
    let co = derive_co(page_url)?;
    let url = format!(
        "https://www.google.com/recaptcha/api2/anchor?ar=1&k={sitekey}&co={co}&hl=en&v={VER}&size=normal&cb={cb}"
    );
    let resp = t.client.get(&url).header("user-agent", CHAIN_UA).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await?;
    Ok((status, text))
}

/// reload POST (application/x-protobuffer; the e2e.py:99 header set with the BFT-LESS
/// bframe referer — the live-exercised variant, recap step 3; later rounds carry the
/// previous rresp's bftToken as a real client would, solve_service.py do_reload).
pub async fn reload(
    t: &Transport,
    sitekey: &str,
    body: Vec<u8>,
    bft: Option<&str>,
) -> Result<(u16, String)> {
    let mut referer = format!("https://www.google.com/recaptcha/api2/bframe?hl=en&v={VER}&k={sitekey}");
    if let Some(b) = bft {
        referer.push_str(&format!("&bft={b}"));
    }
    let resp = t
        .client
        .post(format!("https://www.google.com/recaptcha/api2/reload?k={sitekey}"))
        .header("accept", "*/*")
        .header("content-type", "application/x-protobuffer")
        .header("origin", "https://www.google.com")
        .header("referer", referer)
        .header("user-agent", CHAIN_UA)
        .header("x-browser-validation", X_BROWSER_VALIDATION)
        .body(body)
        .send()
        .await?;
    let status = resp.status().as_u16();
    let text = resp.text().await?;
    Ok((status, text))
}

/// payload GET (e2e.py:155 header set) — the single endpoint serves both media; the caller
/// discriminates by content magic, never by trusting the rresp (§10.4 step 4a).
pub async fn payload(t: &Transport, sitekey: &str, p: &str) -> Result<(u16, String, Vec<u8>)> {
    let url = format!("https://www.google.com/recaptcha/api2/payload?p={p}&k={sitekey}");
    let resp = t
        .client
        .get(&url)
        .header(
            "accept",
            "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        )
        .header("referer", format!("https://www.google.com/recaptcha/api2/bframe?hl=en&v={VER}&k={sitekey}"))
        .header("user-agent", CHAIN_UA)
        .send()
        .await?;
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = resp.bytes().await?.to_vec();
    Ok((status, ct, body))
}

/// userverify POST (the cfsolve `submit_form` shape — urlencoded; e2e.py:476-485's field
/// set v/c/response/t/ct/ch/oc/pm with the REAL response encoding, bug 2 dead).
pub async fn userverify(
    t: &Transport,
    sitekey: &str,
    c: &str,
    response_b64: &str,
    t_ms: &str,
    ch: &str,
    oc: &str,
    bft: Option<&str>,
) -> Result<(u16, String)> {
    let mut referer = format!("https://www.google.com/recaptcha/api2/bframe?hl=en&v={VER}&k={sitekey}");
    if let Some(b) = bft {
        referer.push_str(&format!("&bft={b}"));
    }
    let form = [
        ("v", VER.to_string()),
        ("c", c.to_string()),
        ("response", response_b64.to_string()),
        ("t", t_ms.to_string()),
        ("ct", t_ms.to_string()),
        ("ch", ch.to_string()),
        ("oc", oc.to_string()),
        ("pm", crate::protobuf::PM.to_string()),
    ];
    let body = serde_urlencoded(&form);
    let resp = t
        .client
        .post(format!("https://www.google.com/recaptcha/api2/userverify?k={sitekey}"))
        .header("accept", "*/*")
        .header("content-type", "application/x-www-form-urlencoded;charset=UTF-8")
        .header("origin", "https://www.google.com")
        .header("referer", referer)
        .header("user-agent", CHAIN_UA)
        .header("x-browser-validation", X_BROWSER_VALIDATION)
        .body(body)
        .send()
        .await?;
    let status = resp.status().as_u16();
    let text = resp.text().await?;
    Ok((status, text))
}

/// link4m check-captcha (e2e.py:710-729): S1 first, then link4m.com — §15.2/§17.2.
pub async fn check_captcha(
    t: &Transport,
    token: &str,
    alias: &str,
    code: &str,
) -> Result<Vec<(String, u16, String)>> {
    let form = serde_urlencoded(&[
        ("g-recaptcha-response", token.to_string()),
        ("alias", alias.to_string()),
        ("code", code.to_string()),
    ]);
    let mut out = Vec::new();
    for host in ["https://s1.link4m.app", "https://link4m.com"] {
        let resp = t
            .client
            .post(format!("{host}/links/check-captcha"))
            .header("origin", "https://link4m.com")
            .header("referer", format!("https://link4m.com/go/{alias}"))
            .header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
            .header("x-requested-with", "XMLHttpRequest")
            .header("user-agent", CHAIN_UA)
            .body(form.clone())
            .send()
            .await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        eprintln!("[check-captcha] POST {host}/links/check-captcha -> {status} len={}", text.len());
        // a successful verdict stops the host ladder (e2e.py:718's early return)
        let success = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|j| j.get("success").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        out.push((host.trim_start_matches("https://").to_string(), status, text));
        if success {
            break;
        }
    }
    Ok(out)
}

/// application/x-www-form-urlencoded serializer (cfsolve's `Serializer` shape) — std-only.
pub fn serde_urlencoded(fields: &[(&str, String)]) -> String {
    let mut out = String::new();
    for (k, v) in fields {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&urlencode(k));
        out.push('=');
        out.push_str(&urlencode(v));
    }
    out
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'*' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// anchor-token + ainput-key extraction (e2e.py:44 / solve_service.py extract_anchor_keys).
pub fn extract_anchor(html: &str) -> (Option<String>, Option<i64>, Option<i64>) {
    // NO window cap: the real token is ~1900 chars — a bounded segment truncated it at 172
    // chars and the truncated f2 made Google answer the reload with a degenerate
    // ["rresp",null,…,4] envelope (the 2026-11-01 differential, root-caused here).
    let tok = html.find("id=\"recaptcha-token\"").and_then(|i| {
        let rest = &html[i..];
        rest.find("value=\"").map(|v| {
            let after = &rest[v + 7..];
            after.chars().take_while(|c| *c != '"').collect::<String>()
        })
    });
    let (k18, k31) = extract_anchor_keys(html);
    (tok, k18, k31)
}

/// Best-effort ainput index-18/31 extraction (§10.4 step 1). VERIFIED against a live
/// anchor (2026-11-01, runs/anchor_live.html): the array is embedded as the argument of
/// `recaptcha.anchor.Main.init("...")` — a JS string with \x22 escapes — so the naive
/// '"ainput"' lookup never matches. Decodes the JS string, parses the ainput JSON
/// (arr[0]=="ainput", len 32), and reads the timestamp-like keys at index 18/31.
/// Absent/garbled → the legacy fallback → (None, None), which degrades to
/// encrypted:false, never to a corrupt request.
pub fn extract_anchor_keys(anchor_html: &str) -> (Option<i64>, Option<i64>) {
    const MARKER: &str = "recaptcha.anchor.Main.init(\"";
    let start = match anchor_html.find(MARKER) {
        Some(i) => i + MARKER.len(),
        None => return legacy_extract_anchor_keys(anchor_html),
    };
    // scan to the closing unescaped quote of the JS string argument
    let bytes = anchor_html.as_bytes();
    let mut end = None;
    let mut esc = false;
    for (j, &b) in bytes[start..].iter().enumerate() {
        let c = b as char;
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' => esc = true,
            '"' => {
                end = Some(start + j);
                break;
            }
            _ => {}
        }
    }
    let end = match end {
        Some(e) => e,
        None => return legacy_extract_anchor_keys(anchor_html),
    };
    let decoded = js_unescape(&anchor_html[start..end]);
    let arr: serde_json::Value = match serde_json::from_str(&decoded) {
        Ok(v) => v,
        Err(_) => return legacy_extract_anchor_keys(anchor_html),
    };
    let a = match arr.as_array() {
        Some(a) => a,
        None => return legacy_extract_anchor_keys(anchor_html),
    };
    if a.first().and_then(|v| v.as_str()) != Some("ainput") {
        return legacy_extract_anchor_keys(anchor_html);
    }
    let k18 = a.get(18).and_then(|v| v.as_i64());
    let k31 = a.get(31).and_then(|v| v.as_i64());
    (k18, k31)
}

/// Decode a JS string literal body: \xNN, \uNNNN and the simple escapes.
fn js_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Ok(v) = u8::from_str_radix(&hex, 16) {
                        out.push(v as char);
                    }
                }
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(v) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(v) {
                            out.push(ch);
                        }
                    }
                }
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Legacy path: an unescaped inline `["ainput",...]` array (older widget versions).
fn legacy_extract_anchor_keys(anchor_html: &str) -> (Option<i64>, Option<i64>) {
    let i = match anchor_html.find("\"ainput\"").or_else(|| anchor_html.find("'ainput'")) {
        Some(i) => i,
        None => return (None, None),
    };
    let start = match anchor_html[..i].rfind('[') {
        Some(s) => s,
        None => return (None, None),
    };
    // depth-walk the array whose element 0 IS "ainput"
    let bytes = anchor_html.as_bytes();
    let mut depth = 0i32;
    let mut end = None;
    let mut in_str = false;
    let mut esc = false;
    for (j, &b) in bytes[start..].iter().enumerate() {
        let c = b as char;
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(start + j + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = match end {
        Some(e) => e,
        None => return (None, None),
    };
    let arr: serde_json::Value = match serde_json::from_str(&anchor_html[start..end]) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let arr = match arr.as_array() {
        Some(a) => a,
        None => return (None, None),
    };
    if arr.first().and_then(|v| v.as_str()) != Some("ainput") {
        return (None, None);
    }
    let k18 = arr.get(18).and_then(|v| v.as_i64());
    let k31 = arr.get(31).and_then(|v| v.as_i64());
    (k18, k31)
}
