//! §10.3 the e2e.py byte-level ports (solve_service.py is the verified reference port):
//! varint, the latin-1 restore (HARD error on any codepoint > U+00FF — the Python `except:
//! orig=raw` fallback would silently keep a corrupt body, so the port does the opposite),
//! the field walker + rebuild, parse_rresp, parse_uvresp, encode_response.
//! The two known HTTP-path bugs are dead by construction: the body is an EMBEDDED REDACTED
//! constant (never an importlib-exec of api.py — bug 1) and the userverify `response` is the
//! canonical JSON ARRAY shape (never comma-joined — bug 2).

use anyhow::{bail, Context as _, Result};
use base64::Engine as _;
use serde_json::{json, Value};

pub const VER: &str = "xg_pWYS8-HRESiV6Rdg4aY_R"; // e2e.py:14 — version rotation breaks it
pub const X_BROWSER_VALIDATION: &str = "rvacWodMMC8CsnYVvG35HCYGtZY="; // api.py:29 / e2e.py:99
pub const CH_CONST: &str = "2801408"; // api2.py:45 — static literal
pub const OC_CONST: &str = "0Il3sfQw"; // api2.py:46 — static literal
pub const PM: &str = "51bGwsbnVsbCxbbnVsbCxudWxsLG51bGwsWzcsNS41NDI4NTcxNDQ1NjAxMzI1LDAuMDA3MzYxMTcxNzE4NzAwMTE1LDE2XSxbMCxudWxsLDBdLDEsMCwxXV0"; // api2.py:47 head-truncated capture
pub const S_INNER: &str = "4cd7"; // api2.py:42
pub const E_INNER: &str = "bXVs"; // api2.py:42
pub const DEMO_SITEKEY: &str = "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-"; // the ONLY sitekey hardcoded (§0)

/// The captured reload body, REDACTED (§9.4 / rule 2): f2 (stale anchor token, 1892 chars)
/// → '0'*1892; f14 (link4m sitekey) → the PUBLIC demo key; f21 (prior-captcha token) →
/// 'A'*116. f1/f5/f6/f16/f20/f25 ship as captured. 8336 latin-1 chars round-trip to 8336
/// bytes — the §9.3 selftest asserts that count. Stored as LATIN-1 BYTES (include_str! would
/// reject the non-UTF-8 file); the latin-1 domain is byte-per-char, so the byte identity IS
/// the UTF-8→latin-1 restoration of e2e.py:86-89 — the Python side validated the
/// codepoints-≤-U+00FF invariant at seed time.
pub const RELOAD_BODY_TEMPLATE_BYTES: &[u8] = include_bytes!("reload_template.txt");

/// The latin-1 restoration as bytes: the file already IS the byte-exact restored body; the
/// function documents the transform and keeps the §10.3 call shape (a `String` variant is
/// avoided deliberately — re-decoding latin-1 to UTF-8 and back can only lose fidelity).
pub fn template_latin1_bytes() -> Result<Vec<u8>> {
    Ok(RELOAD_BODY_TEMPLATE_BYTES.to_vec())
}

pub fn varint(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = n;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
    out
}

pub fn read_varint(buf: &[u8], i: &mut usize) -> Option<u64> {
    let mut shift = 0u32;
    let mut result = 0u64;
    while *i < buf.len() {
        let b = buf[*i];
        *i += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// Walk the protobuf body: (field_number, value_bytes) per length-delimited field —
/// `tag + varint(len) + value` for every field, never regex-over-values (§9.4).
pub fn walk_fields(body: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let tag = read_varint(body, &mut i).context("tag varint")?;
        let len = read_varint(body, &mut i).context("len varint")? as usize;
        if i + len > body.len() {
            bail!("field {tag}: len {len} overruns body ({}/{})", i, body.len());
        }
        out.push((tag >> 3, body[i..i + len].to_vec()));
        i += len;
    }
    Ok(out)
}

/// §9.4 structural surgery on the restored captured body:
///   f2 (tag 0x12) ← fresh anchor token; f14 (tag 0x72) ← target sitekey;
///   f6 (tag 0x32) ← challenge mode 'a' (audio; the capture carries 'fi');
///   f21 (tag 0xAA 0x01) stays blanked unless `prior_token` refills it;
///   f5 ← fingerprint_hash and f16 ← fingerprint_encrypted, applied ONLY as a pair
///   (f5 is the hash of the f16 plaintext — never upgrade one without the other).
pub fn rebuild_reload_body(
    anchor_token: &str,
    sitekey: &str,
    mode: &str,
    prior_token: Option<&str>,
    fingerprint_hash: Option<i64>,
    fingerprint_encrypted: Option<&str>,
) -> Result<Vec<u8>> {
    let body = template_latin1_bytes()?;
    let fields = walk_fields(&body)?;
    let mut repl: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();
    repl.insert(2, anchor_token.as_bytes().to_vec());
    repl.insert(14, sitekey.as_bytes().to_vec());
    repl.insert(6, mode.as_bytes().to_vec());
    if let Some(pt) = prior_token {
        repl.insert(21, pt.as_bytes().to_vec());
    }
    // §13.3 window upgrade — BOTH or NEITHER (a fresh hash over a stale ciphertext would be
    // a mismatched pair; the encrypted slot must decode to real bytes).
    if let (Some(fh), Some(fe)) = (fingerprint_hash, fingerprint_encrypted) {
        match base64::engine::general_purpose::STANDARD.decode(fe) {
            Ok(fe_bytes) if !fe_bytes.is_empty() => {
                repl.insert(5, fh.to_string().into_bytes()); // captured f5 is a decimal-string hash
                repl.insert(16, fe_bytes);
            }
            Ok(_) => eprintln!("[window] f16 empty — captured pair stays"),
            Err(e) => eprintln!("[window] f5/f16 upgrade refused — falling back to the captured pair: {e}"),
        }
    }
    let mut out = Vec::with_capacity(body.len() + 32);
    for (fnum, val) in fields {
        let v = repl.get(&fnum).cloned().unwrap_or(val);
        out.extend_from_slice(&varint((fnum << 3) | 2));
        out.extend_from_slice(&varint(v.len() as u64));
        out.extend_from_slice(&v);
    }
    Ok(out)
}

/// anchor `co` = base64(origin).replace('=', '.') where origin is the FULL origin with the
/// EXPLICIT default port (§9.3 — the capture carries https://www.google.com:443). A two-pad
/// origin must end '..'.
pub fn derive_co(page_url: &str) -> Result<String> {
    let u = url::Url::parse(page_url).map_err(|e| anyhow::anyhow!("parse {page_url}: {e}"))?;
    let port = u.port_or_known_default().unwrap_or(443);
    let origin = format!("{}://{}:{}", u.scheme(), host_str(&u), port);
    Ok(base64::engine::general_purpose::STANDARD
        .encode(origin.as_bytes())
        .replace('=', "."))
}

fn host_str(u: &url::Url) -> String {
    u.host_str().unwrap_or("").to_string()
}

fn strip_parens(text: &str) -> &str {
    let t = text.trim();
    if t.starts_with(")]}'") {
        match t.find('\n') {
            Some(i) => &t[i + 1..],
            None => &t[4.min(t.len())..],
        }
    } else {
        t
    }
}

/// parse_rresp — core e2e.py:105-152 (return set {c, p, mids, chal_type, instruction,
/// raw_j, raw_text}) EXTENDED with the envelope fields the Python fallback's own parser
/// already extracts: bft at j[15] and tokenExpiration at j[3] (solve_service.py:291-292).
pub fn parse_rresp(text: &str) -> Value {
    let stripped = strip_parens(text);
    let j: Value = match serde_json::from_str(stripped) {
        Ok(v) => v,
        Err(e) => return json!({"error": e.to_string(), "raw": &text[..text.len().min(800)]}),
    };
    let arr = match j.as_array() {
        Some(a) => a,
        None => return json!({"error": "rresp is not a list", "raw": &text[..text.len().min(800)]}),
    };
    let at = |i: usize| arr.get(i).cloned().unwrap_or(Value::Null);
    let c = at(1).as_str().map(|s| s.to_string());
    let mut p = at(9).as_str().filter(|s| s.starts_with("06AF")).map(|s| s.to_string());
    if p.is_none() {
        let re = regex_lite_06af(text);
        p = re;
    }
    let chal_type = at(5).as_str().map(|s| s.to_string());
    let token_expiration = at(3).as_u64();
    let bft = at(15).as_str().map(|s| s.to_string());
    // image targets (e2e.py:117-141 shape): pmeta anywhere in j, else the legacy j[4] layout
    let mut mids: Vec<String> = Vec::new();
    let mut label_from_pmeta: Option<String> = None;
    for el in arr {
        if let Some(a) = el.as_array() {
            if a.first().and_then(|v| v.as_str()) == Some("pmeta") {
                if let Some(inner) = a.get(1).and_then(|v| v.as_array()) {
                    if inner.first().and_then(|v| v.as_str()).map(|s| s.starts_with("/m/")).unwrap_or(false) {
                        mids.push(inner[0].as_str().unwrap_or_default().to_string());
                        if let Some(l) = inner.get(6).and_then(|v| v.as_str()) {
                            label_from_pmeta = Some(l.to_string());
                        }
                    }
                }
                break;
            }
        }
    }
    if mids.is_empty() {
        if let Some(mids_raw) = at(4).as_array() {
            if let Some(tups) = mids_raw.get(5).and_then(|v| v.as_array()) {
                for tup in tups {
                    if let Some(subs) = tup.as_array() {
                        for sub in subs {
                            if let Some(sa) = sub.as_array() {
                                if sa.first().and_then(|v| v.as_str()).map(|s| s.starts_with("/m/")).unwrap_or(false) {
                                    mids.push(sa[0].as_str().unwrap_or_default().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    json!({
        "c": c, "p": p, "chal_type": chal_type, "token_expiration": token_expiration,
        "bft": bft, "mids": mids, "label": label_from_pmeta, "raw_j": j,
    })
}

/// the `06AFcWeA…{80,}` regex fallback (e2e.py's search) — a bounded literal scan instead of
/// a regex crate: find "06AF", take the run of token characters that follows (≥ 80).
fn regex_lite_06af(text: &str) -> Option<String> {
    const TOKEN_CHARS: fn(char) -> bool = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let mut from = 0usize;
    while let Some(i) = text[from..].find("06AF") {
        let start = from + i;
        let run: String = text[start..].chars().take_while(|c| TOKEN_CHARS(*c)).collect();
        if run.len() >= 80 {
            return Some(run);
        }
        from = start + 4;
    }
    None
}

/// parse_uvresp (e2e.py:487-508): token at j[1]; an embedded rresp element = rejection /
/// dynamic continuation; accept the g-token iff len(token) > 300 (e2e.py:506 threshold).
pub fn parse_uvresp(text: &str) -> Value {
    let stripped = strip_parens(text);
    let j: Value = match serde_json::from_str(stripped) {
        Ok(v) => v,
        Err(_) => return json!({"token": Value::Null, "status": Value::Null, "dynamic_rresp": Value::Null, "error": "json"}),
    };
    let arr = match j.as_array() {
        Some(a) => a,
        None => return json!({"token": Value::Null, "status": Value::Null, "dynamic_rresp": Value::Null, "error": "json"}),
    };
    let token = arr.get(1).and_then(|v| v.as_str()).map(|s| s.to_string());
    let status = arr.get(4).cloned().unwrap_or(Value::Null);
    let mut dyn_rresp: Option<Value> = None;
    for el in arr {
        if let Some(a) = el.as_array() {
            if a.first().and_then(|v| v.as_str()) == Some("rresp") {
                dyn_rresp = Some(el.clone());
                break;
            }
        }
    }
    json!({"token": token, "status": status, "dynamic_rresp": dyn_rresp, "raw_j": j})
}

/// encode_response (§10.3): audio → {"response": "<cleaned transcript>", "s","e"};
/// image → {"response": [<int indices>], "s","e"} — base64'd, the canonical ARRAY shape of
/// recaptcha-main/README.md:1545/:1587 (bug 2 dead by construction).
pub fn encode_userverify_response(answer: &Value) -> String {
    let inner = if answer.is_array() {
        json!({"response": answer, "s": S_INNER, "e": E_INNER})
    } else {
        json!({"response": answer.as_str().unwrap_or_default(), "s": S_INNER, "e": E_INNER})
    };
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&inner).unwrap_or_default().as_bytes())
}

/// looks_like_doscaptcha (audio_solve.py:226-231's detector on bytes, §8.4).
pub fn looks_like_doscaptcha(body: &[u8]) -> bool {
    body.windows(20).any(|w| w == b"rc-doscaptcha-header")
        || body
            .windows(40)
            .any(|w| w == b"Your computer or network may be sending automated queries")
}

/// t/ct in MILLISECONDS, clamped into the §8.3 pacing window (§9.6 step 3). Both known wire
/// samples read as ms (e2e.py:481's '3854'; README:1560-1561's t: 24521). The one live
/// rejection this folder produced carried seconds t/ct=6 — consistent with a 6-ms solve
/// being the worse bot signal; the unit remains a hypothesis consistent with both (§18.1a).
pub fn clamp_tct_ms(elapsed_seconds: f64) -> String {
    ((elapsed_seconds * 1000.0).clamp(4000.0, 15000.0) as i64).to_string()
}

/// The §9.6 audio cleaning — the exact audio_solve.py:80-96 pipeline (lowercase, the 8
/// preamble phrases removed verbatim, punctuation → space, whitespace collapsed). Applied
/// to the shim's transcript result so the Rust side owns the final answer shape.
pub fn clean_transcript(raw: &str) -> String {
    const PREAMBLE: &[&str] = &[
        "please listen carefully to the following words",
        "please listen carefully to the following",
        "please listen carefully",
        "listen carefully and type what you hear",
        "type what you hear",
        "please type",
        "if the audio does not play",
        "make sure your volume is turned up",
    ];
    let mut cleaned = raw.to_lowercase();
    for p in PREAMBLE {
        cleaned = cleaned.replace(p, " ");
    }
    let mut out = String::with_capacity(cleaned.len());
    for ch in cleaned.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch.is_whitespace() {
            out.push(ch);
        } else {
            out.push(' ');
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_round_trips_to_8336_bytes() {
        let b = template_latin1_bytes().expect("all chars ≤ U+00FF");
        assert_eq!(b.len(), 8336, "the §9.3 selftest byte count");
    }

    #[test]
    fn walk_rebuild_round_trip() {
        let body = template_latin1_bytes().unwrap();
        let fields = walk_fields(&body).unwrap();
        assert!(!fields.is_empty());
        let rebuilt = rebuild_reload_body("TOKEN2", "SITEKEY", "a", None, None, None).unwrap();
        let rf = walk_fields(&rebuilt).unwrap();
        assert_eq!(fields.len(), rf.len());
        assert_eq!(rf.iter().find(|(n, _)| *n == 2).unwrap().1, b"TOKEN2");
        assert_eq!(rf.iter().find(|(n, _)| *n == 6).unwrap().1, b"a");
    }

    #[test]
    fn varint_round_trip() {
        for n in [0u64, 1, 127, 128, 300, 16383, 16384, 8336, u64::from(u32::MAX)] {
            let v = varint(n);
            let mut i = 0usize;
            assert_eq!(read_varint(&v, &mut i), Some(n));
            assert_eq!(i, v.len());
        }
    }

    #[test]
    fn tct_clamp() {
        assert_eq!(clamp_tct_ms(6.0), "6000");
        assert_eq!(clamp_tct_ms(0.2), "4000");
        assert_eq!(clamp_tct_ms(120.0), "15000");
    }
}
