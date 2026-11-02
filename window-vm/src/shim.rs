//! §13.1 the python subprocess calls — the Rust engine calls solve_service.py's SHIM faces
//! (built stage 2): `transcribe --audio-b64 -` (MP3 base64 on stdin → cleaned transcript on
//! stdout) and `classify --img-b64 <b64> --targets "…"`. All shim logs go to the child's
//! stderr; stdout carries exactly one line. Vision deps missing → the shim prints
//! {"skipped":"deps_missing"} and the engine re-rolls WITHOUT consuming an attempt (§10.4
//! step 4b). The interpreter resolves RC_PYTHON → python3 → python (§6.1 RC_PYTHON).

use anyhow::{Context as _, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn resolve_python() -> String {
    if let Ok(p) = std::env::var("RC_PYTHON") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    for c in ["python3", "python"] {
        if Command::new(c)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return c.to_string();
        }
    }
    "python".to_string()
}

/// The whisper shim: MP3 bytes in → the CLEANED transcript out (single line). The shim's
/// transcribe face already applies the audio_solve.py:80-96 cleaning; the engine re-applies
/// the idempotent cleaner so the final answer shape is owned here. Called synchronously
/// from a blocking task — the child is reaped by wait_with_output.
pub fn transcribe(mp3_bytes: &[u8], model: &str, dump_dir: Option<&Path>) -> Result<String> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(mp3_bytes);
    if let Some(d) = dump_dir {
        let _ = std::fs::write(d.join("challenge.mp3"), mp3_bytes);
    }
    let exe = resolve_python();
    let mut child = Command::new(&exe)
        .args(["solve_service.py", "transcribe", "--audio-b64", "-", "--model", model])
        .current_dir(project_root()?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {exe} solve_service.py transcribe"))?;
    {
        let stdin = child.stdin.as_mut().expect("stdin piped");
        stdin.write_all(b64.as_bytes()).context("pipe MP3 b64 to the shim")?;
    } // stdin dropped here → EOF → the shim decodes
    let out = child
        .wait_with_output()
        .context("wait for the transcribe shim")?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    eprintln!(
        "[transcribe] shim rc={} cleaned={:?}",
        out.status.code().unwrap_or(-1),
        &text[..text.len().min(60)]
    );
    // exit 0 on ANY transcript (even empty — the engine decides); 2 = crash (§13)
    match out.status.code() {
        Some(0) => Ok(text),
        Some(_) => Err(anyhow::anyhow!("transcribe shim exit {}", out.status.code().unwrap_or(-1))),
        None => Err(anyhow::anyhow!("transcribe shim killed by signal")),
    }
}

/// The YOLO/CLIP classify shim: base64 JPEG + target labels → {"indices":[…]} on success,
/// {"skipped":"deps_missing"} when the optional vision deps are absent (exit 0 — the engine
/// re-rolls without consuming an attempt), crash → Err.
pub fn classify(img_bytes: &[u8], targets: &[String], _grid: usize) -> Result<ClassifyOut> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(img_bytes);
    let exe = resolve_python();
    let out = Command::new(&exe)
        .args([
            "solve_service.py",
            "classify",
            "--img-b64",
            &b64,
            "--targets",
            &targets.join(","),
        ])
        .current_dir(project_root()?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("spawn {exe} solve_service.py classify"))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let j: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("classify shim stdout is not JSON: {text:?}"))?;
    if j.get("skipped").and_then(|v| v.as_str()) == Some("deps_missing") {
        return Ok(ClassifyOut::Skipped);
    }
    let indices = j
        .get("indices")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect::<Vec<_>>())
        .unwrap_or_default();
    Ok(ClassifyOut::Indices(indices))
}

#[derive(Debug)]
pub enum ClassifyOut {
    Indices(Vec<i64>),
    Skipped,
}

impl ClassifyOut {
    pub fn is_deps_missing(&self) -> bool {
        matches!(self, ClassifyOut::Skipped)
    }
}

/// The rc_jsdom/ project root — the shim MUST run there (its argparse expects its own file
/// and the whisper models cache beside it). Resolution: cwd that holds solve_service.py
/// first, then ANY ancestor of the exe holding solve_service.py — a standalone exe shipped
/// at a repo root resolves to that root, no fixed depth assumed.
fn project_root() -> Result<&'static Path> {
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("solve_service.py").exists() {
            return Ok(Box::leak(cwd.into_boxed_path()));
        }
    }
    let exe = std::env::current_exe().context("locate the binary")?;
    for anc in exe.ancestors() {
        if anc.join("solve_service.py").exists() {
            return Ok(Box::leak(anc.to_path_buf().into_boxed_path()));
        }
    }
    Err(anyhow::anyhow!(
        "cannot resolve the root holding solve_service.py from {exe:?}"
    ))
}
