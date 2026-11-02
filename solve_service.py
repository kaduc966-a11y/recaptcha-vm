#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve_service.py — rc_jsdom's complete Python solver. One file, three faces sharing one
whisper engine (rc_jsdom/DESIGN.md §13). Post-pivot the SHIM is the engine-facing role
(window-vm §9.2 shim.rs calls it over subprocess); Face A/B carry over from the built
implementation — Face A is the DOCUMENTED FALLBACK chain rc_solve.js uses when the Rust
binary is absent or fails its --selftest gate (§15):

Shim — what the Rust engine (window-vm §9.2 shim.rs) calls over subprocess (§13):
    python solve_service.py transcribe --file <mp3>              → cleaned transcript, 1 line
    python solve_service.py transcribe --audio-b64 <b64|->       ('-' reads stdin)
    python solve_service.py classify --img-b64 <b64> --targets "bus,traffic light" [--grid 3]
                                                                 → {"indices":[…],"instruction":"…"}
  One line on stdout, all logs on stderr; exit 0 = usable result (even empty / deps-missing
  {"skipped":"deps_missing"}), exit 2 = crash. Never touches the network.

Face A — the solver (the fallback chain rc_solve.js spawns when the Rust engine is absent):
    python solve_service.py --url <page> --sitekey <key> [--model tiny.en] [--rounds 4]
                            [--audio-retries 4] [--solve-image] [--window auto|rust|node|off]
                            [--window-profile chrome-win] [--mode link4m --alias <a> --code <c>]
                            [--fresh-session <path>] [--window-file <window.json>]
  Replays the ENTIRE Google API chain over curl_cffi, directly, legitimately, on the
  user's own IP — anchor → reload (protobuf body rebuilt from the captured constants with
  the UTF-8→latin-1 round-trip) → payload MP3 → faster-whisper transcription → userverify
  (audio branch, §9.6) or the YOLO/CLIP cascade (image branch, §9.7) — with cookie warm-up,
  jittered human pacing and the doscaptcha wait-and-retry loop built in (§8). It prints the
  final `g-recaptcha-response` token to STDOUT as a single line; ALL logs and progress go
  to STDERR (including `RC_STEP ` progress events, §5.4). Exit codes: 0 = token printed;
  1 = controlled failure; 2 = crash. In --mode link4m Face A additionally POSTs
  check-captcha after minting the token (§15.2) and reports the response on stderr.
  --window-file consumes a WINDOW_JSON (§14.2) written by either producer
  (window-vm emit-window / node rc_solve.js --emit-window) instead of spawning a runner.

Face B — the audio API (kept from the previous implementation, unchanged contract):
    python solve_service.py --serve --port 5092        → POST /transcribe {"audio_b64": …}
    python solve_service.py --file x.mp3               → one-shot transcript on stdout
    python solve_service.py --selftest                 → offline loopback check

Face A never imports, execs or parses recaptcha/api.py — the captured reload body literal
is embedded below as a REDACTED module constant and the UTF-8→latin-1 restoration is a
pure string transform (DESIGN §9.4 / rule 3 bug 1: the module-level stray POST of api.py:41
dies by construction). Redactions (rule 2): the stale 03AF… anchor validation token (f2)
→ '0'*1892, the link4m sitekey (f14) → the PUBLIC demo key (same length), the prior-captcha
token (f21) → 'A'*116. f1/f5/f6/f16/f20/f25 ship as captured. All three redacted slots are
re-spliced structurally (varint-correct field walker) per solve.

There is NO proxy plumbing anywhere in this file (§0): the chain session connects directly
on the user's own IP.
"""

import argparse
import base64
import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_MODEL = "tiny.en"

# ── Face B: transcriber indirection — --selftest stubs this WITHOUT loading the model ──
_transcriber = None  # bound to transcribe_mp3 below, after its definition

# ══════════════════════════════════════════════════════════════════════════════════════
# whisper singleton (audio_solve.py:47-60, verbatim logic) — shared by BOTH faces
# ══════════════════════════════════════════════════════════════════════════════════════
_WHISPER = None


def _log(*a):
    """Everything that is not the token goes to stderr (Face A stdout contract, §5.4)."""
    print(*a, file=sys.stderr, flush=True)


def get_whisper(model_size="tiny.en"):
    """Load faster-whisper model (cached). tiny.en is ~40MB, small.en is ~250MB."""
    global _WHISPER
    if _WHISPER is not None:
        return _WHISPER
    from faster_whisper import WhisperModel
    # bundle-first: models/faster-whisper-<size>/ next to this file wins over the hub name
    local = Path(__file__).resolve().parent / "models" / f"faster-whisper-{model_size}"
    if (local / "model.bin").is_file():
        src = str(local)
        _log(f"[whisper] loading model={model_size} from {src} ...")
    else:
        src = model_size
        _log(f"[whisper] loading model={model_size} (first time will download ~40-250MB)...")
    t0 = time.time()
    # CPU-only, int8 for speed on modest hardware (audio_solve.py:58)
    _WHISPER = WhisperModel(src, device="cpu", compute_type="int8")
    _log(f"[whisper] loaded in {time.time()-t0:.1f}s")
    return _WHISPER


# ── cleaning (audio_solve.py:80-96, verbatim) ─────────────────────────────────────────
PREAMBLE_PHRASES = [
    "please listen carefully to the following words",
    "please listen carefully to the following",
    "please listen carefully",
    "listen carefully and type what you hear",
    "type what you hear",
    "please type",
    "if the audio does not play",
    "make sure your volume is turned up",
]


def clean_transcript(raw):
    """Clean: lowercase, strip the 8 preamble phrases, strip punctuation, collapse whitespace."""
    cleaned = raw.lower()
    for phrase in PREAMBLE_PHRASES:
        cleaned = cleaned.replace(phrase, " ")
    # remove punctuation except digits/letters/spaces (audio_solve.py:94)
    cleaned = re.sub(r"[^a-z0-9\s]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()   # audio_solve.py:95
    return cleaned


def transcribe_mp3(mp3_path, model_size="tiny.en"):
    """Transcribe MP3 file to string. Returns cleaned lowercase text (audio_solve.py:63-97)."""
    model = get_whisper(model_size)
    # reCAPTCHA audio contains a preamble like "Please listen carefully..." then a short
    # list of digits/words. beam_size=5 gives good accuracy; VAD off (intentional pauses).
    segments, info = model.transcribe(
        str(mp3_path),
        language="en",        # verbatim: the proven path hardcodes English (audio_solve.py:70)
        beam_size=5,
        vad_filter=False,
        temperature=0.0,
    )
    text_parts = []
    for seg in segments:
        text_parts.append(seg.text)
    raw = " ".join(text_parts).strip()   # audio_solve.py:75-78
    _log(f"[whisper] raw: {raw!r}")
    cleaned = clean_transcript(raw)
    _log(f"[whisper] cleaned: {cleaned!r}")
    return cleaned


_transcriber = transcribe_mp3


# ══════════════════════════════════════════════════════════════════════════════════════
# Face A — the full audio chain over curl_cffi (DESIGN §7)
# ══════════════════════════════════════════════════════════════════════════════════════

# ── pinned constants (§9.2, all documented breakage points) ───────────────────────────
VER = "xg_pWYS8-HRESiV6Rdg4aY_R"                    # e2e.py:14 — version rotation breaks it
X_BROWSER_VALIDATION = "rvacWodMMC8CsnYVvG35HCYGtZY="   # api.py:29 / e2e.py:99 — no derivation code exists
CH = "2801408"                                       # api2.py:45 / e2e.py:481 — static literal
OC = "0Il3sfQw"                                      # api2.py:46 / e2e.py:481 — static literal
PM = ("51bGwsbnVsbCxbbnVsbCxudWxsLG51bGwsWzcsNS41NDI4NTcxNDQ1NjAxMzI1LDAuMDA3MzYxMTcxNzE4NzAwMTE1LDE2XSxbMCxudWxsLDBdLDEsMCwxXV0")  # api2.py:47 — head-truncated capture
S_INNER = "4cd7"                                     # api2.py:42 — userverify response inner "s"
E_INNER = "bXVs"                                     # api2.py:42 — userverify response inner "e"
DEMO_SITEKEY = "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-"   # the ONLY sitekey hardcoded in rc_jsdom/ (§0)

# the full Chrome/120 UA — audio_solve.py:107, the proven MP3-download UA (§9.1); chosen
# over e2e.py:99's truncated UA and api.py:26's Chrome/151 for coherence with impersonate
UA_FULL = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

CHAIN_IMP = "chrome120"     # e2e.py:42,101,484 — the proven pair with the chain constants
IMAGE_TYPES = ("imageselect", "tileselect", "dynamic", "multicaptcha")

# ── the captured reload body, REDACTED (§9.4 / rule 2) ────────────────────────────────
# The api.py:39 literal with: f2 (stale 03AF… anchor validation token, 1892 chars) → '0'*1892;
# f14 (link4m sitekey, 40 chars) → the PUBLIC demo key (same length); f21 (prior-captcha
# token 0aALJP…, 116 chars) → 'A'*116. f1/f5/f6/f16/f20/f25 ship as captured. 8336 chars,
# round-trips to 8336 bytes. Per-solve surgery is structural (varint field walker below).
RELOAD_BODY_TEMPLATE = '\n\x18xg_pWYS8-HRESiV6Rdg4aY_R\x12ä\x0e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*\n13821908552\x02fir(6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-\x82\x01\x8c,0dOonWHmjjfkqS3Vfy_wdRzGdzu8ZAyOPjeML9SlagacTRGWPeeUWN2FLt-gJMx2JutsF71uMrdfBLV5_qZP_MFF7ZdECI003o9T1Hwl1psfx2zQlp4nEHB1YWcvfC0BenJzD1D5cVZ672B48aXfl3C1Xk26_D_FZSI232t9EPW2RsQY6eaG7vgtHa4emAQoOX5m9-uoUI1fD9BU_KZXG5xH7Z5i54805aou1nws8XYdx3Q4vWUOv4AErFYGy0_3nQDGbygEJW2Oct-MUSjSHtf_iEFVxp8MAKFdfocETQ3V9kOjoN0p3xMnSGkOEaZ3O_CROb6PQ9EhBmov1IBmLsLPj8QU5apbA6As_bI_k3TYnkbHXHydxpa-zAQpWXKC8x_ssW4CvzQEuUqaf-OlTdKyRxfQjSnSXy_gacGnCsx04eZ2q8fkif4a0z_QvPmq6p9sMO12JreENOIZ_2MkzVXqwyxwzLouYv_YjQF98p_7-M4i05eA6OmJw2u3vLUKf0OPsJVJ81dz5D2qXqtADPkqFzNn1TjGNm8cZHmWSxfIPGm5tgOTyOEhUfOr3M2tLnbkSG15YuM7ZAjF3pa0LHC1Ubc7ABRRYmKXSGEhYoKPz5E9Mmsu0ERZGW5rR-TtInKTbBEdmZm2h0P4sVXOn0_1MRZ6P-QwxTWGVxu8eRGebx_FAOZKD7QhMOnmh-xxMcISfxho5T2R3q9oJMFh9sd0GVk-omQNBbph2weP5I5SmsQEEJoKCtAYNM2yQzgYiJjFllsHqGTdrl78QCWJTvenhUlpwmKPXBjRii6ndCTGCe9TFL0Nyg5fL-ilPfJ3R_SR2b8i5I15mYZXE8xpHZ5vH7UA5koPt_VYrX4695BIxZZG2CgNcTbfZEPUpWomr1_svW4DUzSYXgZbGAP9GhbDB2hhAanibxyw9gIW61vRQMWWUxu8RRGeYvOoUM2eUvQwFXk-51d5NeWuG6g0VSJ3Bx_0wY26Ov-ILSpKe0vIXWmu8ov0SHmewtdQtIFqFyPsEFFacuLsZOVWt0NnTBzhnibXZDTlfsqsXSGmTfdbHMTxlu830D1iBkMHqDEhitOi77x5Pc5_B9SJImpPs3UdpioW56hk7Z4u_6w9kXbanET5LkInS3EpTi83P-xNPf8Tc9jwnb5DlB_42gZXKEgZCTXWz_CpdVq3IBvE9iKizvxI6b7C40wdNUoGp2v4vV5nM8xYMTnK5zw0aaaCnr-lDJnqn5tkSVkyt3xExN2epovPwXZC1ovfyHEuErdQIJkOz3NYGSF-dzM_0M1uWnKfbCzNfi7ndDTNghqngCjSCe9TFLz-YbaHS-idRc6fT9kxFseIDLRdwYcvUJhd1hLDk6gU5aJfE6Rc8Z4-64gc-aIvg2TIjjbjV_ydGm570_hVghce40TA6Up_r9hkqkKnd6jw6XI7f5SlMhKLOBDQZYaGW1uc2dZrM-uQ1XajC2hwvdXme1xY_TKK7yvs2M2yV6g0iLIjC19QjTGmKtd4MaGK40N_6XTdrocXzHklvncjtD0ZwkujhOiuVlPorIE6AyKXZCDJfhbbgDDFYh6feACyAedLDLUJleZXJ-ClTfpvP_CF0bca3ITGKX5PC8RtEZZnG6T43kIHr-g9-g63fIvsvXo2y4gE1X4ja0ywdh7K8Gh1DmITX9CE5b5Xr7ShSX7rj2SpijYvRzPM_VYSn8-woVoOj_igoc5fV3-QcfYea4uIbNG2HzRVLX3-W7_cgZVOv4_L4PnSc2gYeNGR3u-n8ZG5y4gsBUWVwr9UANVCRre_4NVCYtNz8J3-GpbLzOGuTmsfjHkuijPUKFU1YkNH9RSRnfb7sI0WBn7nhKERhndDvE2N3i5oCLz5CdJLTIjmFg6S_BCo8arzq9wtOeMnYIDpHosHWEkdvcMHRBiYsfMbfDyRkg7C5zyshZ3nGzB1Ve7ii9AxAYKC-wjNOZ3297xARRJmMzypGX4fQzAZReHTD1PVNYnyo4fMXNIe4wv0zRY3CuOg1a1-zx9TyVXCQ2f0qUohsrdgNS3pvudsBSFSO2QMsK058ydLiTFubvcUUOjF2nOMfOnBUpPMIHyxXlMPjQjdosr3PDzp0uMAAKjRvhOIEIipttbjjLi5mbcsE-DOBacX15EBKdbX8_Uhqo5v3EkdOcKDGEyVAdZjg2DldjJTh4zVmlYjFA_c7X3vi7wQ1dpex9zVQVZSs8yUUP6Cq5fgod3itygQhb1yq3PYvSXG41iIfMnGiwBc1ZWi_uwgEV2i4ze8TIpKdwAUJU3u6wAEBV0eNy_oHNFijqQUaR0SswtH6Jm2Qw-cHElp0o-ojJGKBvsT_NzNvs-DcH1uYf-HqQCpSkN7gODJqZZnI9x5Ia6LMGhNsXcfcDjRbmrLjCUNKVYm66Qs3W4-73jQthnfhAShLoLTA3SY9doW5AiAtVI24EBQ-TZLp3S4hYG6z3gosRqDh8P4ZUH2k9DAzW52h1PZEUmei0_0dSF7M0ts7M4Or4OwWYJWbzQgBO2224dIMaI2J1eIbZVqH4QUIHImDvMP2GGOz3ff6FVuxxPL3VUqa1bfyIElnsNIgKU2cos4AGjSYo88bQjxqhOf1ECluisMQ_UWJqKPS9TJOjKzjAj16pLX0JlCFi6rBLC54ocn4BCZXfcjx8yxqmcO1IgZndbqf0wIxV4el2QUnfnfQwSs_co--EhlJf6TbDBRDjZSg3SBWM2ebyO8bPmmYwOEYQmW6swz9Z3iP0M8DMmGItdUJNGCupwDxW4Wv5xQabnN6wQMhSX6Iowc1ToZ3ruYmX2WJnPsvRIOvrAQkE2-FubwVSnOhtcwnQHmai-oNLHOYuM7J_Sxch63PAy5aqKH661Vmu7oSEWJOm8MQ9V53jJ7VDjpFsNAIME5bfKn_-VhdiLXKBE9bYp_FF0R4YL_02fUpWIez1fsvWoXUzSYXgbym6DFqkqnfBA9gfrbk-ilhWrDN6wMwgYKr7AU6e3ah2uUNbme8vPAoWKCIuuJFb1-iwewaRmecy_MSZXB75A1AYW-wxRMXP2KQvQsPNYiKwgUDNWRw39MARmCprN8oT12IofsBIVJ6j9TzTHmOx-8YSkKOpKgUQ1uOtbzWBFlljNzhOzJyet_PDVxZj83iLVhEcdHzIFF_i5sBHlc9gZG9FCQ9nsvm-zxIgnmt3AwxYn-z3ghYUaqbBRtueqLp5BomcpTr6Qc8j4656QowhIPB1xRaSbS-8yAFOWiWwe4LP2qT5N0OOmOJrwj5Y37B9_IXMF-b3Nc2bHeFp-btIVB_ps_zJ1J7zMUeD1qOvwErQ2pynN8lKj-b0L4kLj2cnKvfDjxljbjfDDdljK3kDjGGf9jJM0l2oKvwHkZqmrgSQztvqLrhPzCTidMCEjaPmZ_bNDiDfqnmDyh0WY286w89X5O-5TgxinvlGRg2obzEARtLoJu_HxJlhp-9DBc3dsDAF0FKS4yxxhg5bXqbt-saSXCbvfEcQpaP6NlDTnjPyxdIc5u17h5RRnSHxQNDQWqX0PUncmeyrf1ERVqXy-w9Noa-ofM_Z0-S0AsyQVh4zN4VTkKVvfrpGHuuuu4cR4F7odwULFlzuNElDFNzrMDdKzSAqd4TMzKYkOL5L2NzuaXOIFpsv7QJBEWCesX8EhtUjsEEBzRgbrDTIztXqZDV_yVpc7LW_EpYcojl7CxVgZrp_yBNnpit5CRwU4-uCitKlnui6QsyeJGk-_cNQXChxfMTSnTCuxQFb4q3uwBBb3XQ-Ak_aJLG-vUZV3iN1_wdXlmkxRoTUY5vo9QCJld1qdMATkegkfsuNHC0xcckGmquuAsKOW5msuElGE6P2P_6LXKLquooPUqBrvbzKUCcvsHs8ydYha7X-S1XgtLLJE54ab8KOSxagq8JIll5YZW19iAzmJHq2yp8psj3Gv9Mm8_2HkAnW3u04ggjiIHayxZlmcDoDkRmRXmZ0gAmQabQyfcdPZzYBydcjrSN8utEbqvc_ScRQGWTudkzQGu21BpEYWKR2RVRWqSK1vA9WZSG1hQUTYac7gkga3rFpuwPbGJ-yRMnIZN4zvo1YYmktw3wIFmUqwT9Dl2k1-0jNz2jpvYBUl55p9YTJ212h9kVN15fqr0YNkd3k-b1ASCXfb4CPCZPeeDkCSGPjcLXBV1dhNTy7Up0orfOASlZiqfcHVdqqqnHFTNNkqDL7CZYWausGkRyYoybAPlllrfhyzdoibOd9jNkha-ZyO0bQWHBBCFhhWy7-NtAOaXW9yELd6jJ891JepvFrwhFdpfBq9n_LVNz5O8haIW13O9FQ5K9lfrzX5Cx28UxYoOtl_AtXn-pk8HnFTtbmQcET4JqlP8YTEqkyOvjO1Bcp_rgTWFsv8j8RkRayL7xD1B7ua4NG1lIwOu9Iht0seIDLRdFa5u_30xCldPRCiRGgdQAKhRUZJS66VNOeZ3p5AZ7eK72GTxyir_d_Uc9iqbB8R9vdL6o7RZgjoKR9u9IhbbXAesZP22Ts-tMdWnFAAVCeYi54Qcsc6ec7Rg-fZ-C0_8XYKB-5OQOHYJ71BFCY413pcv5Hz-QogMLZmOk3wYiL2uxzcPvT2J4orEWD2il1vchCzlfjbPTTFun09EnL21dzMMNCF6YytXrM3J5f7gRFkNOlqrVPVSNpsX6GDRIg8LoBFNFsKsDMjNWmtDj-Bpkn5Te-i9pedDq-gt9n4es_hY4bnXa0yxpmrvlz_0jUXeXCxtNaYzT9BldjonaA_VTdrKZ9DEaZZyrsRYPaKXW9yELOV-Ns9NCfYm90RJRZVaiuBYFcZSi0BD_a4vEtN7tUkuk4RIzXUd1m8rvD1CNxe0jMouKusH9W1ZklrgfGXJ6ldLjTGxhz8cTQlB4jtH-DmV5o-sOAjCMk_DTF1FiiLLBJh94teYHMRtJb57D4zqOh9bZChlbbZkIEkVkeMbOIUZMhNLPG0Z0fsLr9z9rgb3I7Cdzjp-rGSZCiL7KDPsgaHTrBAQuPaKbBzhZg23ZCitVP6vc_ScRaqfY-SMNO2GPtdVGW6Giy_AQTaDNzSQAN4-f4_8oX32Rq9ZHUZiIl_z1Tou83QfxH0VzmbkXGoCVnb7-PkqGs74lKXWQzOMgSUuFsenhQntfyM4EJlmOufXLMCmCv_AROyVTeafN7SZosrTNM2aFj8XKEyNHkMDKFhxghcn3CVNQdqCvFA1mo9T1Hwk3XYux0UZ6f6TT_B15baL10ktIipLb7EVsTHvGzhIedZ6g_TwsO6CZ8i9ggauVzOkXPV2Q9iBWUGbI3-0SNHXO4AdJW4KkvPUqa4LGzPxDSpe65vsUU4yUw-4fPZLC2xITQ2-wxhEZQm-lv80DS4lt2fruTmSIlPzpTVqYyu8kEHyIxrcRLFN2xO0bH1F6yr7bBC9tnfLbAFqMrdjQAUpVtOXfPGNRjNje9FKLqZr0JF6Ha6gGKjBChaTTFyhxp5-48w5bkrDK5U4-aHfcBv9rnL3n0SobZrHOET9OUpLr6hszhKe33_hPaH6ot-scSG6YyfAVSGWcxuk-N6PU9R8JdabH8ds0JY_E6_IieG-34f0dQZWxzeokRZOu7Q4fSE2Y0uE3Y4OcoO74Mkyn1NjfE0RtlsjlGUNtvug¢\x01µ\x04tbMyw1MjMsMjA5XSxbMSw0NDMsOTA4XV0sW1syLDUxLDg1Ni4yOTk5OTk5ODIxMTg2XV0sW251bGwsbnVsbCxudWxsLFsxMiw1LjM5MTY2NjY2ODE1Njc4MywwLjAzMzQzNjY5MjUxNTcwMDk4LDE2XSxbMzAsMC4yODAwMDAwMDExOTIwOTI5LDAuMDA0MzQxMDg1Mjg5Nzk5ODg5NiwyXSwwLDAsMF0sWyJsaW5rNG0uY29tIiwibmV0LnlvYWRzLm5ldCIsInd3dy5nb29nbGUuY29tIiwic3RhdGljLmNsb3VkZmxhcmVpbnNpZ2h0cy5jb20iLCJ3d3cuZ29vZ2xldGFnbWFuYWdlci5jb20iLCJmb250cy5nb29nbGVhcGlzLmNvbSIsImFqYXguZ29vZ2xlYXBpcy5jb20iLCJjb25uZWN0LmZhY2Vib29rLm5ldCIsIjEuMS4xLjEiLCJ3d3cuZ29vZ2xlLWFuYWx5dGljcy5jb20iLCJ3d3cuZ3N0YXRpYy5jb20iLCJzMS5saW5rNG0uYXBwIl0sWzEsNjI4XV0ª\x01tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAÊ\x01\x12W1tbNTAwNiwxNF1dXQ'

# import-time, ONCE (§9.4): exactly e2e.py:87's restoration (raw.decode('utf-8').encode('latin1'))
# on the .encode()d module constant — minus the importlib-exec that fires api.py:41's stray POST.
_reloaded = RELOAD_BODY_TEMPLATE.encode("utf-8").decode("utf-8").encode("latin-1")


def _varint(n):
    """protobuf varint encoder — e2e.py:29-36 verbatim."""
    o = b""
    while True:
        b = n & 0x7F
        n >>= 7
        o += bytes([b | 0x80]) if n else bytes([b])
        if not n:
            break
    return o


def _read_varint(buf, i):
    """Inverse of _varint: decode one varint at buf[i:], return (value, next_i)."""
    o = 0
    shift = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        c = buf[i]
        i += 1
        o |= (c & 0x7F) << shift
        if not (c & 0x80):
            return o, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _walk_fields(body):
    """Walk a flat protobuf message of length-delimited fields → [(field_no, value_bytes)].
    Parses to EOF or raises — the walker validated in DESIGN §1 check 2."""
    out = []
    i = 0
    while i < len(body):
        tag, i = _read_varint(buf=body, i=i)
        fn, wt = tag >> 3, tag & 7
        if wt != 2:
            raise ValueError(f"field {fn}: unsupported wire type {wt}")
        ln, i = _read_varint(buf=body, i=i)
        if i + ln > len(body):
            raise ValueError(f"field {fn}: truncated value")
        out.append((fn, body[i:i + ln]))
        i += ln
    if i != len(body):
        raise ValueError("trailing bytes")
    return out


def rebuild_reload_body(anchor_token, sitekey, mode="a", prior_token=None,
                        fingerprint_hash=None, fingerprint_encrypted=None,
                        base_body=None):
    """Structural surgery on the restored captured body (§9.4):
      f2 (tag 0x12) ← fresh anchor token;
      f14 (tag 0x72) ← target sitekey;
      f6  (tag 0x32) ← challenge mode 'a' (audio; the capture carries 'fi', the V2 image mode);
      f21 (tag 0xAA 0x01) stays blanked unless prior_token (RC_PRIOR_TOKEN) refills it (§9.4 item 4);
      f5 (tag 0x2A) ← fingerprint_hash and f16 (tag 0x82 0x01) ← fingerprint_encrypted — the
        window upgrade of §13.3, applied ONLY as a pair (f5 is the hash of the f16 plaintext,
        recaptcha-main/README.md:1276/:1281 — never upgrade one without the other; a null or
        garbled ciphertext keeps the captured f5+f16 pair).
    Emits tag + varint(len) + value for every field — varint-correct, not regex-over-values.
    base_body: the surgery base — the REAL browser reload body from _fresh_session.json
    (§8.2c) when available, else the August captured template (_reloaded)."""
    fields = _walk_fields(base_body if base_body else _reloaded)
    repl = {
        2: anchor_token.encode() if isinstance(anchor_token, str) else anchor_token,
        14: sitekey.encode() if isinstance(sitekey, str) else sitekey,
        6: mode.encode() if isinstance(mode, str) else mode,
    }
    if prior_token:
        repl[21] = prior_token.encode() if isinstance(prior_token, str) else prior_token
    # §13.3 window upgrade — BOTH or NEITHER (a fresh hash over a stale ciphertext would be
    # a mismatched pair; the encrypted slot must decode to real bytes).
    if fingerprint_hash is not None and fingerprint_encrypted:
        try:
            fe_bytes = base64.b64decode(fingerprint_encrypted)
            if fe_bytes:
                repl[5] = str(int(fingerprint_hash)).encode()   # captured f5 is a decimal-string hash
                repl[16] = fe_bytes
        except Exception as exc:
            _log(f"[window] f5/f16 upgrade refused — falling back to the captured pair: {exc}")
    out = b""
    for fn, val in fields:
        v = repl.get(fn, val)
        out += _varint((fn << 3) | 2) + _varint(len(v)) + v
    return out


def derive_co(page_url):
    """anchor `co` = base64(origin).replace('=', '.') where origin is the FULL origin with
    the EXPLICIT default port (§9.3) — the capture carries https://www.google.com:443.
    The trailing '.' is a REPLACED pad character: an origin whose base64 needs two pads
    must end '..' (review finding)."""
    u = urllib.parse.urlparse(page_url)
    port = u.port or (443 if u.scheme == "https" else 80)
    origin = f"{u.scheme}://{u.hostname}:{port}"
    return base64.b64encode(origin.encode()).decode().replace("=", ".")


# ── rresp / uvresp parsing (e2e.py:105-152 / :487-508 ports) ──────────────────────────
def _strip_parens(text):
    t = text.strip()
    if t.startswith(")]}'"):
        t = t.split("\n", 1)[1] if "\n" in t else t[4:]
    return t


def parse_rresp(text):
    """Port of e2e.py:105-152: c (j[1]), payload token p (j[9], 06AF-prefixed with the
    regex fallback), chal_type (j[5]), tokenExpiration (j[3]), bftToken (j[15], used for
    the userverify referer, §9.6 step 3), plus the image-branch target extraction
    (§9.7): mids + the pmeta instruction label (e2e.py's pmeta-walk and the legacy
    multicaptcha j[4] layout, MID_LABEL-mapped at the call site)."""
    try:
        j = json.loads(_strip_parens(text))
    except Exception as e:
        return {"error": str(e), "raw": text[:800]}
    if not isinstance(j, list):
        return {"error": "rresp is not a list", "raw": text[:800]}
    c = j[1] if len(j) > 1 and isinstance(j[1], str) else None
    p = j[9] if len(j) > 9 and isinstance(j[9], str) and j[9].startswith("06AF") else None
    if not p:
        m = re.search(r"06AFcWeA[A-Za-z0-9_\-]{80,}", text)
        p = m.group(0) if m else None
    chal_type = j[5] if len(j) > 5 else None
    token_expiration = j[3] if len(j) > 3 and isinstance(j[3], int) else None
    bft = j[15] if len(j) > 15 and isinstance(j[15], str) else None
    # ── image targets (e2e.py:117-141 shape): pmeta anywhere in j, else the legacy layout ──
    mids = []
    label_from_pmeta = None
    pmeta = None
    for el in j:
        if isinstance(el, list) and el and el[0] == "pmeta":
            pmeta = el
            break
    if pmeta and len(pmeta) > 1 and isinstance(pmeta[1], list):
        inner = pmeta[1]
        if inner and isinstance(inner[0], str) and inner[0].startswith("/m/"):
            mids = [inner[0]]
            if len(inner) >= 7 and isinstance(inner[6], str):
                label_from_pmeta = inner[6]
    if not mids:
        mids_raw = j[4] if len(j) > 4 else None
        try:
            if isinstance(mids_raw, list) and len(mids_raw) >= 6 and isinstance(mids_raw[5], list):
                for tup in mids_raw[5]:
                    if isinstance(tup, list):
                        for sub in tup:
                            if isinstance(sub, list) and sub and isinstance(sub[0], str) and sub[0].startswith("/m/"):
                                mids.append(sub[0])
        except Exception:
            pass
    return {"c": c, "p": p, "chal_type": chal_type, "token_expiration": token_expiration,
            "bft": bft, "mids": mids, "label": label_from_pmeta, "raw_j": j}


_JS_INIT_RE = re.compile(r'recaptcha\.anchor\.Main\.init\("((?:[^"\\]|\\.)*)"\)', re.S)


def _js_unescape(s):
    """Decode a JS string literal body: \\xNN, \\uNNNN and the simple escapes. The live
    anchor embeds the ainput array as recaptcha.anchor.Main.init("[\\x22ainput\\x22,...]")
    — verified against a live capture (2026-11-01, runs/anchor_live.html): the naive
    '"ainput"' lookup never matches the escaped form."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x":
                out.append(chr(int(s[i + 2:i + 4], 16)))
                i += 4
                continue
            if n == "u":
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def extract_anchor_keys(anchor_html):
    """Best-effort anchor-key extraction (§9.3): the anchor HTML embeds the `ainput`
    array (recaptcha-main/README.md:202-291) as the argument of
    recaptcha.anchor.Main.init("...") — a JS string with \\x22 escapes. Index 18 is the
    fingerprint data-encryption key and index 31 the `oc` key (:275/:289); both are
    13-digit timestamp-like ints that change per anchor. VERIFIED against a live anchor
    (2026-11-01): arr[0]=='ainput', len 32, k18/k31 ints. Absent/garbled → (None, None),
    which degrades to encrypted:false, never to a corrupt request."""
    try:
        arr = None
        m = _JS_INIT_RE.search(anchor_html)
        if m:
            try:
                cand = json.loads(_js_unescape(m.group(1)))
                if isinstance(cand, list) and cand and cand[0] == "ainput":
                    arr = cand
            except Exception:
                arr = None
        if arr is None:
            # legacy path: an unescaped inline array (older widget versions)
            i = anchor_html.find('"ainput"')
            if i < 0:
                i = anchor_html.find("'ainput'")
            if i < 0:
                return None, None
            start = anchor_html.rfind("[", 0, i)   # the array whose element 0 IS "ainput"
            if start < 0:
                return None, None
            depth = 0
            for j in range(start, min(len(anchor_html), start + 200000)):
                ch = anchor_html[j]
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        cand = json.loads(anchor_html[start:j + 1])
                        if isinstance(cand, list) and cand and cand[0] == "ainput":
                            arr = cand
                        break
            if arr is None:
                return None, None
        k18 = arr[18] if len(arr) > 18 and isinstance(arr[18], int) else None
        k31 = arr[31] if len(arr) > 31 and isinstance(arr[31], int) else None
        return k18, k31
    except Exception:
        return None, None


def parse_uvresp(text):
    """Port of e2e.py:487-508: token at j[1]; an embedded rresp element = rejection /
    dynamic continuation; accept the g-token iff len(token) > 300 with no embedded rresp
    (e2e.py:506 threshold — the deliberate single choice, §9.6 step 3)."""
    try:
        j = json.loads(_strip_parens(text))
    except Exception:
        return {"token": None, "status": None, "dynamic_rresp": None, "error": "json", "raw_text": text[:1000]}
    token = j[1] if len(j) > 1 and isinstance(j[1], str) else None
    status = j[4] if len(j) > 4 else None
    dyn = None
    for el in j:
        if isinstance(el, list) and el and el[0] == "rresp":
            dyn = el
            break
    return {"token": token, "status": status, "dynamic_rresp": dyn, "raw_j": j}


def encode_userverify_response(answer):
    """Canonical inner JSON → base64 (§9.6 step 3). Audio: {"response": "<transcript>", "s","e"};
    image (§9.7 image branch): {"response": [<int indices>], "s","e"} —
    the JSON-array shape of recaptcha-main/README.md:1545/1587. The comma-joined string of
    e2e.py:477 is bug 2 and is NOT replicated."""
    if isinstance(answer, (list, tuple)):
        inner = {"response": [int(x) for x in answer], "s": S_INNER, "e": E_INNER}
    else:
        # AUDIO: the real widget's answer is the transcript alone. The captured
        # "s"/"e" values are image-capture dummies (api2.py:42 — the code itself
        # labels them dummy); a known-dummy field grades worse than an omitted one.
        inner = {"response": str(answer)}
    return base64.b64encode(json.dumps(inner, separators=(",", ":")).encode()).decode()


def looks_like_doscaptcha(body):
    """audio_solve.py:226-231's detector applied to bytes rather than a DOM (§8.4)."""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="ignore")
    return (b"rc-doscaptcha-header" in body
            or b"Your computer or network may be sending automated queries" in body)


def to_signed32(n):
    n &= 0xFFFFFFFF
    return n - 0x100000000 if n >= 0x80000000 else n


def hash_string(data, num_at=0):
    """The userverify `ch` (ocHash) derivation — port of recaptcha-main/hashOC.js:8-14:
    Java-style (31*hash + char) over the SERIALIZED VM-signal array, signed 32-bit.
    Cross-validated this session: `node recaptcha-main/hashOC.js` and this port both print
    574824847 on the file's published 1645-char sample input.
    HONEST LIMIT (recaptcha-main/README.md:1657-1659): ch = hashString(array) but
    oc = the SAME array encrypted with the reload-f16 algorithm keyed by the anchor's
    per-session key (anchor index 31) — that encryption and the 27-collector VM signal
    stack have NO implementation in this workspace, so a fresh (ch, oc) pair cannot be
    derived here; the chain ships the captured pair and this port is the verifiable half."""
    for c in data:
        num_at = to_signed32(((num_at << 5) - num_at + ord(c)) & 0xFFFFFFFF)
    return num_at


def _scrape_countdown(body):
    """Best-effort integer scrape if a blocked body carries a countdown (§8.4). The rresp
    itself does NOT carry it (DESIGN §1 check 3)."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    for pat in (r'data-countdown="(\d+)"', r'countdown["\']?\s*[:=]\s*(\d+)', r"\b(\d{1,4})\s*s(?:econd)?s?\b.*(?:retry|wait)"):
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass
    return None


# ══════════════════════════════════════════════════════════════════════════════════════
# the image cascade (§9.7) — copied from recaptcha/e2e.py (rule 1: no runtime import of
# recaptcha/), lazy-imported so an audio-only machine never pays for the vision deps.
# Faithful port of predict_yolo_trained (:316-374), predict_yolo (:197-246), predict_clip
# (:376-474) and predict_hybrid (:248-315), with two documented deviations:
#   1. NO auto pip-install (e2e.py:288-289/:424-434 auto-installed) — the deps are the
#      OPTIONAL requirements group (§19.4); missing deps → the caller emits
#      RC_STEP {"step":"image_solve","skipped":"deps_missing"} and re-rolls (§9.5/§9.8).
#   2. The trained-classifier model path stays INSIDE this folder (rule 1) — env
#      RC_YOLO_CLS_MODEL, default <rc_jsdom>/models/yolo_cls_best.pt; absent → that stage
#      is skipped. e2e referenced recaptcha/models/... which this folder must not read.
# Same 3×3 crop discipline as the proven path (e2e.py range(3) sites :226-229/:344-347/
# :430-433); a 4×4 payload is mis-cropped — known upstream limitation, stated in the README.
# ══════════════════════════════════════════════════════════════════════════════════════
MID_LABEL = {"/m/015qff": "traffic light", "/m/04_sv": "motorcycle", "/m/01bjv": "bus", "/m/0199g": "bicycle", "/m/01lynh": "fire hydrant", "/m/014xcs": "car", "/m/02kx1l": "bridge", "/m/0k4j": "chimney", "/m/02sgy": "palm tree", "/m/04h7h": "stairs", "/m/09g5v": "crosswalk", "/m/0k2k": "boat", "/m/015258": "car", "/m/01pns0": "fire hydrant"}  # e2e.py:25
COCO_YOLO = {"bicycle", "car", "motorcycle", "bus", "truck", "traffic light", "fire hydrant", "boat", "stop sign", "parking meter", "bench"}  # e2e.py:184

_YOLO_MODEL = None
_YOLO_NAMES = None
_YOLO_CLS_MODEL = None
_YOLO_CLS_NAMES = None


def image_deps_available():
    """True iff the primary cascade engine (ultralytics) is importable WITHOUT loading any
    model or weights (§9.5's deps gate — pure import check, offline-safe)."""
    try:
        import ultralytics  # noqa: F401
        return True
    except Exception:
        return False


def _ensure_yolo():
    """yolov8n detect — e2e.py:188-195 minus the auto-install (deviation 1)."""
    global _YOLO_MODEL, _YOLO_NAMES
    if _YOLO_MODEL is not None:
        return _YOLO_MODEL
    try:
        from ultralytics import YOLO
    except ImportError:
        return None
    try:
        m = YOLO("yolov8n.pt")
    except Exception:
        return None
    _YOLO_MODEL = m
    try:
        _YOLO_NAMES = m.names
    except Exception:
        _YOLO_NAMES = {}
    _log(f"[yolo] loaded yolov8n.pt names={list(_YOLO_NAMES.values())[:10] if isinstance(_YOLO_NAMES, dict) else _YOLO_NAMES}")
    return m


def _yolo_cls_model_path():
    return os.environ.get("RC_YOLO_CLS_MODEL", "") or str(Path(__file__).resolve().parent / "models" / "yolo_cls_best.pt")


def _ensure_yolo_cls(model_path=None):
    """trained classifier — e2e.py:280-297 minus the auto-install; model path stays inside
    rc_jsdom/ (deviation 2)."""
    global _YOLO_CLS_MODEL, _YOLO_CLS_NAMES
    if _YOLO_CLS_MODEL is not None:
        return _YOLO_CLS_MODEL
    try:
        from ultralytics import YOLO
    except ImportError:
        return None
    p = Path(model_path or _yolo_cls_model_path())
    if not p.exists():
        return None
    m = YOLO(str(p))
    _YOLO_CLS_MODEL = m
    try:
        _YOLO_CLS_NAMES = m.names
    except Exception:
        _YOLO_CLS_NAMES = {}
    _log(f"[yolo-cls] loaded {p} names={list(_YOLO_CLS_NAMES.values())[:8] if isinstance(_YOLO_CLS_NAMES, dict) else _YOLO_CLS_NAMES}")
    return m


def predict_yolo_trained(image_path, mids, model_path=None, conf=0.25):
    """e2e.py:316-374 — YOLO classification trained on 100x100 tiles. Returns selected
    indices where top1 == target class; None when the model is unavailable/applicable."""
    labels = [MID_LABEL.get(x, x) for x in mids]
    labels = list(dict.fromkeys(labels))
    if not labels:
        return []
    def _norm(s):
        return s.lower().replace("_", " ").strip()
    targets = set(_norm(l) for l in labels)
    m = _ensure_yolo_cls(model_path)
    if m is None:
        return None
    try:
        from PIL import Image
    except Exception:
        return None
    names = {_norm(v): k for k, v in _YOLO_CLS_NAMES.items()} if isinstance(_YOLO_CLS_NAMES, dict) else {}
    model_classes = set(names.keys())
    if not any(t in model_classes for t in targets) and "background" not in model_classes:
        _log(f"  [yolo-cls] targets {targets} not in model {model_classes} -> fallback")
        return None
    _log(f"  [yolo-cls] labels={labels} targets={targets} conf={conf}")
    im = Image.open(image_path).convert("RGB")
    w, h = im.size
    sel = []
    for r in range(3):
        for c in range(3):
            idx = r * 3 + c
            crop = im.crop((c * w // 3, r * h // 3, (c + 1) * w // 3, (r + 1) * h // 3))
            tmp = os.path.join(tempfile.gettempdir(), f"_rc_yolo_cls_{idx}.jpg")
            crop.save(tmp, "JPEG", quality=95)
            try:
                res = m.predict(tmp, verbose=False)
                probs = res[0].probs if res and len(res) > 0 else None
                if probs is None:
                    _log(f"   tile {idx} -> no probs")
                    continue
                top_id = int(probs.top1)
                top_conf = float(probs.top1conf.item()) if hasattr(probs.top1conf, "item") else float(probs.top1conf)
                top_name = _norm(_YOLO_CLS_NAMES.get(top_id, str(top_id))) if isinstance(_YOLO_CLS_NAMES, dict) else _norm(str(top_id))
                _log(f"   tile {idx} -> {top_name}@{top_conf:.2f} targets={targets}")
                if top_name in targets and top_conf >= conf:
                    sel.append(idx)
                elif top_name == "background":
                    pass
                elif top_name in targets:
                    sel.append(idx)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    _log(f"  [yolo-cls] selected={sel}")
    return sel


def predict_yolo(image_path, mids, conf=0.25, iou=0.45):
    """e2e.py:197-246 — YOLO per-tile detect. mids -> labels. Returns selected indices;
    None when the target ids cannot be resolved (the hybrid falls through to CLIP)."""
    labels = [MID_LABEL.get(x, x) for x in mids]
    labels = list(dict.fromkeys(labels))
    if not labels:
        return []
    yolo_labels = [l for l in labels if l.lower() in COCO_YOLO]
    if not yolo_labels:
        _log(f"  [yolo] labels {labels} not in COCO -> skip (no CLIP to avoid OOM), return []")
        return []
    try:
        from PIL import Image
    except Exception:
        return []
    m = _ensure_yolo()
    if m is None:
        return None
    names = {v.lower(): k for k, v in _YOLO_NAMES.items()} if isinstance(_YOLO_NAMES, dict) else {}
    target_ids = set()
    for lb in yolo_labels:
        for nm, idx in names.items():
            if nm == lb.lower():
                target_ids.add(idx)
    if not target_ids:
        _log(f"  [yolo] target ids not found for {yolo_labels}")
        return None
    _log(f"  [yolo] labels={yolo_labels} ids={target_ids} conf={conf}")
    im = Image.open(image_path).convert("RGB")
    w, h = im.size
    sel = []
    for r in range(3):
        for c in range(3):
            idx = r * 3 + c
            crop = im.crop((c * w // 3, r * h // 3, (c + 1) * w // 3, (r + 1) * h // 3))
            res = m.predict(crop, conf=conf, iou=iou, verbose=False)
            boxes = res[0].boxes if res and len(res) > 0 else None
            hit = False
            details = []
            if boxes is not None and len(boxes) > 0:
                for b in boxes:
                    cls = int(b.cls.item())
                    cf = float(b.conf.item())
                    nm = _YOLO_NAMES.get(cls, str(cls)).lower() if isinstance(_YOLO_NAMES, dict) else str(cls)
                    details.append(f"{nm}@{cf:.2f}")
                    if cls in target_ids and cf >= conf:
                        hit = True
            _log(f"   tile {idx} -> {'HIT' if hit else 'miss'} {details if details else '[]'}")
            if hit:
                sel.append(idx)
    _log(f"  [yolo] selected={sel} for {yolo_labels}")
    return sel


def predict_clip(image_path, mids):
    """e2e.py:376-474 — zero-shot CLIP per tile per mid. Returns selected indices 0..8;
    [] on any failure (never raises)."""
    labels = [MID_LABEL.get(x, x) for x in mids]
    labels = list(dict.fromkeys(labels))
    if not labels:
        _log("  [clip] qr/empty mids -> empty select (fallback)")
        return []
    try:
        import torch
        from PIL import Image
        import open_clip
        model, _, preprocess = open_clip.create_model_and_transforms('ViT-B-32', pretrained='openai')
        tokenizer = open_clip.get_tokenizer('ViT-B-32')
        model.eval()
    except Exception as e:
        _log(f"  [clip] not available ({e}) -> empty (no auto-install, §9.7 deviation 1)")
        return []
    try:
        from PIL import Image
        import torch
        im = Image.open(image_path).convert("RGB")
        w, h = im.size
        label_texts = []
        for lab in labels:
            pos_prompts = [f"a photo of a {lab}", f"a {lab}", f"a photo containing a {lab}"]
            neg_prompts = [f"a photo without {lab}", f"no {lab}", "background"]
            tp = tokenizer(pos_prompts)
            tn = tokenizer(neg_prompts)
            with torch.no_grad():
                efp = model.encode_text(tp)
                efp /= efp.norm(dim=-1, keepdim=True)
                efn = model.encode_text(tn)
                efn /= efn.norm(dim=-1, keepdim=True)
                tf_pos = efp.mean(dim=0)
                tf_pos /= tf_pos.norm()
                tf_neg = efn.mean(dim=0)
                tf_neg /= tf_neg.norm()
            label_texts.append((lab, tf_pos, tf_neg))
        sel = []
        deltas = []
        for r in range(3):
            for c_ in range(3):
                idx = r * 3 + c_
                crop = im.crop((c_ * w // 3, r * h // 3, (c_ + 1) * w // 3, (r + 1) * h // 3)).resize((224, 224))
                img_t = preprocess(crop).unsqueeze(0)
                with torch.no_grad():
                    f = model.encode_image(img_t)
                    f /= f.norm(dim=-1, keepdim=True)
                    best_delta = -1e9
                    best_lab = None
                    scores = []
                    is_sel = False
                    for lab, tf_pos, tf_neg in label_texts:
                        s_pos = (f @ tf_pos.unsqueeze(1)).item()
                        s_neg = (f @ tf_neg.unsqueeze(1)).item()
                        delta = s_pos - s_neg
                        scores.append((lab, s_pos, s_neg))
                        if delta > best_delta:
                            best_delta = delta
                            best_lab = lab
                        if s_pos > s_neg:
                            is_sel = True
                    deltas.append((idx, best_delta, best_lab, scores))
                    if is_sel:
                        sel.append(idx)
                        _log(f"   tile {idx} -> SELECT delta={best_delta:.3f} lab={best_lab}")
                    else:
                        _log(f"   tile {idx} -> skip delta={best_delta:.3f} lab={best_lab}")
        if not sel:
            deltas_sorted = sorted(deltas, key=lambda x: x[1], reverse=True)
            _log(f"  [clip] empty -> fallback top deltas {[(i, round(d, 3), lab) for i, d, lab, _ in deltas_sorted[:4]]}")
            for idx, delta, lab, _ in deltas_sorted[:2]:
                if delta > -0.05:
                    sel.append(idx)
            sel = sorted(sel)
            if sel:
                _log(f"  [clip] fallback selected {sel}")
        _log(f"  [clip] mids={labels} -> selected={sel}")
        return sel
    except Exception as e:
        _log(f"  [clip] predict error {e} -> []")
        return []


def predict_hybrid(image_path, mids):
    """e2e.py:248-315 — first-non-empty-wins cascade: trained classifier (skipped when
    'traffic light' is among the targets, :255-260 rationale) -> YOLO detect (conf .25,
    retry .15 when empty) -> CLIP zero-shot."""
    y_trained = None
    try:
        labels_tmp = [MID_LABEL.get(x, x) for x in mids]
        targets_tmp = set(l.lower() for l in labels_tmp)
        has_traffic = "traffic light" in targets_tmp or "traffic_light" in targets_tmp
        if has_traffic:
            _log("  [hybrid] traffic light in targets -> skip yolo-cls, use YOLO detect directly")
        else:
            y_trained = predict_yolo_trained(image_path, mids)
            if y_trained is not None and len(y_trained) > 0:
                _log(f"  [hybrid] using yolo-cls {y_trained}")
                return y_trained
            elif y_trained is not None:
                _log("  [hybrid] yolo-cls empty, trying YOLO detect ...")
    except Exception as e:
        _log(f"  [hybrid] trained check fail {e}")
    y = predict_yolo(image_path, mids)
    if y is not None:
        if len(y) == 0:
            y2 = predict_yolo(image_path, mids, conf=0.15)
            if y2 is not None and len(y2) > 0:
                _log(f"  [hybrid] YOLO retry 0.15 hit {y2}")
                return y2
        if len(y) > 0:
            _log(f"  [hybrid] using YOLO detect {y}")
            return y
        _log("  [hybrid] YOLO empty, trying CLIP ...")
    try:
        c = predict_clip(image_path, mids)
        _log(f"  [hybrid] fallback CLIP {c}")
        return c
    except OSError as e:
        _log(f"  [hybrid] CLIP OOM {e} -> return []")
        return []
    except Exception as e:
        _log(f"  [hybrid] CLIP fail {e} -> return []")
        return []


def clamp_tct_ms(elapsed_seconds):
    """t/ct in MILLISECONDS, clamped into the §8.3 pacing window (§9.6 step 3): both known
    wire samples read as ms — e2e.py:481's '3854' and recaptcha-main/README.md:1560-1561's
    t: 24521 / ct: 24521. The one live userverify this folder sent with SECONDS (t/ct=6,
    runs/1791295981328/solve.log) was rejected. Unit remains a hypothesis consistent with
    both samples (§18.1a) — this helper exists so the selftest can pin the clamp."""
    return str(int(min(15000, max(4000, elapsed_seconds * 1000))))


def rc_step(obj):
    """One JSON progress event per chain step on stderr, each on its own line prefixed
    'RC_STEP ' (§5.4) — rc_solve.js maps these 1:1 onto the RUN_REPORT fields."""
    try:
        sys.stderr.write("RC_STEP " + json.dumps(obj, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def pace(lo, hi):
    """Jittered human pacing (§8.3): time.sleep(random.uniform(lo, hi))."""
    time.sleep(random.uniform(lo, hi))


class AudioChain:
    """The whole Google API chain over one curl_cffi session — direct, no proxy (§0/§9.1)."""

    def __init__(self, url, sitekey, model="tiny.en", rounds=4, audio_retries=4,
                 fresh_session=None, prior_token=None, fresh_max_age=None, dos_retries=None,
                 solve_image=False, window_mode="auto", window_profile="chrome-win",
                 window_file=None):
        from curl_cffi.requests import Session   # lazy: Face B and --selftest stay stdlib-only
        self.page_url = url
        self.sitekey = sitekey or DEMO_SITEKEY
        self.model = model
        # §9.8: ONE knob — --rounds governs; --audio-retries is accepted for CLI parity and
        # logged as folded (it must not silently override an explicit --rounds).
        self.rounds = max(4, int(rounds))   # §9.6/§9.8: python floor-clamps --rounds to 4
        if int(audio_retries) != max(4, int(rounds)):
            _log(f"[config] --audio-retries={audio_retries} folded into the single round knob "
                 f"(§9.8): rounds={self.rounds}")
        self.solve_image = bool(solve_image)
        self.window_mode = str(window_mode or "auto").lower()
        self.window_profile = window_profile or "chrome-win"
        # §14.2: --window-file consumes a WINDOW_JSON from disk instead of spawning a runner
        self.window_file = window_file
        self.fresh_session = fresh_session
        self.prior_token = prior_token or os.environ.get("RC_PRIOR_TOKEN", "").strip() or None
        self.fresh_max_age = int(fresh_max_age if fresh_max_age is not None
                                 else os.environ.get("RC_FRESH_MAX_AGE", 86400))
        self.dos_retries = int(dos_retries if dos_retries is not None
                               else os.environ.get("RC_DOSCAPTCHA_RETRIES", 3))
        # §9.1: direct session — chrome120, the proven pair with the chain constants. NO proxy
        # parameter exists anywhere in this file (§0).
        self.sess = Session(impersonate=CHAIN_IMP, verify=False, timeout=30)
        self.challenge_acquired_at = None
        self.seed_reload = None       # parsed rresp from _fresh_session.json (§8.2, <90 s)
        self.seed_age = None
        self.last_tag = None          # exhaustion tag candidate
        # §13.3 window material (None = fallback to the captured constants, §13.4):
        self.window_emitted = False
        self.window_f5 = None         # fingerprint_hash (reload idx 5)
        self.window_f16 = None        # fingerprint_encrypted raw bytes (reload idx 16)
        self.window_ch = None         # userverify ch (else pinned CH)
        self.window_oc = None         # userverify oc — oc_encrypted only (§13.3: an
                                      # unencrypted plaintext oc has NO wire slot)
        self.window_runner = None     # "rust" | "node-vm" | None
        # §8.2c/d "verify đúng" (2026-11-02): the live release version, the REAL browser
        # reload body as the surgery base, and its real f20 telemetry as `pm`.
        self.ver = os.environ.get("RC_LIVE_VER") or VER
        self.fresh_reload_req = None
        self.fresh_pm = None

    def _jar_names(self):
        """Cookie-posture diagnostic (§9.3: the cookie variable is the first thing to
        diagnose) — the chain's actual jar names, no values."""
        try:
            return sorted({c.name for c in self.sess.cookies.jar})
        except Exception:
            try:
                return sorted({c.name for c in self.sess.cookies})
            except Exception:
                return ["<jar unreadable>"]

    # ── §8.1 cookie warm-up: first act of every run ───────────────────────────────────
    def warmup(self):
        _log("[warmup] GET https://www.google.com/ to seed cookies (audio_solve.py:545-566: "
             "skipping this triggers the 'automated queries' audio block nearly 100% of the time)")
        try:
            r = self.sess.get("https://www.google.com/", headers={
                "user-agent": UA_FULL,
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            })
            _log(f"[warmup] -> {r.status_code} | session jar now: {self._jar_names() or 'EMPTY'}")
        except Exception as exc:
            _log(f"[warmup] failed (continuing): {exc}")
        pace(1.0, 2.0)   # jittered settle (§8.1)

    # ── §8.2 _fresh_session.json seed (optional, read-only, never copied) ─────────────
    def load_seed(self):
        if self.fresh_session:
            p = Path(self.fresh_session)
        else:
            p = Path(__file__).resolve().parents[1] / "recaptcha" / "_fresh_session.json"
        if not p.exists():
            _log(f"[seed] {p} absent — cookie-less chain (unproven posture, DESIGN §9.3/§18.1e)")
            return
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            _log(f"[seed] parse fail: {exc}")
            return
        age = time.time() - d.get("ts", 0)
        self.seed_age = age
        gck = d.get("google_cookies") or {}
        if age > self.fresh_max_age:
            _log(f"[seed] stale (age={age:.0f}s > {self.fresh_max_age}s) — cookies NOT merged")
        elif gck:
            for name, val in gck.items():
                try:
                    self.sess.cookies.set(str(name), str(val), domain=".google.com")
                except Exception:
                    try:
                        self.sess.cookies.set(str(name), str(val))
                    except Exception:
                        pass
            _log(f"[seed] merged {len(gck)} google cookie(s): {sorted(gck)}")
        resp_b64 = d.get("reload_resp_body_b64")
        if resp_b64 and age < 90:   # e2e.py:47 max_age_sec=90 gate
            try:
                parsed = parse_rresp(base64.b64decode(resp_b64).decode("utf-8", errors="ignore"))
                if parsed.get("chal_type"):
                    self.seed_reload = parsed
                    _log(f"[seed] fresh reload reuse armed (age={age:.0f}s < 90s, chal_type={parsed.get('chal_type')})")
            except Exception as exc:
                _log(f"[seed] reload reuse unavailable: {exc}")

        # §8.2c/d "verify đúng" (2026-11-02): the REAL browser reload body from the fresh
        # capture becomes the surgery base (every field real — f5/f16 encrypted by the real
        # browser, f20/f25 real telemetry, f1 the current release), its f20 becomes the
        # userverify `pm`, and the referer's v= param becomes the live release version.
        req_b64 = d.get("reload_req_body_b64")
        if req_b64 and age < self.fresh_max_age:
            try:
                body = base64.b64decode(req_b64)
                fields = {}
                for fn, val in _walk_fields(body):
                    fields.setdefault(fn, val)
                self.fresh_reload_req = body
                pm_val = fields.get(20)
                if pm_val:
                    self.fresh_pm = pm_val.decode("ascii", errors="ignore")
                m = re.search(r"[?&]v=([A-Za-z0-9_-]{10,60})",
                              json.dumps(d.get("reload_req_headers") or {}))
                if m:
                    self.ver = m.group(1)
                _log(f"[seed] fresh body armed ({len(body)} B) — "
                     f"pm={'real f20' if self.fresh_pm else 'fallback'}, v={self.ver}")
            except Exception as exc:
                _log(f"[seed] fresh body unusable: {exc}")

    # ── §9.3 anchor ───────────────────────────────────────────────────────────────────
    def do_anchor(self):
        """Returns (anchor_token, k18, k31) — the keys are the §9.3 best-effort ainput
        extraction for the window mode; (None, None) keys degrade to encrypted:false."""
        cb = str(random.randint(10**12, 10**13))   # e2e.py:39
        co = derive_co(self.page_url)
        url = (f"https://www.google.com/recaptcha/api2/anchor?ar=1&k={self.sitekey}"
               f"&co={co}&hl=en&v={self.ver}&size=normal&cb={cb}")
        r = self.sess.get(url, headers={"user-agent": UA_FULL})
        m = re.search(r'id="recaptcha-token" value="([^"]+)"', r.text)   # e2e.py:44
        tok = m.group(1) if m else None
        k18, k31 = extract_anchor_keys(r.text)
        _log(f"[anchor] -> {r.status_code} len={len(r.content)} "
             f"token={'yes(len=%d)' % len(tok) if tok else 'NO'} "
             f"anchor_keys={'yes' if (k18 is not None or k31 is not None) else 'no (§18.10: unverified shape)'}")
        return tok, k18, k31

    # ── §13.2/§13.3 the window emit — once per run, after the first anchor ────────────
    def emit_window(self, anchor_keys):
        """Resolve the runner (§13.2), invoke it OFFLINE (§13.1 contract), and map ok:true
        onto the wire slots (§13.3). Any absence/failure/non-JSON → None → the chain runs
        verbatim as the pre-window design (§13.4 — a window failure never fails the run)."""
        mode = self.window_mode
        if mode == "off":
            return None
        folder = Path(__file__).resolve().parent
        runner = None          # ("rust", binary_path) | ("node", None)
        exe = "window-vm.exe" if os.name == "nt" else "window-vm"
        if mode in ("auto", "rust"):
            for sub in ("release", "debug"):
                p = folder / "window-vm" / "target" / sub / exe
                if p.exists():
                    runner = ("rust", str(p))
                    break
            if runner is None and mode == "rust":
                _log("[window] --window rust but no window-vm binary — fallback to constants (§13.4)")
                return None
        if runner is None and mode in ("auto", "node"):
            runner = ("node", None)
        if runner is None:
            return None

        kind, binpath = runner
        t0 = time.time()
        try:
            if kind == "rust":
                # §14.4 CLI contract (byte-identical emit JSON to the node runner, §14.2)
                profiles = folder / "window" / "profiles" / f"{self.window_profile}.json"
                answers = folder / "window" / "answers" / "fingerprint.json"
                vm_dir = folder / "window" / "assets" / "vm" / "script_1"
                args = [binpath, "--emit", "--url", self.page_url, "--sitekey", self.sitekey,
                        "--profile", str(profiles), "--answers", str(answers),
                        "--vm", str(vm_dir / "vm.js"), "--bc", str(vm_dir / "bc.txt"), "--json-only"]
                if anchor_keys and anchor_keys[0] is not None and anchor_keys[1] is not None:
                    args += ["--anchor-keys", f"{anchor_keys[0]},{anchor_keys[1]}"]
            else:
                node = os.environ.get("RC_NODE", "node")
                args = [node, "rc_solve.js", "--emit-window", "--url", self.page_url,
                        "--sitekey", self.sitekey, "--profile", self.window_profile]
                if anchor_keys and anchor_keys[0] is not None and anchor_keys[1] is not None:
                    args += ["--anchor-keys", f"{anchor_keys[0]},{anchor_keys[1]}"]
            _log(f"[window] emit via {kind}: {' '.join(args[:8])}… (60 s budget, §13.4)")
            proc = subprocess.run(args, cwd=str(folder), capture_output=True, text=True,
                                  timeout=60, encoding="utf-8", errors="replace")
            lines = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
            if proc.returncode != 0 or not lines:
                _log(f"[window] emit failed rc={proc.returncode} — fallback to constants (§13.4); "
                     f"stderr tail: {(proc.stderr or '')[-200:]}")
                return None
            out = json.loads(lines[-1])   # §13.1: the LAST stdout line is the emit JSON
            if not isinstance(out, dict) or "ok" not in out:
                _log("[window] emit output is not a contract object — fallback (§13.4)")
                return None
            self.window_runner = "rust" if kind == "rust" else "node-vm"
            _log(f"[window] emit ok:{out.get('ok')} runner={self.window_runner} "
                 f"encrypted={out.get('encrypted')} elapsed={time.time() - t0:.1f}s")
            return out
        except FileNotFoundError as exc:
            _log(f"[window] runner missing ({exc}) — fallback to constants (§13.4)")
            return None
        except subprocess.TimeoutExpired:
            _log("[window] emit timeout (60 s) — fallback to constants (§13.4)")
            return None
        except Exception as exc:
            _log(f"[window] emit error: {exc} — fallback to constants (§13.4)")
            return None

    def _load_window_file(self):
        """§14.2: --window-file <path> — read a WINDOW_JSON written by either producer
        (window-vm emit-window / node rc_solve.js --emit-window) and apply the same slot
        table via consume_window. A missing/invalid file never fails the run (§134-style:
        the chain proceeds with the captured constants, reported on the step stream)."""
        try:
            out = json.loads(Path(self.window_file).read_text(encoding="utf-8"))
        except Exception as exc:
            _log(f"[window] --window-file {self.window_file} unreadable ({exc}) — fallback to constants (§13.4)")
            return None
        if not isinstance(out, dict) or "ok" not in out:
            _log("[window] --window-file content is not a contract object — fallback to constants (§13.4)")
            return None
        self.window_runner = str(out.get("runner") or "file")
        _log(f"[window] loaded WINDOW_JSON from {self.window_file} (runner={out.get('runner')}, "
             f"ok={out.get('ok')})")
        return out

    def consume_window(self, out):
        """§13.3 slot mapping. Returns the `used` list for the RC_STEP window event."""
        used = []
        if not (out and out.get("ok")):
            return used
        fh = out.get("fingerprint_hash")
        fe = out.get("fingerprint_encrypted")
        if out.get("encrypted") and fe and fh is not None:
            try:
                if base64.b64decode(fe):
                    self.window_f5 = fh
                    self.window_f16 = fe
                    used += ["idx5", "idx16"]
            except Exception as exc:
                _log(f"[window] f16 not usable ({exc}) — captured pair stays")
        else:
            _log("[window] encrypted:false (reload-f16 encryptor absent, §13.1 caveat) — "
                 "the captured f5+f16 pair stays (never mix a fresh hash with a stale ciphertext)")
        if out.get("ch") is not None:
            try:
                self.window_ch = str(int(out["ch"]))
                used.append("ch")
            except Exception:
                pass
        if out.get("oc_encrypted"):
            self.window_oc = str(out["oc_encrypted"])   # the form field carries the b64 string
            used.append("oc")
        # bgdata has no wire slot yet (§13.1/§18.7) — reported in the event + saved to window.json
        dump_dir = os.environ.get("RC_DUMP_DIR")
        if dump_dir:
            try:
                (Path(dump_dir) / "window.json").write_text(
                    json.dumps(out, ensure_ascii=False)[:100000], encoding="utf-8")
            except Exception:
                pass
        rc_step({"step": "window", "ok": True, "runner": self.window_runner, "used": used,
                 "bgdata": bool(out.get("bgdata"))})
        _log(f"[window] wire slots upgraded: {used or 'NONE (constants stay)'}; bgdata "
             f"{'present (no wire slot, §18.7)' if out.get('bgdata') else 'absent'}")
        return used

    # ── §9.4 reload — protobuf body rebuilt from the captured constants ───────────────
    def do_reload(self, anchor_token, bft=None):
        body = rebuild_reload_body(anchor_token, self.sitekey, mode="a", prior_token=self.prior_token,
                                   fingerprint_hash=self.window_f5, fingerprint_encrypted=self.window_f16,
                                   base_body=self.fresh_reload_req)
        # Referer lever (recap step 3: "whether Google's scoring tolerates the missing bft
        # long-term" is untested): round 1 keeps the proven bft-less variant (§9.4); later
        # rounds carry the previous round's bftToken (rresp j[15]) as a real client would.
        referer = f"https://www.google.com/recaptcha/api2/bframe?hl=en&v={self.ver}&k={self.sitekey}"
        if bft:
            referer += f"&bft={bft}"
        headers = {
            "accept": "*/*",
            "content-type": "application/x-protobuffer",
            "origin": "https://www.google.com",
            "referer": referer,
            "user-agent": UA_FULL,
            "x-browser-validation": X_BROWSER_VALIDATION,
        }
        r = self.sess.post("https://www.google.com/recaptcha/api2/reload",
                           params={"k": self.sitekey}, data=body, headers=headers)
        _log(f"[reload] -> {r.status_code} len={len(r.content)} body_bytes={len(body)} "
             f"referer_bft={'yes' if bft else 'no(round-1 proven bft-less variant)'}")
        return r

    # ── §9.6 payload (the single payload endpoint serves both challenge media) ────────
    def do_payload(self, p):
        headers = {
            "accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",  # e2e.py:155
            "referer": f"https://www.google.com/recaptcha/api2/bframe?hl=en&v={VER}&k={self.sitekey}",
            "user-agent": UA_FULL,
        }
        r = self.sess.get("https://www.google.com/recaptcha/api2/payload",
                          params={"p": p, "k": self.sitekey}, headers=headers)
        _log(f"[payload] -> {r.status_code} ct={r.headers.get('content-type')} len={len(r.content)}")
        return r

    # ── §9.6 step 3 — userverify ───────────────────────────────────────────────────────────────
    def do_userverify(self, parsed, answer):
        """`answer` is the cleaned transcript (audio) or the selected tile indices (image —
        the encoder emits the JSON-array shape, bug 2 not replicated, §9.6 step 3)."""
        b64 = encode_userverify_response(answer)
        # t/ct in MILLISECONDS (§9.6 step 3), clamped into the 4000-15000 range of the §8.3
        # pacing window. The seconds variant (t/ct=6) is the one live userverify this folder
        # sent — and it was rejected (runs/1791295981328/solve.log).
        t = clamp_tct_ms(time.time() - (self.challenge_acquired_at or time.time()))
        # the referer carries a fresh bft from OUR reload response's j[15] (§9.6 step 3)
        referer = f"https://www.google.com/recaptcha/api2/bframe?hl=en&v={VER}&k={self.sitekey}"
        if parsed.get("bft"):
            referer += f"&bft={parsed['bft']}"
        headers = {
            "accept": "*/*",
            "content-type": "application/x-www-form-urlencoded;charset=UTF-8",   # e2e.py:482
            "origin": "https://www.google.com",
            "referer": referer,
            "user-agent": UA_FULL,
            "x-browser-validation": X_BROWSER_VALIDATION,
        }
        # ch/oc from the window mode when it delivered them, else the pinned constants
        # (§13.3). An unencrypted plaintext oc has NO wire slot — only oc_encrypted is sent.
        ch = self.window_ch if self.window_ch is not None else CH
        oc = self.window_oc if self.window_oc else OC
        data = {
            "v": self.ver, "c": parsed.get("c") or "", "response": b64,
            "t": t, "ct": t, "ch": ch, "oc": oc, "pm": self.fresh_pm or PM,
        }
        r = self.sess.post("https://www.google.com/recaptcha/api2/userverify",
                           params={"k": self.sitekey}, data=data, headers=headers)
        _log(f"[userverify] -> {r.status_code} len={len(r.content)} t/ct={t} (ms) "
             f"ch/oc={'window' if (self.window_ch or self.window_oc) else 'pinned constants'}")
        return r

    # ── §15.2 check-captcha (link4m mode, Face A) ────────────────────────────────────────
    def post_check_captcha(self, token, alias, code):
        """Port of e2e.py:710-729 — POST /links/check-captcha on the chain's own curl_cffi
        session (Face A never uses the bridge, §4; the design's §15.2 'bridge POST'
        phrasing is implemented Face-A-side, which is the reading consistent with §5.4
        handing --alias/--code to this process and with §4's no-bridge rule). S1 first,
        then link4m.com (e2e.py:15-16 / REVERSE_TRAIN_PLAN.md:68). A stale alias is an
        acceptable, honestly-reported outcome (§15.3) — it never flips a token-bearing
        run to failure."""
        if not alias:
            _log("[check-captcha] no alias — POST skipped (node-side should have tagged alias_missing)")
            return None
        hosts = ["https://s1.link4m.app", "https://link4m.com"]   # e2e.py:15-16, S1 first (§15.2)
        data = {"g-recaptcha-response": token, "alias": alias, "code": code or ""}
        headers = {
            "Origin": "https://link4m.com",
            "Referer": f"https://link4m.com/go/{alias}",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
        }
        verdict = None
        for host in hosts:
            try:
                r = self.sess.post(f"{host}/links/check-captcha", data=data, headers=headers)
                body = r.text or ""
                _log(f"[check-captcha] POST {host}/links/check-captcha -> {r.status_code} len={len(body)} head={body[:160]!r}")
                try:
                    j = r.json()
                except Exception:
                    j = None
                verdict = {"host": host.replace("https://", ""), "status": r.status_code,
                           "success": bool(isinstance(j, dict) and j.get("success")),
                           "url": (j or {}).get("url") if isinstance(j, dict) else None,
                           "body_head": body[:2000]}
                dump_dir = os.environ.get("RC_DUMP_DIR")
                if dump_dir:
                    try:
                        (Path(dump_dir) / "check_captcha.json").write_text(
                            json.dumps(verdict, ensure_ascii=False), encoding="utf-8")
                    except Exception:
                        pass
                rc_step({"step": "check_captcha", "host": verdict["host"], "status": r.status_code,
                         "success": verdict["success"], "url": verdict["url"]})
                if verdict["success"]:
                    _log(f"[check-captcha] SUCCESS bypass url={verdict['url']}")
                    return verdict
                if isinstance(j, dict) and j.get("success") is False:
                    _log(f"[check-captcha] rejected: {j.get('message') or j.get('msg') or j}")
            except Exception as exc:
                _log(f"[check-captcha] {host} error: {exc}")
                rc_step({"step": "check_captcha", "error": str(exc)})
        return verdict

    # ── §8.4 doscaptcha wait-and-retry ────────────────────────────────────────────────
    def doscaptcha_wait(self, body, token_expiration=None):
        """wait = max(30, countdown) + uniform(0,5) (§8.4, at least 30 s, respecting the
        countdown). A dos-blocked body usually carries NO scrapeable countdown; the rresp
        envelope's tokenExpiration (j[3], 120 s in every capture) is then the only countdown
        signal available and is used as the countdown floor, capped at itself. The caller
        then takes a FRESH anchor (never re-POSTs the stale envelope's token)."""
        countdown = _scrape_countdown(body)
        source = "body scrape"
        if countdown is None:
            countdown = token_expiration
            source = "rresp tokenExpiration (no countdown in the blocked body)"
        if countdown is not None and token_expiration:
            countdown = min(countdown, token_expiration)   # j[3] as upper sanity bound
        wait = max(30, countdown or 30) + random.uniform(0, 5)
        _log(f"[doscaptcha] blocked — LEVER: wait {wait:.0f}s before a fresh anchor "
             f"(countdown={countdown} via {source})")
        time.sleep(wait)

    # ── the round loop (§9.8) ─────────────────────────────────────────────────────────
    def run(self):
        """Returns (token_or_None, error_tag_or_None). Emits RC_STEP events; the token is
        printed by run_chain (the ONLY stdout write in Face A)."""
        rc_step({"step": "warmup"})
        self.warmup()
        self.load_seed()

        # §9.8 attempt model: --rounds (floor-clamped to 4) is the SOLVE-ATTEMPT budget. A
        # round consumes one attempt iff a solve was performed on an acquired challenge
        # (audio: acquired MP3 → transcribe → userverify; image: cascade → userverify). A
        # doscaptcha round (wait + fresh anchor, §8.4) and an image round skipped for missing
        # vision deps re-roll WITHOUT consuming an attempt — bounded by MAX_NON_ATTEMPTS
        # below so a page that never yields a solvable challenge cannot spin forever
        # (engineering guard, logged; the node-side RC_TIMEOUT is the outer bound).
        MAX_NON_ATTEMPTS = 8
        token = None
        err = None
        dos_waits = 0
        attempts = 0
        non_attempts = 0
        iters = 0
        prev_bft = None   # rresp j[15] of the previous round — referer lever for rounds ≥ 2
        while token is None:
            if attempts >= self.rounds:
                break
            if non_attempts >= MAX_NON_ATTEMPTS:
                _log(f"[loop] {non_attempts} consecutive non-attempt rounds (dos waits / "
                     f"deps-missing image rounds) — stopping (§9.8 guard)")
                break
            iters += 1
            _log(f"=== ROUND {iters} (attempts {attempts}/{self.rounds}, non-attempts {non_attempts}) ===")

            # anchor (§9.3)
            try:
                anchor_tok, k18, k31 = self.do_anchor()
            except Exception as exc:
                _log(f"[anchor] exception: {exc}")
                anchor_tok, k18, k31 = None, None, None
            if not anchor_tok:
                rc_step({"step": "anchor", "ok": False})
                self.last_tag = "anchor_fail"
                break
            rc_step({"step": "anchor", "ok": True})
            pace(0.8, 2.0)   # post-anchor (audio_solve.py:183's 1.5 s)

            # window emit — ONCE per run, after the first anchor (§13.3). A failure never
            # fails the run (§13.4): the chain proceeds with the captured constants.
            # --window-file (§14.2) consumes a producer's WINDOW_JSON from disk instead.
            if not self.window_emitted:
                self.window_emitted = True
                if self.window_file:
                    wout = self._load_window_file()
                else:
                    wout = self.emit_window((k18, k31))
                if wout is not None and wout.get("ok"):
                    self.consume_window(wout)
                else:
                    rc_step({"step": "window", "ok": False, "fallback": "constants"})

            # reload (§9.4) — or the <90 s seed-reuse path (§8.2: reload=skipped)
            parsed = None
            if iters == 1 and self.seed_reload is not None:
                parsed = self.seed_reload
                _log(f"[reload] SKIPPED — round-1 reload answered from _fresh_session.json "
                     f"(age={self.seed_age:.0f}s < 90s)")
                rc_step({"step": "reload", "ok": True, "skipped": True})
            else:
                try:
                    r = self.do_reload(anchor_tok, bft=prev_bft)
                    if r.status_code != 200:
                        rc_step({"step": "reload", "ok": False})
                        self.last_tag = "reload_fail"
                        break
                    parsed = parse_rresp(r.text)
                    if parsed.get("error"):
                        _log(f"[reload] rresp parse fail: {parsed.get('error')}")
                        rc_step({"step": "reload", "ok": False})
                        self.last_tag = "reload_fail"
                        break
                    rc_step({"step": "reload", "ok": True, "skipped": False})
                except Exception as exc:
                    _log(f"[reload] exception: {exc}")
                    rc_step({"step": "reload", "ok": False})
                    self.last_tag = "reload_fail"
                    break
            pace(0.8, 2.0)   # post-reload (audio_solve.py:222's 2.0 s)

            chal = parsed.get("chal_type")
            _log(f"[route] chal_type={chal} c={'yes' if parsed.get('c') else 'no'} "
                 f"p={'yes' if parsed.get('p') else 'no'} bft={'yes' if parsed.get('bft') else 'no'} "
                 f"jar={self._jar_names() or 'EMPTY'}")
            prev_bft = parsed.get("bft") or prev_bft

            # ── route on chal_type (§9.5) ──────────────────────────────────────────────
            if chal == "doscaptcha":
                # §8.4: reload reports ok (genuine rresp envelope came back — L2 transport
                # criterion); the block is expressed by challenge:none + error:doscaptcha.
                rc_step({"step": "challenge", "type": "doscaptcha"})
                self.last_tag = "doscaptcha"   # exhaustion while dos-blocked → tag doscaptcha
                dos_waits += 1
                non_attempts += 1              # a dos wait does NOT consume an attempt (§9.8)
                # diagnostic: keep OUR dos envelope (the DESIGN §1 check read a captured one
                # from August; ours may carry an actionable field) under the run's dump dir
                dump_dir = os.environ.get("RC_DUMP_DIR")
                if dump_dir:
                    try:
                        (Path(dump_dir) / f"dos_rresp_{iters}.json").write_text(
                            json.dumps(parsed.get("raw_j"), ensure_ascii=False)[:20000],
                            encoding="utf-8")
                        _log(f"[doscaptcha] raw envelope -> dos_rresp_{iters}.json | head: "
                             f"{json.dumps(parsed.get('raw_j'))[:220]}")
                    except Exception as exc:
                        _log(f"[doscaptcha] envelope dump failed: {exc}")
                if dos_waits > self.dos_retries:
                    break
                self.doscaptcha_wait(json.dumps(parsed.get("raw_j"))[:4000],
                                     parsed.get("token_expiration"))
                continue   # fresh anchor next iteration (never reuse the stale token)

            if chal in IMAGE_TYPES:
                # §9.5: image rounds are an EXPECTED outcome, not a splice-failure tell-tale
                # (the f6 'a' splice is proven live, §18.1) — the §9.7 branch routes them.
                rc_step({"step": "challenge", "type": "image"})
                token, action, dos_waits, non_attempts = self._image_branch(
                    parsed, None, iters, dos_waits, non_attempts)
                if token or action == "stop":
                    break
                continue

            if chal != "audio":
                # nocaptcha / qr / anything else (§9.5)
                rc_step({"step": "challenge", "type": "none"})
                self.last_tag = "no_audio_challenge"
                non_attempts += 1
                pace(1.0, 2.5)
                continue

            # ── audio: payload MP3 (§9.6 step 1) ─────────────────────────────────────
            try:
                pr = self.do_payload(parsed["p"])
            except Exception as exc:
                _log(f"[payload] exception: {exc}")
                rc_step({"step": "challenge", "type": "none"})
                self.last_tag = "mp3_fail"
                non_attempts += 1
                continue
            body = pr.content or b""
            if pr.status_code != 200:
                rc_step({"step": "challenge", "type": "none"})
                self.last_tag = "mp3_fail"
                non_attempts += 1
                continue
            if body[:2] in (b"\xff\xd8", b"\x89P"):
                # the e2e.py:163 check — image despite an audio rresp (§9.5/§9.6): the
                # image branch handles it instead of discarding the round (rule 5)
                _log("[payload] got an IMAGE despite an audio rresp — routed to the image branch (§9.5)")
                rc_step({"step": "challenge", "type": "image"})
                token, action, dos_waits, non_attempts = self._image_branch(
                    parsed, body, iters, dos_waits, non_attempts)
                if token or action == "stop":
                    break
                continue
            if looks_like_doscaptcha(body):
                rc_step({"step": "challenge", "type": "doscaptcha"})
                self.last_tag = "doscaptcha"   # exhaustion while dos-blocked → tag doscaptcha
                dos_waits += 1
                non_attempts += 1              # a dos wait does NOT consume an attempt (§9.8)
                if dos_waits > self.dos_retries:
                    break
                self.doscaptcha_wait(body, parsed.get("token_expiration"))
                continue
            ct = (pr.headers.get("content-type") or "").lower()
            is_mp3 = len(body) >= 1000 and ("audio/mpeg" in ct or body[:3] == b"ID3" or (len(body) > 2 and body[0] == 0xFF and (body[1] & 0xE0) == 0xE0))
            if not is_mp3:
                # the audio_solve.py:268 gate: < 1000 bytes (or unrecognized media) keeps
                # interstitial/blocked pages out of whisper (§9.6 step 1)
                _log(f"[payload] not MP3 (len={len(body)} ct={ct}) — gate rejects, fresh challenge")
                rc_step({"step": "challenge", "type": "none"})
                self.last_tag = "mp3_fail"
                non_attempts += 1
                continue
            # real MP3 bytes in hand — only NOW challenge=acquired-audio (§9.6 step 1) and
            # the round CONSUMES its attempt (§9.8: one solve attempt on a freshly
            # acquired challenge)
            rc_step({"step": "challenge", "type": "audio"})
            self.challenge_acquired_at = time.time()
            attempts += 1

            # ── whisper transcription (§9.6 step 2, in-process — Face A shares Face B's engine) ──
            tmp = None
            try:
                fd, tmp = tempfile.mkstemp(suffix=".mp3")
                with os.fdopen(fd, "wb") as f:
                    f.write(body)
                transcript = _transcriber(tmp, model_size=self.model)
            except Exception as exc:
                _log(f"[transcribe] exception: {exc}")
                transcript = None
                self.last_tag = "transcribe_failed"
            finally:
                if tmp:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
            if not transcript or len(transcript) < 2:
                # empty / <2-char answer → fresh audio challenge (§9.6 step 2); the exhaustion
                # tag for transcription that never produced an answer is transcribe_failed
                _log("[transcribe] empty/<2-char answer — fresh audio challenge")
                rc_step({"step": "transcribe", "ok": False})
                self.last_tag = "transcribe_failed"
                pace(1.0, 2.5)
                continue
            rc_step({"step": "transcribe", "ok": True})
            _log(f"[transcribe] answer={transcript!r}")

            # ── userverify (§9.6 step 3) ─────────────────────────────────────────────────────
            pace(1.0, 2.5)   # pre-userverify (audio_solve.py:308's 2.5 s)
            try:
                uv = self.do_userverify(parsed, transcript)
                parsed_uv = parse_uvresp(uv.text)
            except Exception as exc:
                _log(f"[userverify] exception: {exc}")
                rc_step({"step": "userverify", "ok": False})
                self.last_tag = "uv_reject"
                continue
            tok = parsed_uv.get("token")
            if tok and len(tok) > 300 and parsed_uv.get("dynamic_rresp") is None:
                # accept iff len > 300 with no embedded rresp (e2e.py:506 threshold)
                rc_step({"step": "userverify", "ok": True, "token_len": len(tok)})
                token = tok
                break
            rc_step({"step": "userverify", "ok": False})
            self.last_tag = "uv_reject"
            _log(f"[userverify] rejected (token={'yes' if tok else 'no'} len={len(tok) if tok else 0} "
                 f"dyn={'yes' if parsed_uv.get('dynamic_rresp') else 'no'}) — next round")
            pace(1.0, 2.5)   # between rounds (e2e.py:701)

        if token:
            return token, None
        return None, err or self.last_tag or "no_audio_challenge"

    # ── the image branch (§9.7) ───────────────────────────────────────────────────────
    def _image_branch(self, parsed, body, iters, dos_waits, non_attempts):
        """payload JPEG → YOLO/CLIP cascade → userverify. `body` may carry the bytes already
        fetched (the image-despite-audio-rresp case). Returns (token, action, dos_waits,
        non_attempts) — action: "loop" (continue the round loop) | "stop" (dos exhausted).
        Attempt accounting (§9.8): an attempt is consumed iff the cascade actually ran on
        an acquired image; a deps-missing round re-rolls WITHOUT consuming one."""
        if not self.solve_image:
            _log("[image] --solve-image not set — image round re-rolled (§9.5)")
            self.last_tag = "image_unsolved"
            non_attempts += 1
            pace(1.0, 2.5)
            return None, "loop", dos_waits, non_attempts

        if body is None:
            try:
                pr = self.do_payload(parsed["p"])
            except Exception as exc:
                _log(f"[payload] exception: {exc}")
                rc_step({"step": "image_solve", "ok": False})
                self.last_tag = "image_unsolved"
                non_attempts += 1
                return None, "loop", dos_waits, non_attempts
            body = pr.content or b""
            if pr.status_code != 200:
                rc_step({"step": "image_solve", "ok": False})
                self.last_tag = "image_unsolved"
                non_attempts += 1
                return None, "loop", dos_waits, non_attempts
        if looks_like_doscaptcha(body):
            rc_step({"step": "challenge", "type": "doscaptcha"})
            self.last_tag = "doscaptcha"
            dos_waits += 1
            non_attempts += 1          # a dos wait does NOT consume an attempt (§9.8)
            if dos_waits > self.dos_retries:
                return None, "stop", dos_waits, non_attempts
            self.doscaptcha_wait(body, parsed.get("token_expiration"))
            return None, "loop", dos_waits, non_attempts
        if body[:2] not in (b"\xff\xd8", b"\x89P"):
            _log(f"[image] payload is not an image (len={len(body)} head={body[:8]!r}) — re-roll")
            rc_step({"step": "image_solve", "ok": False})
            self.last_tag = "image_unsolved"
            non_attempts += 1
            return None, "loop", dos_waits, non_attempts

        if not image_deps_available():
            # §9.5/§9.7: requires importable vision deps — else a fresh round WITHOUT
            # consuming an attempt, reported as
            # RC_STEP {"step":"image_solve","skipped":"deps_missing"}
            _log("[image] vision deps missing (ultralytics not importable) — deps_missing re-roll")
            rc_step({"step": "image_solve", "skipped": "deps_missing"})
            self.last_tag = "image_unsolved"
            non_attempts += 1
            pace(1.0, 2.5)
            return None, "loop", dos_waits, non_attempts

        # an acquired image with deps available — the round consumes its attempt (§9.8)
        dump_dir = os.environ.get("RC_DUMP_DIR")
        img_path = None
        try:
            fd, img_path = tempfile.mkstemp(suffix=".jpg")
            with os.fdopen(fd, "wb") as f:
                f.write(body)
            if dump_dir:
                try:
                    (Path(dump_dir) / f"image_round_{iters}.jpg").write_bytes(body)
                except Exception:
                    pass
            mids = parsed.get("mids") or []
            _log(f"[image] challenge acquired ({len(body)}B, mids={mids}) — running the "
                 f"cascade (3x3 crop discipline, §9.7)")
            indices = predict_hybrid(img_path, mids)
        except Exception as exc:
            _log(f"[image] cascade exception: {exc}")
            indices = None
        finally:
            if img_path:
                try:
                    os.unlink(img_path)
                except OSError:
                    pass

        if not indices:
            rc_step({"step": "image_solve", "ok": False})
            self.last_tag = "image_unsolved"
            pace(1.0, 2.5)
            return None, "loop", dos_waits, non_attempts
        rc_step({"step": "image_solve", "ok": True, "indices": [int(i) for i in indices]})
        self.challenge_acquired_at = time.time()

        pace(1.0, 2.5)   # pre-userverify (§8.3)
        try:
            uv = self.do_userverify(parsed, list(indices))
            parsed_uv = parse_uvresp(uv.text)
        except Exception as exc:
            _log(f"[userverify] exception: {exc}")
            rc_step({"step": "userverify", "ok": False})
            self.last_tag = "uv_reject"
            return None, "loop", dos_waits, non_attempts
        tok = parsed_uv.get("token")
        if tok and len(tok) > 300 and parsed_uv.get("dynamic_rresp") is None:
            rc_step({"step": "userverify", "ok": True, "token_len": len(tok)})
            return tok, "loop", dos_waits, non_attempts
        rc_step({"step": "userverify", "ok": False})
        self.last_tag = "uv_reject"
        _log(f"[userverify] rejected (token={'yes' if tok else 'no'} "
             f"len={len(tok) if tok else 0} dyn={'yes' if parsed_uv.get('dynamic_rresp') else 'no'}) — next round")
        pace(1.0, 2.5)   # between rounds (e2e.py:701)
        return None, "loop", dos_waits, non_attempts


# ══════════════════════════════════════════════════════════════════════════════════════
# Shim modes (§13) — what the Rust engine (window-vm, §9.2 shim.rs) calls over subprocess.
# Contract: ONE line on stdout, all logs on stderr; exit 0 = usable result (even an empty
# transcript / deps-missing classify), exit 2 = crash. The shims never touch the network.
# ══════════════════════════════════════════════════════════════════════════════════════

def _decode_b64_arg(b64):
    """--audio-b64/--img-b64 payload: the argv value, or '-' to read stdin (the engine
    pipes the base64 text). Returns raw bytes, or None when nothing was supplied."""
    if b64 is None:
        return None
    s = str(b64).strip()
    if s == "-":
        s = sys.stdin.read().strip()
    if not s:
        return None
    return base64.b64decode(s)


def shim_transcribe(args):
    """§13: `transcribe --file <mp3>` | `transcribe --audio-b64 <b64|->` → prints the
    CLEANED transcript to stdout (single line). Exit 0 on any transcript (even empty —
    the engine decides), 2 on crash. Reuses the exact audio_solve.py:49-97 port
    (transcribe_mp3 → get_whisper singleton → clean_transcript)."""
    try:
        raw = _decode_b64_arg(args.audio_b64)
        if raw is not None:
            fd, mp3_path = tempfile.mkstemp(suffix=".mp3")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(raw)
                text = transcribe_mp3(mp3_path, model_size=args.model)
            finally:
                try:
                    os.unlink(mp3_path)
                except OSError:
                    pass
        elif args.file:
            text = transcribe_mp3(args.file, model_size=args.model)
        else:
            _log("[shim] transcribe: no --file and no --audio-b64 — nothing to transcribe")
            return 2
        print(text, flush=True)
        return 0
    except Exception as exc:
        _log(f"[shim] transcribe failed: {exc}")
        return 2


def shim_classify(args):
    """§13: `classify --img-b64 <b64> --targets "bus,traffic light" [--grid 3]` → prints
    {"indices":[…],"instruction":"…"} to stdout. Vision deps missing → {"skipped":
    "deps_missing"} and exit 0 (the engine re-rolls WITHOUT consuming an attempt, §9.8).
    Reuses the e2e.py cascade port (predict_hybrid, MID_LABEL-mapped targets); the crop
    discipline stays the hardcoded 3×3 (a 4×4 payload is mis-cropped — known upstream
    limitation), so a non-3 --grid is logged and clamped, never silently honored."""
    try:
        if not image_deps_available():
            print(json.dumps({"skipped": "deps_missing"}), flush=True)
            return 0
        raw = _decode_b64_arg(args.img_b64)
        if raw is None:
            _log("[shim] classify: no --img-b64")
            return 2
        labels = [t.strip() for t in (args.targets or "").split(",") if t.strip()]
        if not labels:
            _log("[shim] classify: no --targets")
            return 2
        grid = int(args.grid or 3)
        if grid != 3:
            _log(f"[shim] classify: --grid {grid} clamped to 3 (hardcoded 3×3 crop, §9.7)")
        label_to_mid = {}
        for mid, lab in MID_LABEL.items():
            label_to_mid.setdefault(lab.lower(), mid)
        mids = [label_to_mid.get(l.lower(), l) for l in labels]   # unmapped labels pass through
        fd, img_path = tempfile.mkstemp(suffix=".jpg")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            indices = predict_hybrid(img_path, mids)
        finally:
            try:
                os.unlink(img_path)
            except OSError:
                pass
        print(json.dumps({"indices": [int(i) for i in (indices or [])],
                          "instruction": ", ".join(labels)}), flush=True)
        return 0
    except Exception as exc:
        _log(f"[shim] classify failed: {exc}")
        return 2


def run_chain(args):
    """Face A CLI entry: runs the chain, prints the token to stdout ONCE, exits 0/1/2 (§5.4).
    In --mode link4m the check-captcha POST (§15.2) runs after minting and reports on
    stderr; a stale alias never changes the exit code (§15.3)."""
    try:
        chain = AudioChain(
            url=args.url,
            sitekey=args.sitekey or DEMO_SITEKEY,
            model=args.model,
            rounds=args.rounds,
            audio_retries=args.audio_retries,
            fresh_session=args.fresh_session,
            solve_image=args.solve_image,
            window_mode=args.window,
            window_profile=args.window_profile,
            window_file=args.window_file,
        )
        token, err = chain.run()
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr)
        rc_step({"step": "done", "token": False, "error": "crash"})
        return 2
    if token:
        # §15.2 (Face A): the link4m check-captcha POST runs after the token is minted and
        # BEFORE the done event; its verdict travels on stderr via RC_STEP and into
        # runs/<ts>/check_captcha.json — the token itself still prints, and a stale alias
        # never changes the exit code (§15.3).
        if args.mode == "link4m":
            chain.post_check_captcha(token, args.alias, args.code)
        rc_step({"step": "done", "token": True, "error": None})
        print(token, flush=True)   # the ONLY stdout write: the g-recaptcha-response token
        return 0
    rc_step({"step": "done", "token": False, "error": err})
    _log(f"[done] no token — error tag: {err}")
    return 1


# ══════════════════════════════════════════════════════════════════════════════════════
# Face B — the audio API (kept from the current implementation, unchanged contract, §7)
# ══════════════════════════════════════════════════════════════════════════════════════

# ── the one endpoint's core ───────────────────────────────────────────────────────────
def handle_transcribe(data):
    """dict in → dict out. All failures are 200 {"error": …} per the contract."""
    audio_b64 = data.get("audio_b64")
    if not audio_b64:
        return {"error": "no_audio_b64"}
    try:
        mp3_bytes = base64.b64decode(audio_b64)
    except Exception as exc:
        return {"error": f"bad_audio_b64: {exc}"}
    if len(mp3_bytes) < 1000:
        # the size gate normally fires first in rc_solve.js (§8 step 3); kept per §9 item 3
        return {"error": f"mp3_too_small (< 1000 bytes): {len(mp3_bytes)}"}
    model_size = data.get("model") or DEFAULT_MODEL
    tmp = None
    try:
        # faster-whisper consumes a path (§9 item 1); temp file deleted in finally
        fd, tmp = tempfile.mkstemp(suffix=".mp3")
        with os.fdopen(fd, "wb") as f:
            f.write(mp3_bytes)
        text = _transcriber(tmp, model_size=model_size)
    except Exception as exc:
        return {"error": f"transcribe_failed: {exc}"}
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return {"text": text}


class TranscribeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):   # quieter default logging
        sys.stderr.write("[solve_service] " + (fmt % args) + "\n")

    def do_POST(self):
        if self.path.rstrip("/") != "/transcribe":
            self._send(404, {"error": f"unknown path {self.path} (POST /transcribe only)"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception as exc:
            self._send(200, {"error": f"bad_json: {exc}"})
            return
        try:
            self._send(200, handle_transcribe(data))
        except Exception as exc:   # never 500: the contract is {"error": …} on any failure
            self._send(200, {"error": f"transcribe_failed: {exc}"})

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(port, model):
    global DEFAULT_MODEL
    DEFAULT_MODEL = model
    httpd = ThreadingHTTPServer(("127.0.0.1", port), TranscribeHandler)
    _log(f"[solve_service] listening on http://127.0.0.1:{port}/transcribe (model={model})")
    httpd.serve_forever()


# ══════════════════════════════════════════════════════════════════════════════════════
# --selftest — NO external network, model NOT loaded/downloaded, NO child processes.
# Face B checks (loopback /transcribe contract) + Face A offline checks (the reload body
# round-trip and field walk, the structural splice, derive_co, the rresp/uvresp parsers,
# the response encoder, the doscaptcha detector, varint round-trips).
# ══════════════════════════════════════════════════════════════════════════════════════
def selftest():
    results = []

    def check(name, ok, extra=""):
        results.append((name, bool(ok), str(extra)[:140]))

    # ── Face B: cleaning pipeline (verbatim audio_solve.py:80-96 behavior) ────────────
    check("clean: full preamble removed",
          clean_transcript("Please listen carefully to the following words. 5, 9, 7, 3.") == "5 9 7 3",
          repr(clean_transcript("Please listen carefully to the following words. 5, 9, 7, 3.")))
    check("clean: short preamble removed", clean_transcript("Type what you hear: 1 2 3") == "1 2 3",
          repr(clean_transcript("Type what you hear: 1 2 3")))
    check("clean: volume preamble removed",
          clean_transcript("Make sure your volume is turned up! 8 8 8") == "8 8 8")
    check("clean: punctuation stripped", clean_transcript("5. 9! 7? 3.") == "5 9 7 3",
          repr(clean_transcript("5. 9! 7? 3.")))
    check("clean: whitespace collapsed", clean_transcript("  1    2 \n 3  ") == "1 2 3")
    check("clean: 8 preamble phrases present", len(PREAMBLE_PHRASES) == 8)

    # ── Face A: the reload body round-trip and field walk (§9.4) ──────────────────────
    check("template: round-trip == 8336 bytes", len(_reloaded) == 8336, f"len={len(_reloaded)}")
    try:
        fields = _walk_fields(_reloaded)
        shape = [(fn, len(v)) for fn, v in fields]
        expected = [(1, 24), (2, 1892), (5, 10), (6, 2), (14, 40), (16, 5644), (20, 565), (21, 116), (25, 18)]
        check("template: field walk matches the §1 decode", shape == expected, str(shape))
        by_fn = dict(fields)
        check("template: f6 ships as captured 'fi'", by_fn.get(6) == b"fi", repr(by_fn.get(6)))
        check("template: f2 redacted to '0'*1892", by_fn.get(2) == b"0" * 1892)
        check("template: f14 redacted to the public demo key", by_fn.get(14) == DEMO_SITEKEY.encode())
        check("template: f21 redacted to 'A'*116", by_fn.get(21) == b"A" * 116)
        # rule 2: no captured material anywhere in the shipped constant. The old negative check
        # embedded the captured link4m key prefix to assert its absence — self-defeating under
        # rule 2 — so the invariant is strengthened instead: after removing the demo key (which
        # f14 legitimately carries), no other 40-char sitekey-shaped literal may remain.
        check("template: no stale 03AF token", b"03AFcWeA" not in _reloaded)
        check("template: the only sitekey-shaped field is the demo key",
              all(fn == 14 or not (len(v) == 40 and re.fullmatch(rb"6L[A-Za-z0-9_\-]{38}", v))
                  for fn, v in fields))
        check("template: no prior-captcha 0aALJP token", b"0aALJP" not in _reloaded)
    except Exception as exc:
        check("template: field walk", False, str(exc))

    # ── Face A: structural splice (§9.4 per-solve surgery) ────────────────────────────
    try:
        tok = "03AFcWeA" + "Z" * 100
        key = "6L" + "x" * 38   # inert 40-char v2-shaped fixture key (rule 2: no real key material)
        body = rebuild_reload_body(tok, key, mode="a")
        by_fn = dict(_walk_fields(body))
        check("splice: f2 ← fresh anchor token", by_fn.get(2) == tok.encode())
        check("splice: f14 ← target sitekey", by_fn.get(14) == key.encode())
        check("splice: f6 ← 'a' (audio mode, §9.4)", by_fn.get(6) == b"a")
        check("splice: f21 stays blanked", by_fn.get(21) == b"A" * 116)
        check("splice: f16 untouched", by_fn.get(16) == dict(_walk_fields(_reloaded))[16])
        check("splice: f21 refill via prior_token",
              dict(_walk_fields(rebuild_reload_body(tok, key, prior_token="0aALJP" + "q" * 110))).get(21)
              == b"0aALJP" + b"q" * 110)
        # non-40-char sitekey still lands (varint rewrite covers any length, §9.4)
        short_key = "abc"
        check("splice: varint rewrite for short sitekey",
              dict(_walk_fields(rebuild_reload_body(tok, short_key))).get(14) == b"abc")
    except Exception as exc:
        check("splice: rebuild", False, str(exc))

    # ── Face A: derive_co (§9.3 — pads REPLACED by dots) ──────────────────────────────
    # expected = the EXACT capture at recaptcha/e2e.py:40 (decodes to https://www.google.com:443)
    check("co: demo origin reproduces the captured constant",
          derive_co("https://www.google.com/recaptcha/api2/demo") == "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDM.",
          derive_co("https://www.google.com/recaptcha/api2/demo"))
    # 'https://foo.com:443' is 19 bytes -> base64 needs two pads -> must end '..' (§9.3)
    check("co: two-pad origin ends '..'",
          derive_co("https://foo.com/page").endswith(".."),
          derive_co("https://foo.com/page"))

    # ── Face A: varint round-trips ────────────────────────────────────────────────────
    ok = True
    for n in (0, 1, 127, 128, 1892, 5644, 202, 2 ** 31):
        v, ni = _read_varint(_varint(n) + b"\x00", 0)
        ok = ok and v == n and ni == len(_varint(n))
    check("varint: encode/decode round-trips", ok)

    # ── Face A: rresp parser (§9.5) ───────────────────────────────────────────────────
    audio_rresp = (")]}'\n" + json.dumps([
        "rresp", "0cAFcWeA" + "c" * 40, None, 120, None, "audio", None, None, None,
        "06AFcWeA" + "p" * 90, None, None, None, None, None, "0dAFcWeA" + "b" * 40,
    ]))
    pr = parse_rresp(audio_rresp)
    check("rresp: audio envelope parsed",
          pr.get("chal_type") == "audio" and pr.get("c") == "0cAFcWeA" + "c" * 40
          and pr.get("p") == "06AFcWeA" + "p" * 90, str({k: (v[:20] if isinstance(v, str) else v) for k, v in pr.items() if k != "raw_j"}))
    check("rresp: tokenExpiration 120 at j[3]", pr.get("token_expiration") == 120)
    check("rresp: bft at j[15]", pr.get("bft") == "0dAFcWeA" + "b" * 40)
    dos_rresp = (")]}'\n" + json.dumps([
        "rresp", "0cAFcWeA" + "x" * 40, None, 120, None, "doscaptcha", None, None, None,
        "06AFcWeA" + "y" * 90,
    ]))
    pr2 = parse_rresp(dos_rresp)
    check("rresp: doscaptcha envelope still carries j[1] token but is routed by chal_type",
          pr2.get("chal_type") == "doscaptcha" and pr2.get("p", "").startswith("06AF"), pr2.get("chal_type"))
    check("rresp: garbage → error, no raise", bool(parse_rresp("not json at all").get("error")))

    # ── Face A: uvresp parser (§9.6 step 3, e2e.py:506 threshold) ────────────────────────────
    good_uv = (")]}'\n" + json.dumps(["uvresp", "03AFcWeA" + "g" * 600, None, None, 0]))
    puv = parse_uvresp(good_uv)
    check("uvresp: >300-char token accepted, no dyn",
          puv.get("token") and len(puv["token"]) > 300 and puv.get("dynamic_rresp") is None)
    reject_uv = (")]}'\n" + json.dumps(["uvresp", None, None, None, 0, ["rresp", "0cAF", None, 120, None, "dynamic"]]))
    puv2 = parse_uvresp(reject_uv)
    check("uvresp: embedded rresp = rejection", puv2.get("dynamic_rresp") is not None)
    short_uv = (")]}'\n" + json.dumps(["uvresp", "03AFcWeA" + "s" * 150, None, None, 0]))
    check("uvresp: ≤300-char token NOT accepted", not (parse_uvresp(short_uv).get("token") and len(parse_uvresp(short_uv)["token"]) > 300))

    # ── Face A: the response encoder (§9.6 step 3 — bug 2 dies here) ─────────────────────────
    b64_audio = encode_userverify_response("5 9 7 3")
    inner = json.loads(base64.b64decode(b64_audio))
    check("uvresp-encoder: audio string shape", inner == {"response": "5 9 7 3", "s": "4cd7", "e": "bXVs"}, str(inner))
    b64_img = encode_userverify_response([3, 1, 4])
    inner2 = json.loads(base64.b64decode(b64_img))
    check("uvresp-encoder: image JSON-array shape (NOT comma-joined)", inner2 == {"response": [3, 1, 4], "s": "4cd7", "e": "bXVs"}, str(inner2))

    # ── Face A: doscaptcha detector on bytes (audio_solve.py:226-231, §8.4) ───────────
    check("dosdetect: header marker", looks_like_doscaptcha(b'<html id="rc-doscaptcha-header">'))
    check("dosdetect: message marker", looks_like_doscaptcha(b"Your computer or network may be sending automated queries"))
    check("dosdetect: clean body", not looks_like_doscaptcha(b"<html>normal audio challenge</html>"))
    check("dosdetect: countdown scrape best-effort",
          _scrape_countdown(b'<div data-countdown="45">retry</div>') == 45,
          str(_scrape_countdown(b'<div data-countdown="45">retry</div>')))

    # ── Face A: ch (ocHash) derivation — hashOC.js:8-14 port ─────────────────────────
    # Full-sample cross-validation ran live this session: node hashOC.js and this port both
    # print 574824847 on the file's published 1645-char sample (not embedded here — keep the
    # folder lean); the known-answer vectors pin the same algorithm deterministically.
    check("ch-hash: Java hashCode known-answer vectors",
          hash_string("") == 0 and hash_string("a") == 97 and hash_string("ab") == 3105,
          f"hash('ab')={hash_string('ab')}")
    hv = hash_string("x" * 64)
    check("ch-hash: signed-32-bit output range", -2**31 <= hv < 2**31, str(hv))
    check("ch-hash: wraparound goes negative (README sample ch:-4007845 shape)",
          to_signed32(0xFFFFFFFF) == -1 and to_signed32(0x80000000) == -2147483648)

    # ── Face A: anchor-key extraction (§9.3 — best-effort, UNVERIFIED live shape §18.10) ─
    ainput_fixture = ('<script>var a = ["ainput",["bgdata","","x","y","z"],null,["conf"],'
                      + ",".join(str(i) for i in range(4, 18))
                      + ',1777669303203'          # index 18 — the fingerprint encryption key
                      + ',' + ",".join(str(i) for i in range(19, 31))
                      + ',1777752103288'          # index 31 — the oc encryption key
                      + '];</script>')
    k18, k31 = extract_anchor_keys(ainput_fixture)
    check("anchor-keys: index 18 / 31 extracted from an ainput fixture",
          k18 == 1777669303203 and k31 == 1777752103288, f"{k18}/{k31}")
    check("anchor-keys: garbled HTML → (None, None), never a raise",
          extract_anchor_keys("<html>no config</html>") == (None, None) and
          extract_anchor_keys('["ainput", broken') == (None, None))

    # ── Face A: the window f5/f16 pair upgrade (§13.3 — BOTH or NEITHER) ──────────────
    try:
        tok = "03AFcWeA" + "Z" * 100
        key = "6L" + "x" * 38   # inert 40-char v2-shaped fixture key (rule 2: no real key material)
        cap = dict(_walk_fields(_reloaded))
        enc = base64.b64encode(b"\x01\x02ENCRYPTED-BYTES-FROM-THE-WINDOW").decode()
        up = dict(_walk_fields(rebuild_reload_body(tok, key, fingerprint_hash=1382190855,
                                                   fingerprint_encrypted=enc)))
        check("window-splice: f5 ← fingerprint_hash (decimal-string form)",
              up.get(5) == b"1382190855", repr(up.get(5)))
        check("window-splice: f16 ← decoded fingerprint_encrypted bytes",
              up.get(16) == b"\x01\x02ENCRYPTED-BYTES-FROM-THE-WINDOW")
        check("window-splice: no override → captured f5/f16 pair stays",
              dict(_walk_fields(rebuild_reload_body(tok, key))).get(5) == cap[5] and
              dict(_walk_fields(rebuild_reload_body(tok, key))).get(16) == cap[16])
        half = dict(_walk_fields(rebuild_reload_body(tok, key, fingerprint_hash=42)))
        check("window-splice: hash WITHOUT ciphertext → pair NOT mixed",
              half.get(5) == cap[5] and half.get(16) == cap[16])
        garbled = dict(_walk_fields(rebuild_reload_body(tok, key, fingerprint_hash=42,
                                                        fingerprint_encrypted="!!!not-b64!!!")))
        check("window-splice: garbled ciphertext → captured pair stays",
              garbled.get(5) == cap[5] and garbled.get(16) == cap[16])
    except Exception as exc:
        check("window-splice: rebuild", False, str(exc))

    # ── Face A: t/ct in MILLISECONDS (§9.6 step 3 — the rejected seconds POST) ────────
    check("t/ct: seconds-scale elapsed → milliseconds string",
          clamp_tct_ms(6) == "6000", clamp_tct_ms(6))
    check("t/ct: clamped into the 4000-15000 §8.3 pacing window",
          clamp_tct_ms(0.2) == "4000" and clamp_tct_ms(120) == "15000",
          f"{clamp_tct_ms(0.2)}/{clamp_tct_ms(120)}")

    # ── Face A: image branch constants + deps gate (§9.7 — imports only, NO model load) ─
    check("image: MID_LABEL maps the known mids (e2e.py:25)",
          MID_LABEL["/m/015qff"] == "traffic light" and MID_LABEL["/m/01lynh"] == "fire hydrant")
    check("image: COCO_YOLO covers the detectable set (e2e.py:184)",
          "traffic light" in COCO_YOLO and "fire hydrant" in COCO_YOLO)
    check("image: deps gate answers without loading any model",
          isinstance(image_deps_available(), bool), str(image_deps_available()))

    # ── Face A: link4m check-captcha request shape (§15.2 — S1 first; no network) ─────
    check("link4m: hosts ordered S1 then link4m.com (e2e.py:15-16)",
          ["https://s1.link4m.app", "https://link4m.com"] ==
          ["https://" + h for h in ("s1.link4m.app", "link4m.com")])
    check("link4m: form keys are the API's exact names (e2e.py:716)",
          sorted({"g-recaptcha-response", "alias", "code"}) ==
          sorted(["g-recaptcha-response", "alias", "code"]))

    # ── Face B: /transcribe contract over LOOPBACK with the transcriber stubbed ───────
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), TranscribeHandler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/transcribe"

    def post(obj):
        req = urllib.request.Request(base, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    big = base64.b64encode(b"\x00" * 1200).decode()
    small = base64.b64encode(b"\x00" * 500).decode()
    try:
        stub = lambda path, model_size="tiny.en": "stub answer 5 9 7 3"   # noqa: E731
        global _transcriber
        _transcriber = stub
        r1 = post({"audio_b64": big, "lang": "en"})
        check("contract: success shape {text}", r1.get("text") == "stub answer 5 9 7 3", json.dumps(r1)[:100])
        r2 = post({})
        check("contract: no_audio_b64", r2.get("error") == "no_audio_b64", json.dumps(r2)[:100])
        r3 = post({"audio_b64": small})
        check("contract: mp3_too_small", str(r3.get("error", "")).startswith("mp3_too_small"), json.dumps(r3)[:100])
        r4 = post({"audio_b64": "!!!not-base64!!!"})
        check("contract: bad_audio_b64", str(r4.get("error", "")).startswith("bad_audio_b64"), json.dumps(r4)[:100])

        def _boom(path, model_size="tiny.en"):
            raise RuntimeError("stub failure")

        _transcriber = _boom
        r5 = post({"audio_b64": big})
        check("contract: transcribe_failed", str(r5.get("error", "")).startswith("transcribe_failed"), json.dumps(r5)[:100])
    finally:
        _transcriber = transcribe_mp3
        httpd.shutdown()

    # ── Shim modes (§13): offline checks — no model load, no network ──────────────────
    check("shim: _decode_b64_arg argv round-trip",
          _decode_b64_arg(base64.b64encode(b"\xff\xd8abc").decode()) == b"\xff\xd8abc")
    check("shim: _decode_b64_arg absent → None", _decode_b64_arg(None) is None)
    check("shim: _decode_b64_arg empty → None", _decode_b64_arg("") is None)
    try:
        rc = shim_transcribe(argparse.Namespace(audio_b64=None, file=None, model="tiny.en"))
        check("shim: transcribe with no input → exit 2 (crash contract), no model load",
              rc == 2, f"rc={rc}")
    except Exception as exc:
        check("shim: transcribe no-input runs", False, str(exc))
    try:
        _real_deps = globals()["image_deps_available"]
        globals()["image_deps_available"] = lambda: False   # stub: answers WITHOUT loading models
        buf = io.StringIO()
        _stdout = sys.stdout
        sys.stdout = buf
        try:
            rc = shim_classify(argparse.Namespace(img_b64=big, targets="bus,traffic light", grid=3))
        finally:
            sys.stdout = _stdout
            globals()["image_deps_available"] = _real_deps
        out = json.loads(buf.getvalue().strip() or "{}")
        check("shim: classify deps-missing → {\"skipped\":\"deps_missing\"}, exit 0 (engine re-rolls)",
              rc == 0 and out.get("skipped") == "deps_missing", f"rc={rc} out={buf.getvalue().strip()[:60]}")
    except Exception as exc:
        check("shim: classify deps-missing runs", False, str(exc))

    # ── info-only: heavy deps importable? (models are NOT loaded/downloaded) ──────────
    try:
        import faster_whisper  # noqa: F401
        check("info: faster-whisper importable (model not loaded)", True)
    except Exception as exc:
        check("info: faster-whisper NOT importable — pip install -r requirements.txt", False, str(exc)[:100])
    try:
        import curl_cffi  # noqa: F401
        check("info: curl_cffi importable", True)
    except Exception as exc:
        check("info: curl_cffi NOT importable — pip install -r requirements.txt", False, str(exc)[:100])

    core = [(n, ok) for (n, ok, _) in results if not n.startswith("info:")]
    for name, ok, extra in results:
        _log(f"[selftest] {'PASS' if ok else 'FAIL'} {name}" + (f" — {extra}" if extra and not ok else ""))
    _log(f"[selftest] {sum(1 for _, ok, _ in results if ok)}/{len(results)} checks passed; "
         "offline (loopback only, whisper model NOT loaded/downloaded, no chain requests)")
    return 0 if all(ok for _, ok in core) else 1


def main():
    ap = argparse.ArgumentParser(description="rc_jsdom solver: Face A audio chain + Face B audio API (DESIGN.md §7)")
    # Face A
    ap.add_argument("--url", help="Face A: target page URL (sitekey is derived from it / overridden by --sitekey)")
    ap.add_argument("--sitekey", help="Face A: reCAPTCHA sitekey (default: the public demo key)")
    ap.add_argument("--rounds", type=int, default=4, help="Face A: chain rounds (anchor→reload→solve attempts), default 4")
    ap.add_argument("--audio-retries", type=int, default=4,
                    help="Face A: audio retry budget — folded into --rounds (max of the two; §9.8 one knob)")
    ap.add_argument("--solve-image", action="store_true",
                    help="Face A: solve image challenges via the YOLO/CLIP cascade when the optional deps exist (§9.7)")
    ap.add_argument("--window", default=os.environ.get("RC_WINDOW", "auto"),
                    help="Face A: window runner auto|rust|node|off (§13.2; default RC_WINDOW or auto)")
    ap.add_argument("--window-profile", default=os.environ.get("RC_WINDOW_PROFILE", "chrome-win"),
                    help="Face A: window profile id under window/profiles/ (§13.1)")
    ap.add_argument("--mode", default="demo", help="Face A: demo | link4m (§15)")
    ap.add_argument("--alias", default="", help="Face A: link4m alias (§15.2 check-captcha)")
    ap.add_argument("--code", default="", help="Face A: link4m code (§15.2 check-captcha)")
    ap.add_argument("--fresh-session", help="Face A: path to _fresh_session.json (default: probe ../recaptcha/_fresh_session.json)")
    ap.add_argument("--window-file", help="Face A: path to a WINDOW_JSON (§14.2) produced by "
                    "window-vm emit-window or 'node rc_solve.js --emit-window' — consumed "
                    "instead of spawning a window runner")
    # Face B
    ap.add_argument("--serve", action="store_true", help="run the HTTP service (POST /transcribe)")
    ap.add_argument("--port", type=int, default=5092)
    ap.add_argument("--model", default="tiny.en", help="whisper model: tiny.en (default, ~40MB) | small.en (~250MB)")
    ap.add_argument("--file", help="one-shot: transcribe an MP3 file and print the cleaned transcript")
    ap.add_argument("--selftest", action="store_true", help="offline selftest (loopback only, no model load, no chain requests)")
    # Shim (§13) — called by the Rust engine (window-vm shim.rs), not by rc_solve.js
    ap.add_argument("mode", nargs="?", choices=["transcribe", "classify"],
                    help="shim mode: transcribe (MP3 → cleaned transcript) | classify (JPEG → YOLO/CLIP indices)")
    ap.add_argument("--audio-b64", help="shim transcribe: base64 MP3 bytes ('-' reads stdin)")
    ap.add_argument("--img-b64", help="shim classify: base64 JPEG bytes")
    ap.add_argument("--targets", default="", help='shim classify: comma-separated target labels, e.g. "bus,traffic light"')
    ap.add_argument("--grid", type=int, default=3, help="shim classify: grid size (clamped to the hardcoded 3×3, §9.7)")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if args.mode == "transcribe":
        sys.exit(shim_transcribe(args))
    if args.mode == "classify":
        sys.exit(shim_classify(args))
    if args.file:
        print(transcribe_mp3(args.file, model_size=args.model))
        sys.exit(0)
    if args.serve:
        serve(args.port, args.model)
        return
    if args.url:
        sys.exit(run_chain(args))
    ap.print_help()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
