# recaptcha-vm-browserless

recaptcha-vm-browserless is a Rust command line tool that solves reCAPTCHA v2 challenges
without a headless browser. It replays the full Google API chain (anchor → reload →
challenge → userverify) over a TLS-impersonating HTTP client with an in-process JS VM, and
returns a `g-recaptcha-response` token. A small Python shim (`solve_service.py`) provides
the audio transcription (faster-whisper).

Challenges can be solved using the page URL and the sitekey. Audio is the default branch;
image challenges are opt-in. No Chrome, no Selenium, no WebDriver — the solver never
launches a browser.

## Repository layout

| Path | Role |
|---|---|
| `window-vm.exe` | Prebuilt binary (Windows, x64) — run it directly |
| `solve_service.py` | Python shim — transcription (audio) and classification (image) |
| `window/` | Runtime assets: profiles, answers, VM scripts — keep next to the binary |
| `window-vm/` | Rust source, if you want to rebuild |
| `models/yolo_cls_best.pt` | Image-branch classifier (used only with `--solve-image`) |
| `.gitignore` | Excludes dumps, tokens, mp3 captures and build output from commits |

## Browser profiles

The engine impersonates a specific browser, described by a profile file. One is included:
`window/profiles/chrome-win.json` (Chrome 120 on Windows), which is also the default.
Profiles pin the user agent the whole chain sends — a profile whose user agent does not
match the chain's UA fails validation and falls back to `chrome-win`.

Keep each profile with its directory (`window/profiles/`) when you copy. Pass a profile by
name or full path with `--profile`.

## Building

You need the Rust version pinned in `rust-toolchain.toml` (1.99.0), plus CMake, a C/C++
compiler, libclang, and Git (to build BoringSSL). Python 3.9+ with `faster-whisper` is
needed for audio transcription:

```bash
pip install faster-whisper
```

```bash
cd window-vm
cargo build --release --bin window-vm
```

The binary self-locates its assets: keep it next to `window/` and `solve_service.py`
(the repository root). After building, copy `window-vm/target/release/window-vm.exe`
to the root, or run it from there directly.

## Command line tool

Google's official demo page:

```bash
./window-vm.exe solve \
  --url https://www.google.com/recaptcha/api2/demo \
  --sitekey 6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ- \
  --model base.en --rounds 6 \
  --dump-dir dumps
```

link4m (mints the token, then POSTs `check-captcha` for you):

```bash
./window-vm.exe solve \
  --url https://s1.link4m.app \
  --sitekey 6LcQsTQgAAAAADNQ_pCfukfvS0i9lk4oJTVSs5bZ \
  --mode link4m --alias Wcee8Q3 \
  --model base.en --rounds 6 \
  --dump-dir dumps
```

On PowerShell, replace `./` with `.\` and use `$env:TEMP\...` paths.

On success the last stdout line is the result contract — `token` is a real boolean and
stderr carries the proof-of-mint line (`[userverify] -> 200 TOKEN len=…`):

```
RC_SOLVE: {"scrape":"ok","anchor":"ok","reload":"ok","challenge":"acquired-audio","solved":"transcribed","token":true,"injected":"none","error":null}
```

Exit codes: `0` = token minted · `1` = controlled failure (e.g. rounds exhausted) ·
`2` = unexpected error.

With `--dump-dir`, every successful mint writes:

```
dumps/token_<unix>.txt   the raw token — use it immediately
dumps/tokens.log         one line per mint: ts · mode · alias · sitekey · len · file
dumps/challenge.mp3      the winning round's audio
dumps/reload_*.txt       raw round info
```

Tokens are single-use and live ~120 seconds from mint — submit them right away.
Failed rounds write no token file.

## Solving your own site

Any page with a reCAPTCHA v2 widget: pass its URL and sitekey (both demo commands above are
examples of this). Useful additions:

- `--page-context <file>` — JSON `{"head_bloom": …, "page_text": …}` scraped from the page,
  when the site feeds context into the widget.
- `--fresh-session <file>` — a cookie-jar JSON to seed the session instead of warm-up.
- `--proxy http://user:pass@host:port` — routes every request of the session through the
  proxy (no automatic fallback to direct). A dead proxy fails fast with `ProxyConnect`.
- `--solve-image` — enable the image branch (needs the Python vision deps and
  `models/yolo_cls_best.pt`; without it image rounds are skipped and re-rolled).
- `--model tiny.en|base.en|small.en` — whisper size; `base.en` is recommended. If
  `models/faster-whisper-<size>/` exists next to `solve_service.py` it is loaded directly
  from there; otherwise the model downloads on first use (~40–250 MB, once) and is cached
  afterwards. Bundles exceed GitHub's 100 MB file limit, so they stay out of the repo.
- `--rounds` — max attempts; 4–8 works well in practice.
- `--timeout` — whole-run time budget in milliseconds (default 600000).

## link4m notes

`--mode link4m --alias <alias>` mints a token and then POSTs it to the alias page's
`/links/check-captcha`. The acceptor may reply
`{"success":false,...,"info":"Kiểm tra captcha không thành công..."}` when the page session
requires a nonce you have not supplied (`--code`) — the engine prints the reply verbatim and
the minted token itself is still real. Tokens minted for link4m follow the same single-use,
~120 s lifetime.

## Python fallback

The same file is a standalone solver (curl_cffi chain) when the Rust binary is absent:

```bash
python solve_service.py --url https://www.google.com/recaptcha/api2/demo \
  --sitekey 6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ- --model base.en --rounds 4
```

It also exposes the shim faces the engine itself calls, useful for testing:

```bash
python solve_service.py transcribe --file challenge.mp3      # cleaned transcript
python solve_service.py --serve --port 5092                  # POST /transcribe {"audio_b64": …}
python solve_service.py --selftest                           # offline loopback check
```

## Verifying a build

```bash
cd window-vm
cargo test --release
cargo run --release -- --selftest    # offline gate — exit 0 = pass
```
