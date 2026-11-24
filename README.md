# SATARK AI 2.2.0 — Personal Digital Scam Guardian

SATARK AI helps ordinary citizens pause and assess suspicious SMS, WhatsApp forwards, emails, and URLs. Its primary vertical is Indian consumer digital safety: banking/UPI, fake jobs, courier delivery, utilities, prizes, impersonation, and social engineering. It is an explainable decision-support tool, not a guarantee that a message or website is safe.

## What it does

- Scans up to 5,000 characters of English, Hindi, Hinglish, Gujarati, Tamil, Bengali, and Marathi text.
- Applies deterministic multilingual rules for urgency, account threats, OTP/PIN/password requests, payment/QR traps, remote-access apps, fake jobs, courier lures, utility impersonation, prizes, and investment promises.
- Extracts at most eight URL-like strings and analyzes each locally. It does not resolve DNS, fetch pages, follow redirects, or contact URL targets.
- Shows matched evidence, category/context advice, and the score contributions. High-risk findings should be independently verified.
- Offers an accessible server-rendered web interface, REST API, awareness lessons, quiz, synthetic regression benchmark, and a 1930 incident worksheet.
- Accepts JPG, PNG, and WebP screenshot uploads for size and file-signature checks. **It does not perform OCR**; users must paste or transcribe visible text into the scanner.

## How scoring works

The displayed risk index is a deterministic, rule-based score. Matched rules add documented weights; URL findings contribute 65% of the highest structural URL index. The ordinary score is capped at 100. Routine urgency by itself is capped at 22, and a benign OTP notice with an explicit do-not-share warning is capped at 15 when no conflicting credential/payment request or risky URL is found. Bands are low (0–29), medium (30–59), and high (60–100). The result exposes rule points, URL points, pre-cap score, cap, matched evidence, and structural signals.

The separate experimental text signal is a small Naive Bayes classifier trained from the bundled synthetic examples. It is **uncalibrated, not independently validated, and does not affect the risk index**. The API retains the legacy `ml_scam_probability` response field for compatibility; `ml_signal_note` explains its limitations. The bundled 19-example benchmark is a regression fixture, not evidence of real-world accuracy.

## Architecture

```text
app/
  main.py                 FastAPI API, server-rendered routes, security/cache middleware
  schemas.py              Pydantic v2 request validation
  core/
    analyzer.py           Language detection, deterministic scoring, explanations
    rules.py              Precompiled multilingual detection rules
    url_inspector.py      Zero-visit URL parsing, brand/domain structural signals
    ml_scorer.py          Experimental sample-based score, separate from risk scoring
    benchmark.py          Synthetic regression benchmark
  services/
    security.py           CSRF helpers and bounded in-process rate limiter
    storage.py            Bounded, session-isolated in-memory history/feedback
    reports.py            Plain-text assessment and incident worksheet
  data/                   Synthetic samples, UI strings, lessons, quiz
  templates/              Autoescaped Jinja2 pages
  static/                 Local CSS, small JS enhancement, icon and PWA assets
tests/                    Pytest-compatible unit and FastAPI TestClient tests
```

## Requirements and local setup

Python 3.10 or newer is supported. Runtime dependencies are in `requirements.txt`; the project metadata also defines optional `test` and `dev` extras.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` for the citizen-facing interface and `/docs` for the OpenAPI reference. To include Ruff checks when developing:

```powershell
python -m pip install -e ".[test,dev]"
ruff check app tests
```

For environments that do not use PowerShell, activate the virtual environment with its platform-specific command. A simple setup without an editable install is also available:

```sh
python -m pip install -r requirements.txt
python -m pytest -q
python -m uvicorn app.main:app --reload
```

## Environment and deployment

`SATARK_COOKIE_SECURE` controls the `Secure` attribute on session and CSRF cookies. It defaults to `false` for local HTTP development; set it to `true` when serving the application over HTTPS. See `.env.example` for the local default. The application does not automatically load `.env` files; set the environment variable in the process environment or deployment configuration.

The built-in rate limiter allows at most 120 requests per observed client address per 60 seconds, and stores state in the current process. The limiter and session history are not shared across worker processes, so put a shared reverse-proxy/API-gateway limiter in front of multi-worker or public deployments. Configure proxy trust carefully so client addresses cannot be forged. Use HTTPS at the edge, set `SATARK_COOKIE_SECURE=true`, and keep access logs free of sensitive request data. The app does not enable cross-origin access (no permissive CORS policy).

## API examples

```sh
curl -s http://127.0.0.1:8000/api/v1/health
curl -s -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text":"Your account will be blocked tonight. Share your OTP immediately.","context_id":"banking"}'
curl -s -X POST http://127.0.0.1:8000/api/v1/url-check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://sbi.co.in.kyc-verify.example.xyz/login"}'
```

Important endpoints: `GET /api/v1/health`, `POST /api/v1/scan`, `GET /api/v1/history`, `POST /api/v1/url-check`, `GET /api/v1/benchmark`, `POST /api/v1/feedback`, `GET /api/v1/report/{analysis_id}`, and `POST /api/v1/report/1930`. Invalid request models return 422, unknown session-owned reports/feedback return 404, oversized uploads return 413, unsupported or mismatched image types return 415, and rate-limited requests return 429 with `Retry-After`.

The API uses a session cookie to scope history and reports. Feedback is accepted only for an analysis in that same session. For the HTML forms, fetch a page to obtain its CSRF cookie/token before submitting. `retain_raw_text` is false by default; enabling it stores the scan text in that session's in-memory history and makes it available in the report.

## Privacy and security

- Message and URL analysis is local to the application process. The analyzer makes no outbound calls.
- Raw message text is redacted in stored scan results by default; explicit retention is opt-in. The application does not write scan history or feedback to a database.
- History is limited to 100 scans per session, 1,000 in-memory sessions, and 100 feedback items per session. Oldest sessions are evicted when the in-process bound is reached; all records disappear when the process exits.
- Dynamic pages and API responses use `Cache-Control: no-store`; the service worker caches only static assets and skips API/sensitive-query requests.
- CSRF-protected HTML POSTs, bounded request models, per-process rate limiting, secure response headers, a restrictive CSP, and upload signature/size checks are enabled. Cookies are `HttpOnly` for the session ID and `SameSite=Lax`; configure `Secure` for HTTPS.
- URL checks parse user input only. Never treat a low score or HTTPS as proof that a URL is safe. Domain ownership uses a small bundled suffix list, not the live Public Suffix List.
- Uploaded screenshots are checked for a declared image MIME type, matching file signature, and size limit, then discarded; no image-to-text extraction is performed.

## Tests and CI

```sh
python -m compileall -q app tests
python -m pytest -q
ruff check app tests
```

Tests cover request validation, multilingual detection, false-positive guards, explainable scores, URL parsing/lookalikes, session privacy, CSRF, headers, rate limiting, screenshot type/size behavior, and major API/web routes. CI runs tests and Ruff on Python 3.10, 3.11, and 3.12.

## Limitations and future work

Rules and examples are curated heuristics, not a guarantee of fraud detection; new scam language, regional variations, benign lookalikes, and novel domains can cause false positives or misses. There is no live threat-intelligence feed, URL reputation lookup, user-trained model, OCR, persistent storage, account system, distributed rate limiter, or independent accuracy evaluation. The bundled suffix list and protected-brand catalog need maintenance. Any future OCR/live-check feature should be opt-in, locally/privacy reviewed, isolated from target networks, and independently tested before being described as available.
