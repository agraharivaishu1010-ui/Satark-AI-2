"""SATARK AI FastAPI app: CSRF, rate limiting, session isolation, strict CSP, API & bilingual UI."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from app import __version__
from app.core.analyzer import analyze_message
from app.core.benchmark import run_benchmark
from app.core.constants import ANALYSIS_CONTEXTS
from app.core.url_inspector import inspect_url_locally
from app.data.academy import ACADEMY_LESSONS
from app.data.i18n import get_ui_strings
from app.data.quiz import QUIZ_QUESTIONS
from app.data.samples import BENCHMARK_SAMPLES
from app.schemas import FeedbackRequest, IncidentSheetRequest, ScanRequest, UrlCheckRequest
from app.services.body_limit import RequestBodyLimitMiddleware
from app.services.reports import build_1930_incident_sheet, build_text_report
from app.services.security import generate_token, rate_limiter, verify_csrf_token
from app.services.storage import history_store

APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

SESSION_COOKIE = "satark_sid"
CSRF_COOKIE = "satark_csrf"
ALLOWED_IMAGE_TYPES = frozenset({"image/jpeg", "image/png", "image/webp"})
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_MULTIPART_OVERHEAD_BYTES = 64 * 1024


def _environment_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean value.")


COOKIE_SECURE = _environment_bool("SATARK_COOKIE_SECURE", False)
IMAGE_SIGNATURES = {
    "image/jpeg": lambda data: data.startswith(b"\xff\xd8\xff"),
    "image/png": lambda data: data.startswith(b"\x89PNG\r\n\x1a\n"),
    "image/webp": lambda data: len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP",
}
REQUIRED_SCREENSHOT = File(...)

STRICT_CSP = (
    "default-src 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "manifest-src 'self'; "
    "worker-src 'self'"
)


def _apply_security_headers(response: Any, request: Request, path: str) -> Any:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400, stale-while-revalidate=604800"
    else:
        response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers["Content-Security-Policy"] = STRICT_CSP
    return response


class SecurityAndCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Any:
        path = request.url.path
        if path == "/screenshot" and request.method == "POST":
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    request_size = int(content_length)
                except ValueError:
                    response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
                    return _apply_security_headers(response, request, path)
                if request_size < 0:
                    response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
                    return _apply_security_headers(response, request, path)
                if request_size > MAX_UPLOAD_BYTES + MAX_MULTIPART_OVERHEAD_BYTES:
                    response = JSONResponse(
                        status_code=413,
                        content={"detail": "Screenshot request exceeds the 10 MB limit."},
                    )
                    return _apply_security_headers(response, request, path)
        if path.startswith("/api/") or request.method == "POST":
            client_ip = request.client.host if request.client else "local"
            allowed, retry_after = rate_limiter.check(client_ip)
            if not allowed:
                response = JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please retry shortly."},
                    headers={"Retry-After": str(retry_after)},
                )
                return _apply_security_headers(response, request, path)

        response = await call_next(request)
        return _apply_security_headers(response, request, path)


app = FastAPI(
    title="SATARK AI — Personal Digital Scam Guardian",
    version=__version__,
    description="Local-first, explainable multilingual scam detection and zero-visit URL inspection.",
)
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_size=MAX_UPLOAD_BYTES + MAX_MULTIPART_OVERHEAD_BYTES,
)
app.add_middleware(SecurityAndCacheMiddleware)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


def _session_id(request: Request) -> str:
    return request.cookies.get(SESSION_COOKIE) or generate_token(16)


def _csrf_token(request: Request) -> str:
    return request.cookies.get(CSRF_COOKIE) or generate_token(24)


def _attach_session_cookies(response: Any, sid: str, csrf: str) -> Any:
    response.set_cookie(
        SESSION_COOKIE, sid, httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=86400 * 7
    )
    response.set_cookie(
        CSRF_COOKIE, csrf, httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=86400 * 7
    )
    return response


def _require_csrf(request: Request, submitted_token: str) -> None:
    if not verify_csrf_token(request.cookies.get(CSRF_COOKIE), submitted_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token.")


def _safe_next_url(next_url: str) -> str:
    from urllib.parse import unquote, urlsplit

    decoded_path = unquote(next_url)
    parsed = urlsplit(next_url)
    if (
        next_url.startswith("/")
        and not next_url.startswith("//")
        and not decoded_path.startswith(("//", "/\\", "\\\\"))
        and "\\" not in next_url
        and not parsed.scheme
        and not parsed.netloc
        and not any(ord(char) < 32 for char in next_url)
    ):
        return next_url
    return "/"


def _ctx(request: Request, active_nav: str, csrf_token: str, **extra: Any) -> dict[str, Any]:
    lang = "hi" if request.cookies.get("satark_lang") == "hi" else "en"
    simple = request.query_params.get("simple") == "1" or request.cookies.get("satark_simple") == "1"
    theme = request.cookies.get("satark_theme", "auto")
    if theme not in ("light", "dark", "auto"):
        theme = "auto"
    return {
        "request": request,
        "active_nav": active_nav,
        "csrf_token": csrf_token,
        "lang": lang,
        "ui": get_ui_strings(lang),
        "simple_mode": simple,
        "theme": theme,
        "contexts": ANALYSIS_CONTEXTS,
        **extra,
    }


# ---------------------------------------------------------------------------
# PWA Manifest & Service Worker
# ---------------------------------------------------------------------------

@app.get("/manifest.webmanifest")
def pwa_manifest() -> FileResponse:
    return FileResponse(APP_DIR / "static" / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js")
def pwa_service_worker() -> FileResponse:
    return FileResponse(APP_DIR / "static" / "sw.js", media_type="application/javascript")


# ---------------------------------------------------------------------------
# Preference Toggles (Zero-JS Cookie Persistence)
# ---------------------------------------------------------------------------

@app.get("/prefs/lang")
def toggle_lang(request: Request, next: str = "/") -> RedirectResponse:
    current = request.cookies.get("satark_lang", "en")
    resp = RedirectResponse(url=_safe_next_url(next), status_code=303)
    resp.set_cookie("satark_lang", "hi" if current != "hi" else "en", samesite="lax", max_age=86400 * 30)
    return resp


@app.get("/prefs/simple")
def toggle_simple(request: Request, next: str = "/") -> RedirectResponse:
    current = request.cookies.get("satark_simple", "0")
    resp = RedirectResponse(url=_safe_next_url(next), status_code=303)
    resp.set_cookie("satark_simple", "0" if current == "1" else "1", samesite="lax", max_age=86400 * 30)
    return resp


@app.get("/prefs/theme")
def toggle_theme(request: Request, next: str = "/") -> RedirectResponse:
    current = request.cookies.get("satark_theme", "light")
    resp = RedirectResponse(url=_safe_next_url(next), status_code=303)
    resp.set_cookie("satark_theme", "dark" if current != "dark" else "light", samesite="lax", max_age=86400 * 30)
    return resp


# ---------------------------------------------------------------------------
# JSON REST API Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/health")
def api_health() -> dict[str, str]:
    return {"status": "ok", "service": "satark-ai", "version": __version__}


@app.post("/api/v1/scan")
def api_scan_message(request: Request, payload: ScanRequest) -> JSONResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    result = analyze_message(
        text=payload.text,
        language_hint=payload.language_hint,
        context_id=payload.context_id,
        retain_raw_text=payload.retain_raw_text,
    )
    history_store.add_scan(sid, result)
    return _attach_session_cookies(JSONResponse(content=result), sid, csrf)


@app.get("/api/v1/history")
def api_history(request: Request) -> list[dict[str, Any]]:
    sid = request.cookies.get(SESSION_COOKIE)
    return history_store.list_scans(sid) if sid else []


@app.post("/api/v1/url-check")
def api_check_url(payload: UrlCheckRequest) -> dict[str, Any]:
    return inspect_url_locally(payload.url)


@app.get("/api/v1/benchmark")
def api_benchmark() -> dict[str, Any]:
    return run_benchmark(BENCHMARK_SAMPLES)


@app.post("/api/v1/feedback")
def api_feedback(request: Request, payload: FeedbackRequest) -> JSONResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    if history_store.get_scan(sid, payload.analysis_id) is None:
        raise HTTPException(status_code=404, detail="Analysis record not found for this session.")
    record = history_store.add_feedback(sid, payload.analysis_id, payload.assessment)
    return _attach_session_cookies(JSONResponse(content=record), sid, csrf)


@app.get("/api/v1/report/{analysis_id}", response_class=PlainTextResponse)
def api_download_report(request: Request, analysis_id: str) -> PlainTextResponse:
    sid = request.cookies.get(SESSION_COOKIE)
    item = history_store.get_scan(sid, analysis_id) if sid else None
    if not item:
        raise HTTPException(status_code=404, detail="Analysis record not found for this session.")
    return PlainTextResponse(
        content=build_text_report(item),
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}-satark-report.txt"'},
    )


@app.post("/api/v1/report/1930", response_class=PlainTextResponse)
def api_1930_worksheet(payload: IncidentSheetRequest) -> PlainTextResponse:
    return PlainTextResponse(
        content=build_1930_incident_sheet(
            date=payload.date,
            amount=payload.amount,
            utr=payload.utr,
            suspect_id=payload.suspect_id,
            platform=payload.platform,
            notes=payload.notes,
        ),
        headers={"Content-Disposition": 'attachment; filename="satark-1930-incident-worksheet.txt"'},
    )


# ---------------------------------------------------------------------------
# Server-Rendered Accessible HTML Routes (CSRF-Protected, Zero-JS Core)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def page_home(request: Request) -> HTMLResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    resp = templates.TemplateResponse(
        request=request,
        name="index.html",
        context=_ctx(
            request, "home", csrf, samples=BENCHMARK_SAMPLES[:4], history=history_store.list_scans(sid)[:5]
        ),
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.post("/scan", response_class=HTMLResponse)
def page_scan_submit(
    request: Request,
    csrf_token: str = Form(""),
    text: str = Form(..., max_length=5000),
    language_hint: Literal["auto", "en", "hi", "hinglish", "gu", "ta", "bn", "mr"] = Form("auto"),
    context_id: Literal["general", "banking", "employment", "courier", "utility", "lottery"] = Form("general"),
    retain_raw_text: str = Form("0"),
) -> HTMLResponse:
    _require_csrf(request, csrf_token)
    if not text.strip():
        raise HTTPException(status_code=422, detail="Message text must not be blank.")
    sid = _session_id(request)
    csrf = _csrf_token(request)
    result = analyze_message(
        text=text,
        language_hint=language_hint,
        context_id=context_id,
        retain_raw_text=(retain_raw_text == "1"),
    )
    history_store.add_scan(sid, result)
    resp = templates.TemplateResponse(
        request=request, name="result.html", context=_ctx(request, "home", csrf, result=result)
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.get("/url-check", response_class=HTMLResponse)
def page_url_check(request: Request, url: str = "") -> HTMLResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    result = inspect_url_locally(url) if url.strip() else None
    resp = templates.TemplateResponse(
        request=request, name="url_check.html", context=_ctx(request, "url", csrf, url=url, result=result)
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.post("/url-check", response_class=HTMLResponse)
def page_url_check_post(
    request: Request,
    csrf_token: str = Form(""),
    url: str = Form(..., max_length=2048),
) -> HTMLResponse:
    _require_csrf(request, csrf_token)
    if not url.strip():
        raise HTTPException(status_code=422, detail="URL must not be blank.")
    sid = _session_id(request)
    csrf = _csrf_token(request)
    result = inspect_url_locally(url)
    resp = templates.TemplateResponse(
        request=request, name="url_check.html", context=_ctx(request, "url", csrf, url=url, result=result)
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.get("/screenshot", response_class=HTMLResponse)
def page_screenshot(request: Request) -> HTMLResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    resp = templates.TemplateResponse(
        request=request,
        name="screenshot.html",
        context=_ctx(request, "screenshot", csrf, notice=None, extracted_text=""),
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.post("/screenshot", response_class=HTMLResponse)
async def page_screenshot_upload(
    request: Request,
    csrf_token: str = Form(""),
    file: UploadFile = REQUIRED_SCREENSHOT,
) -> HTMLResponse:
    _require_csrf(request, csrf_token)
    sid = _session_id(request)
    csrf = _csrf_token(request)
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=415, detail="Only JPG, PNG, or WebP screenshots are accepted.")
    raw_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Screenshot exceeds the 10 MB safety limit.")
    if not IMAGE_SIGNATURES[file.content_type](raw_bytes):
        raise HTTPException(status_code=415, detail="Screenshot content does not match its declared image type.")
    filename = re.sub(r"[\x00-\x1f\x7f]", "", Path(file.filename or "screenshot").name)[:80]
    notice = (
        f"Validated '{filename or 'screenshot'}' ({len(raw_bytes):,} bytes, {file.content_type}). "
        "OCR is not implemented; paste or edit the visible text below to run a full scan."
    )
    resp = templates.TemplateResponse(
        request=request,
        name="screenshot.html",
        context=_ctx(request, "screenshot", csrf, notice=notice, extracted_text=""),
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.get("/benchmark", response_class=HTMLResponse)
def page_benchmark(request: Request) -> HTMLResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    report = run_benchmark(BENCHMARK_SAMPLES)
    resp = templates.TemplateResponse(
        request=request, name="benchmark.html", context=_ctx(request, "benchmark", csrf, report=report)
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.get("/learn", response_class=HTMLResponse)
def page_learn(request: Request) -> HTMLResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    resp = templates.TemplateResponse(
        request=request,
        name="learn.html",
        context=_ctx(request, "learn", csrf, lessons=ACADEMY_LESSONS, questions=QUIZ_QUESTIONS, quiz_result=None),
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.post("/learn/quiz", response_class=HTMLResponse)
def page_quiz_submit(
    request: Request,
    csrf_token: str = Form(""),
    q1: str = Form(""),
    q2: str = Form(""),
    q3: str = Form(""),
) -> HTMLResponse:
    _require_csrf(request, csrf_token)
    sid = _session_id(request)
    csrf = _csrf_token(request)
    answers = {"q1": q1, "q2": q2, "q3": q3}
    score = sum(1 for q in QUIZ_QUESTIONS if answers.get(q["id"]) == q["answer"])
    resp = templates.TemplateResponse(
        request=request,
        name="learn.html",
        context=_ctx(
            request,
            "learn",
            csrf,
            lessons=ACADEMY_LESSONS,
            questions=QUIZ_QUESTIONS,
            quiz_result={"score": score, "total": len(QUIZ_QUESTIONS), "answers": answers},
        ),
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.get("/report", response_class=HTMLResponse)
def page_report(request: Request) -> HTMLResponse:
    sid = _session_id(request)
    csrf = _csrf_token(request)
    resp = templates.TemplateResponse(
        request=request, name="report.html", context=_ctx(request, "report", csrf, worksheet=None)
    )
    return _attach_session_cookies(resp, sid, csrf)


@app.post("/report", response_class=HTMLResponse)
def page_report_submit(
    request: Request,
    csrf_token: str = Form(""),
    date: str = Form(""),
    amount: str = Form(""),
    utr: str = Form(""),
    suspect_id: str = Form(""),
    platform: str = Form("WhatsApp / SMS"),
    notes: str = Form(""),
) -> HTMLResponse:
    _require_csrf(request, csrf_token)
    sid = _session_id(request)
    csrf = _csrf_token(request)
    sheet = build_1930_incident_sheet(date, amount, utr, suspect_id, platform, notes)
    resp = templates.TemplateResponse(
        request=request, name="report.html", context=_ctx(request, "report", csrf, worksheet=sheet)
    )
    return _attach_session_cookies(resp, sid, csrf)
