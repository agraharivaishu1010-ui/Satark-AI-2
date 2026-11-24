import re
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.analyzer import highlight_evidence_in_text
from app.main import app
from app.services.security import SlidingWindowRateLimiter, rate_limiter
from app.services.storage import SessionHistoryStore, history_store


class TestSecurityAndAccessibility(unittest.TestCase):
    def setUp(self) -> None:
        rate_limiter.reset()
        history_store.clear()
        self.client = TestClient(app)

    def test_token_safe_highlighter_escapes_xss_without_nested_marks(self) -> None:
        raw = "<script>alert('xss')</script> Your bank account is blocked."
        out = highlight_evidence_in_text(
            raw,
            [{"text": "bank account is blocked"}, {"text": "blocked"}],
        )
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", out)
        self.assertEqual(out.count("<mark"), 1)

    def test_strict_security_headers_and_static_cache_control(self) -> None:
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["x-frame-options"], "DENY")
        self.assertEqual(resp.headers["x-content-type-options"], "nosniff")
        self.assertEqual(resp.headers["cross-origin-opener-policy"], "same-origin")
        csp = resp.headers["content-security-policy"]
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(resp.headers["cache-control"], "no-store")
        self.assertEqual(resp.headers["cross-origin-resource-policy"], "same-origin")

        css_resp = self.client.get("/static/styles.css")
        self.assertEqual(css_resp.status_code, 200)
        self.assertIn("max-age=86400", css_resp.headers["cache-control"])

    def test_csrf_rejects_missing_or_bad_token_and_accepts_valid_token(self) -> None:
        bad = self.client.post("/scan", data={"text": "Share OTP now"})
        self.assertEqual(bad.status_code, 403)

        home = self.client.get("/")
        csrf = home.cookies.get("satark_csrf")
        self.assertTrue(csrf)
        good = self.client.post("/scan", data={"csrf_token": csrf, "text": "Share OTP immediately"})
        self.assertEqual(good.status_code, 200)
        self.assertIn("High Scam Risk", good.text)

    def test_rate_limiter_enforces_429_with_retry_after(self) -> None:
        orig_max = rate_limiter.max_requests
        rate_limiter.max_requests = 3
        rate_limiter.reset()
        try:
            for _ in range(3):
                self.assertEqual(self.client.get("/api/v1/health").status_code, 200)
            blocked = self.client.get("/api/v1/health")
            self.assertEqual(blocked.status_code, 429)
            self.assertIn("retry-after", blocked.headers)
        finally:
            rate_limiter.max_requests = orig_max
            rate_limiter.reset()

    def test_rate_limiter_bounds_key_storage(self) -> None:
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60, max_keys=1)
        self.assertEqual(limiter.check("one"), (True, 0))
        self.assertEqual(limiter.check("two"), (False, 60))
        self.assertEqual(len(limiter._hits), 1)

    def test_history_store_bounds_sessions_and_feedback(self) -> None:
        store = SessionHistoryStore(max_items_per_session=1, max_sessions=1, max_feedback_per_session=1)
        store.add_scan("first", {"analysis_id": "scan-a"})
        store.add_feedback("first", "scan-a", "accurate")
        store.add_scan("second", {"analysis_id": "scan-b"})
        self.assertEqual(store.list_scans("first"), [])
        self.assertEqual(store.list_scans("second"), [{"analysis_id": "scan-b"}])
        self.assertEqual(store.get_scan("first", "scan-a"), None)

    def test_redirect_preference_rejects_encoded_external_targets(self) -> None:
        response = self.client.get(
            "/prefs/lang?next=%2F%252f%252fevil.example",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/")

    def test_session_isolation_prevents_cross_user_history_leak(self) -> None:
        client_a = TestClient(app)
        client_b = TestClient(app)
        scan = client_a.post("/api/v1/scan", json={"text": "Share OTP immediately"})
        self.assertEqual(scan.status_code, 200)
        aid = scan.json()["analysis_id"]

        self.assertEqual(len(client_a.get("/api/v1/history").json()), 1)
        self.assertEqual(len(client_b.get("/api/v1/history").json()), 0)
        self.assertEqual(client_b.get(f"/api/v1/report/{aid}").status_code, 404)

    def test_accessibility_landmarks_labels_and_zero_inline_scripts(self) -> None:
        for path in ("/", "/url-check", "/screenshot", "/benchmark", "/learn", "/report"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200)
            body = resp.text
            self.assertIn('href="#main-content"', body)
            self.assertIn('aria-label="Main Navigation"', body)
            self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)[^>]*>", body, re.I))
            self.assertIsNone(re.search(r"\bon(?:click|input|change|submit)=", body, re.I))

        css = Path("app/static/styles.css").read_text(encoding="utf-8")
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)
        self.assertIn(":focus-visible", css)


if __name__ == "__main__":
    unittest.main()
