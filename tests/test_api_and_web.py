import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import FeedbackRequest, ScanRequest, UrlCheckRequest
from app.services.security import rate_limiter
from app.services.storage import history_store


class TestApiAndWebRoutes(unittest.TestCase):
    def setUp(self) -> None:
        rate_limiter.reset()
        history_store.clear()
        self.client = TestClient(app)

    def test_health_scan_ml_signal_and_report_download(self) -> None:
        h = self.client.get("/api/v1/health")
        self.assertEqual(h.status_code, 200)
        self.assertEqual(h.json()["status"], "ok")
        self.assertEqual(h.json()["version"], app.version)

        scan = self.client.post(
            "/api/v1/scan",
            json={
                "text": "URGENT: Your SBI account will be blocked. Update KYC at http://sbi-kyc.xyz",
                "context_id": "banking",
            },
        )
        self.assertEqual(scan.status_code, 200)
        data = scan.json()
        self.assertEqual(data["risk_level"], "high")
        self.assertEqual(data["raw_text"], "[Redacted by User Privacy Preference]")
        self.assertGreaterEqual(data["ml_scam_probability"], 0.5)

        rep = self.client.get(f"/api/v1/report/{data['analysis_id']}")
        self.assertEqual(rep.status_code, 200)
        self.assertIn("SATARK AI", rep.text)

    def test_negative_api_validation_422_and_404(self) -> None:
        self.assertEqual(self.client.post("/api/v1/scan", json={"text": ""}).status_code, 422)
        self.assertEqual(self.client.post("/api/v1/scan", json={"text": "a" * 5001}).status_code, 422)
        self.assertEqual(
            self.client.post("/api/v1/feedback", json={"analysis_id": "bad id!", "assessment": "accurate"}).status_code,
            422,
        )
        self.assertEqual(self.client.get("/api/v1/report/scan-doesnotexist").status_code, 404)

    def test_url_check_benchmark_feedback_1930_and_pwa_routes(self) -> None:
        u = self.client.post("/api/v1/url-check", json={"url": "https://sb1-kyc.xyz/login"})
        self.assertEqual(u.status_code, 200)
        self.assertEqual(u.json()["risk_level"], "high")

        bm = self.client.get("/api/v1/benchmark")
        self.assertEqual(bm.status_code, 200)
        self.assertEqual(bm.json()["total"], 19)

        scan = self.client.post("/api/v1/scan", json={"text": "Share your OTP immediately"})
        fb = self.client.post(
            "/api/v1/feedback",
            json={"analysis_id": scan.json()["analysis_id"], "assessment": "accurate"},
        )
        self.assertEqual(fb.status_code, 200)

        sheet = self.client.post("/api/v1/report/1930", json={"amount": "15000", "utr": "123456789012"})
        self.assertEqual(sheet.status_code, 200)
        self.assertIn("123456789012", sheet.text)

        self.assertEqual(self.client.get("/manifest.webmanifest").status_code, 200)
        self.assertEqual(self.client.get("/sw.js").status_code, 200)

    def test_preference_toggles_and_all_csrf_protected_forms(self) -> None:
        self.assertEqual(self.client.get("/prefs/lang?next=/", follow_redirects=False).status_code, 303)
        hi_home = self.client.get("/")
        self.assertIn("स्कैनर", hi_home.text)

        self.assertEqual(self.client.get("/prefs/simple?next=/", follow_redirects=False).status_code, 303)
        self.assertIn("simple-safety-mode", self.client.get("/").text)

        self.assertEqual(self.client.get("/prefs/theme?next=/", follow_redirects=False).status_code, 303)
        self.assertIn("theme-dark", self.client.get("/").text)

        csrf = hi_home.cookies.get("satark_csrf")
        post_url = self.client.post("/url-check", data={"csrf_token": csrf, "url": "https://hdfcbank.com.login.xyz/"})
        self.assertEqual(post_url.status_code, 200)
        self.assertIn("login.xyz", post_url.text)

        post_quiz = self.client.post(
            "/learn/quiz",
            data={"csrf_token": csrf, "q1": "legitimate", "q2": "scam", "q3": "scam"},
        )
        self.assertEqual(post_quiz.status_code, 200)
        self.assertIn("3 / 3", post_quiz.text)

        post_rep = self.client.post("/report", data={"csrf_token": csrf, "amount": "5000", "utr": "999888777666"})
        self.assertEqual(post_rep.status_code, 200)
        self.assertIn("999888777666", post_rep.text)

        bad_file = self.client.post(
            "/screenshot",
            data={"csrf_token": csrf},
            files={"file": ("malware.exe", b"MZ...", "application/octet-stream")},
        )
        self.assertEqual(bad_file.status_code, 415)

        spoofed_file = self.client.post(
            "/screenshot",
            data={"csrf_token": csrf},
            files={"file": ("spoof.png", b"MZ-not-a-png", "image/png")},
        )
        self.assertEqual(spoofed_file.status_code, 415)

        good_file = self.client.post(
            "/screenshot",
            data={"csrf_token": csrf},
            files={
                "file": (
                    "sms.png",
                    bytes.fromhex(
                        "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C489"
                        "0000000B49444154789C636000020000050001A5F645400000000049454E44AE426082"
                    ),
                    "image/png",
                )
            },
        )
        self.assertEqual(good_file.status_code, 200)
        self.assertIn("sms.png", good_file.text)
        self.assertIn("OCR is not implemented", good_file.text)

    def test_schema_validation_strips_blank_text_and_forbids_unknown_fields(self) -> None:
        with self.assertRaises(ValueError):
            ScanRequest(text="   ")
        with self.assertRaises(ValueError):
            ScanRequest(text="hello", unexpected="value")
        with self.assertRaises(ValueError):
            FeedbackRequest(analysis_id="bad id", assessment="accurate")
        with self.assertRaises(ValueError):
            UrlCheckRequest(url="  ")

    def test_feedback_requires_a_scan_in_the_same_session(self) -> None:
        response = self.client.post(
            "/api/v1/feedback",
            json={"analysis_id": "scan-1234", "assessment": "accurate"},
        )
        self.assertEqual(response.status_code, 404)

    def test_default_history_redacts_message_and_sensitive_url_content(self) -> None:
        marker = "private-token-should-not-be-retained"
        scan = self.client.post(
            "/api/v1/scan",
            json={"text": f"Check https://example.com/?token={marker} and share your OTP"},
        )
        self.assertEqual(scan.status_code, 200)
        self.assertIn(marker, scan.json()["extracted_urls"][0]["submitted_url"])

        history = self.client.get("/api/v1/history")
        self.assertEqual(history.status_code, 200)
        self.assertNotIn(marker, str(history.json()))
        self.assertEqual(
            history.json()[0]["extracted_urls"][0]["submitted_url"],
            "[Redacted by User Privacy Preference]",
        )

    def test_form_rejects_blank_scan_and_invalid_context(self) -> None:
        home = self.client.get("/")
        csrf = home.cookies.get("satark_csrf")
        blank = self.client.post("/scan", data={"csrf_token": csrf, "text": "   "})
        self.assertEqual(blank.status_code, 422)
        invalid_context = self.client.post(
            "/scan",
            data={"csrf_token": csrf, "text": "hello", "context_id": "not-a-context"},
        )
        self.assertEqual(invalid_context.status_code, 422)

    def test_upload_rejects_oversized_content_length_early(self) -> None:
        response = self.client.post(
            "/screenshot",
            content=b"",
            headers={"content-length": str(11 * 1024 * 1024)},
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_body_limit_catches_oversized_stream_without_content_length(self) -> None:
        body_chunk = b"a" * (10 * 1024 * 1024 + 128 * 1024)
        response = self.client.post(
            "/api/v1/url-check",
            content=iter((b'{"url":"', body_chunk, b'"}')),
            headers={"content-type": "application/json"},
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
