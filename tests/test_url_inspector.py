import unittest

from app.core.url_inspector import (
    extract_registrable_domain,
    extract_urls_from_text,
    inspect_url_locally,
)


class TestUrlInspector(unittest.TestCase):
    def test_extracts_registrable_domains_and_ipv4(self) -> None:
        self.assertEqual(extract_registrable_domain("portal.sbi.co.in"), ("sbi.co.in", 1))
        self.assertEqual(extract_registrable_domain("a.b.c.example.com"), ("example.com", 3))
        self.assertEqual(extract_registrable_domain("192.168.1.10"), ("192.168.1.10", 0))

    def test_flags_bank_lookalike_and_homoglyph(self) -> None:
        res = inspect_url_locally("https://sbi.co.in.kyc-verify-portal.xyz/login?redirect=http://evil.test")
        self.assertEqual(res["risk_level"], "high")
        self.assertEqual(res["impersonated_brand"], "SBI")
        self.assertEqual(res["registrable_domain"], "kyc-verify-portal.xyz")

        homo = inspect_url_locally("https://sb1-online-verify.xyz/login")
        self.assertEqual(homo["risk_level"], "high")
        self.assertEqual(homo["impersonated_brand"], "SBI")

    def test_recognizes_official_bank_domain(self) -> None:
        res = inspect_url_locally("https://retail.onlinesbi.sbi/")
        self.assertEqual(res["risk_level"], "low")
        self.assertIsNone(res["impersonated_brand"])

    def test_flags_dangerous_uri_schemes(self) -> None:
        for uri in ("javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "file:///etc/passwd"):
            res = inspect_url_locally(uri)
            self.assertEqual(res["risk_level"], "high")
            self.assertTrue(any(s["signal"] == "dangerous_uri_scheme" for s in res["signals"]))

    def test_flags_embedded_credentials_shortener_and_caps_extraction(self) -> None:
        cred = inspect_url_locally("https://sbi.co.in@evil-login.xyz/kyc")
        self.assertTrue(any(s["signal"] == "embedded_credentials_in_url" for s in cred["signals"]))

        short = inspect_url_locally("https://bit.ly/free-prize")
        self.assertTrue(short["is_shortened"])

        many = " ".join(f"https://site-{i}.example.com/p" for i in range(12))
        self.assertEqual(len(extract_urls_from_text(many)), 8)

    def test_detects_one_character_typosquats_and_unicode_homoglyphs(self) -> None:
        typo = inspect_url_locally("https://amazonn.in/signin")
        self.assertEqual(typo["impersonated_brand"], "AMAZON")
        self.assertTrue(any(signal["signal"] == "brand_impersonation" for signal in typo["signals"]))

        unicode = inspect_url_locally("https://раураl.com/login")
        self.assertTrue(unicode["has_punycode_or_idn"])
        self.assertEqual(unicode["risk_level"], "high")

    def test_rejects_malformed_authority_and_oversized_url(self) -> None:
        for value in ("https://example.com:invalid/", "https://trusted.com\\@evil.test/", "https://bad..example.com"):
            result = inspect_url_locally(value)
            self.assertEqual(result["risk_level"], "high")
            self.assertTrue(any(signal["signal"] == "malformed_url" for signal in result["signals"]))

        oversized = inspect_url_locally("https://example.com/" + "a" * 2048)
        self.assertEqual(oversized["risk_index"], 82)
        self.assertTrue(any(signal["signal"] == "oversized_url" for signal in oversized["signals"]))


if __name__ == "__main__":
    unittest.main()
