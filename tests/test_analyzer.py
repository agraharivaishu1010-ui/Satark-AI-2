import unittest

from app.core.analyzer import analyze_message, detect_language
from app.core.benchmark import run_benchmark
from app.data.samples import BENCHMARK_SAMPLES


class TestAnalyzer(unittest.TestCase):
    def test_detects_indic_hindi_hinglish_and_explicit_hint(self) -> None:
        self.assertEqual(detect_language("आपका बैंक खाता ब्लॉक हो जाएगा"), "hi")
        self.assertEqual(detect_language("Aapka bank khata aaj raat block ho jayega abhi KYC karo"), "hinglish")
        self.assertEqual(detect_language("તમારું ખાતું બંધ થઈ જશે"), "gu")
        self.assertEqual(detect_language("உங்கள் வங்கி கணக்கு"), "ta")
        self.assertEqual(detect_language("আপনার ব্যাংক অ্যাকাউন্ট"), "bn")
        self.assertEqual(detect_language("Hello world", hint="hi"), "hi")

    def test_legitimate_otp_notice_stays_low_risk(self) -> None:
        res = analyze_message(
            "Your OTP for SBI YONO login is 482910. Valid for 10 minutes. NEVER share your OTP or ATM PIN with anyone."
        )
        self.assertEqual(res["risk_level"], "low")
        self.assertEqual(res["category"], "legitimate_service_notice")
        self.assertEqual(res["risk_breakdown"]["risk_index"], res["risk_index"])
        self.assertNotEqual(res["ml_signal_note"], "")

    def test_warning_does_not_hide_a_conflicting_otp_request(self) -> None:
        res = analyze_message(
            "Your OTP for SBI login is 482910. Never share your OTP. Reply with your OTP to verify your account."
        )
        self.assertEqual(res["risk_level"], "high")
        self.assertTrue(any(item["type"] == "credential_request" for item in res["evidence"]))

    def test_routine_workplace_urgency_stays_low_risk(self) -> None:
        res = analyze_message("Urgent reminder: please submit Q3 slides before 5 PM today.")
        self.assertEqual(res["risk_level"], "low")

    def test_all_19_benchmark_samples_classify_accurately(self) -> None:
        report = run_benchmark(BENCHMARK_SAMPLES)
        self.assertEqual(report["total"], 19)
        self.assertEqual(report["confusion"]["fp"], 0)
        self.assertEqual(report["confusion"]["fn"], 0)
        self.assertEqual(report["accuracy_label"], "100%")

    def test_contextual_advisory_tailors_job_utility_and_courier(self) -> None:
        job = analyze_message("Earn Rs 5000 per day liking YouTube videos", context_id="employment")
        self.assertEqual(job["contextual_advisory"]["context_id"], "employment")
        self.assertEqual(len(job["contextual_advisory"]["dimensions"]), 6)

        util = analyze_message("Electricity power will be disconnected tonight at 9:30 PM", context_id="utility")
        self.assertEqual(util["contextual_advisory"]["context_id"], "utility")

        courier = analyze_message("Parcel held due to incomplete house address", context_id="courier")
        self.assertEqual(courier["contextual_advisory"]["context_id"], "courier")

    def test_privacy_default_redacts_raw_text(self) -> None:
        res = analyze_message("Share your 6-digit OTP immediately")
        self.assertEqual(res["raw_text"], "[Redacted by User Privacy Preference]")

    def test_explicit_retention_is_opt_in(self) -> None:
        text = "Share your 6-digit OTP immediately"
        self.assertEqual(analyze_message(text)["raw_text"], "[Redacted by User Privacy Preference]")
        self.assertEqual(analyze_message(text, retain_raw_text=True)["raw_text"], text)


if __name__ == "__main__":
    unittest.main()
