"""English and Hindi UI copy for SATARK AI."""
from __future__ import annotations

UI_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "nav_scanner": "Scanner",
        "nav_url": "URL Inspector",
        "nav_screenshot": "Screenshot",
        "nav_benchmark": "Benchmark",
        "nav_learn": "Academy & Quiz",
        "nav_report": "1930 Report",
        "nav_docs": "API Docs",
        "hero_title": "Personal Digital Scam Guardian",
        "hero_sub": "Paste any suspicious SMS, WhatsApp forward, or email in English, Hindi, Hinglish, or Indic scripts. Links are inspected structurally without ever visiting them.",
        "msg_label": "Suspicious Message",
        "ctx_label": "Scenario Context",
        "lang_label": "Language",
        "btn_analyze": "Analyze Message",
        "btn_listen": "Read Verdict Aloud",
        "btn_report": "Download Text Report",
        "btn_again": "Scan Another Message",
        "simple_on": "Simple Mode: ON",
        "simple_off": "Simple Mode: OFF",
        "theme_dark": "Dark",
        "theme_light": "Light",
    },
    "hi": {
        "nav_scanner": "स्कैनर",
        "nav_url": "लिंक जांच",
        "nav_screenshot": "स्क्रीनशॉट",
        "nav_benchmark": "बेंचमार्क",
        "nav_learn": "अकादमी और क्विज़",
        "nav_report": "1930 रिपोर्ट",
        "nav_docs": "API डॉक्स",
        "hero_title": "आपका व्यक्तिगत डिजिटल स्कैम सुरक्षा कवच",
        "hero_sub": "कोई भी संदिग्ध SMS, WhatsApp संदेश या ईमेल पेस्ट करें। लिंक को खोले बिना उसकी संरचना की स्थानीय जांच की जाती है।",
        "msg_label": "संदिग्ध संदेश",
        "ctx_label": "संदेश का संदर्भ",
        "lang_label": "भाषा",
        "btn_analyze": "संदेश की जांच करें",
        "btn_listen": "परिणाम सुनें",
        "btn_report": "रिपोर्ट डाउनलोड करें",
        "btn_again": "नया संदेश जांचें",
        "simple_on": "सरल मोड: चालू",
        "simple_off": "सरल मोड: बंद",
        "theme_dark": "डार्क",
        "theme_light": "लाइट",
    },
}


def get_ui_strings(lang: str) -> dict[str, str]:
    return UI_STRINGS["hi"] if lang == "hi" else UI_STRINGS["en"]
