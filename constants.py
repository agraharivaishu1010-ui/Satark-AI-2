"""Shared constants, protected Indian brands, TLDs, categories, and 6 contextual scenarios."""
from __future__ import annotations

from typing import Final

MULTI_PART_TLDS: Final[frozenset[str]] = frozenset({
    "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "edu.in",
    "co.uk", "org.uk", "com.au", "co.jp", "com.sg",
})

SUSPICIOUS_TLDS: Final[frozenset[str]] = frozenset({
    "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
    "buzz", "icu", "vip", "monster", "shop", "live",
})

KNOWN_SHORTENERS: Final[frozenset[str]] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy",
    "cutt.ly", "shorturl.at", "tiny.cc",
})

PROTECTED_BRANDS: Final[dict[str, tuple[str, ...]]] = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbicard.com"),
    "hdfc": ("hdfcbank.com", "hdfc.com"),
    "icici": ("icicibank.com", "icicidirect.com"),
    "axis": ("axisbank.com",),
    "kotak": ("kotak.com", "kotakbank.com"),
    "pnb": ("pnbindia.in", "netpnb.com"),
    "paytm": ("paytm.com", "paytmbank.com"),
    "phonepe": ("phonepe.com",),
    "uidai": ("uidai.gov.in",),
    "aadhaar": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in",),
    "indiapost": ("indiapost.gov.in",),
    "delhivery": ("delhivery.com",),
    "bluedart": ("bluedart.com",),
    "amazon": ("amazon.in", "amazon.com"),
    "paypal": ("paypal.com", "paypal.me"),
    "flipkart": ("flipkart.com",),
}

CATEGORY_META: Final[dict[str, dict[str, str]]] = {
    "bank_impersonation": {"label_en": "Bank Account Impersonation", "label_hi": "बैंक खाता प्रतिरूपण"},
    "kyc_phishing": {"label_en": "KYC Update Phishing", "label_hi": "केवाईसी अपडेट फ़िशिंग"},
    "otp_credential_theft": {"label_en": "OTP or Credential Theft", "label_hi": "ओटीपी और पासवर्ड चोरी"},
    "upi_payment_scam": {"label_en": "UPI & QR Payment Deception", "label_hi": "यूपीआई और क्यूआर भुगतान धोखाधड़ी"},
    "job_scam": {"label_en": "Job & Recruitment Fraud", "label_hi": "नौकरी और भर्ती धोखाधड़ी"},
    "scholarship_scam": {"label_en": "Fake Scholarship Announcement", "label_hi": "नकली छात्रवृत्ति धोखाधड़ी"},
    "prize_lottery_scam": {"label_en": "Prize & Lottery Fraud", "label_hi": "लॉटरी और इनाम धोखाधड़ी"},
    "delivery_scam": {"label_en": "Courier & Parcel Delivery Scam", "label_hi": "कूरियर और पार्सल डिलीवरी स्कैम"},
    "investment_scam": {"label_en": "Investment & Crypto Fraud", "label_hi": "निवेश और क्रिप्टो धोखाधड़ी"},
    "government_impersonation": {"label_en": "Government & Utility Impersonation", "label_hi": "सरकारी या बिजली विभाग प्रतिरूपण"},
    "tech_support_scam": {"label_en": "Remote Access & Tech Support Scam", "label_hi": "रिमोट एक्सेस और कस्टमर केयर स्कैम"},
    "other_suspicious": {"label_en": "Other Suspicious Communication", "label_hi": "अन्य संदिग्ध संदेश"},
    "legitimate_service_notice": {"label_en": "Legitimate Security / OTP Notice", "label_hi": "वैध सुरक्षा / ओटीपी सूचना"},
    "no_strong_indicators": {"label_en": "No Strong Scam Indicators Detected", "label_hi": "कोई मजबूत स्कैम संकेत नहीं मिला"},
}

ANALYSIS_CONTEXTS: Final[dict[str, dict[str, str]]] = {
    "general": {
        "id": "general",
        "label_en": "General / Unsure",
        "label_hi": "सामान्य / अनिश्चित",
        "description_en": "Analyze all threat vectors without prior scenario bias.",
    },
    "banking": {
        "id": "banking",
        "label_en": "Banking & UPI",
        "label_hi": "बैंक और यूपीआई",
        "description_en": "Focus on account blocks, KYC lures, OTP theft, and UPI/QR traps.",
    },
    "employment": {
        "id": "employment",
        "label_en": "Job & Part-Time",
        "label_hi": "नौकरी और पार्ट-टाइम",
        "description_en": "Detect advance fees, fake video-liking tasks, and Telegram recruitment traps.",
    },
    "courier": {
        "id": "courier",
        "label_en": "Courier & Delivery",
        "label_hi": "कूरियर और पार्सल",
        "description_en": "Detect fake India Post, BlueDart, or incomplete-address parcel lures.",
    },
    "utility": {
        "id": "utility",
        "label_en": "Electricity & Govt",
        "label_hi": "बिजली और सरकारी नोटिस",
        "description_en": "Identify power disconnection threats, fake officer numbers, and digital arrests.",
    },
    "lottery": {
        "id": "lottery",
        "label_en": "Lottery & Crypto",
        "label_hi": "लॉटरी और क्रिप्टो",
        "description_en": "Flag guaranteed returns, fake KBC/lucky draws, and processing fee scams.",
    },
}
