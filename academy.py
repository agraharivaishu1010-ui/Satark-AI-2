"""Interactive scam-awareness micro-lessons."""
from __future__ import annotations

from typing import Any

ACADEMY_LESSONS: list[dict[str, Any]] = [
    {
        "slug": "upi-collect-request-scam",
        "title": "UPI Collect Request & QR Code Trap",
        "category": "UPI & Payments",
        "summary": "Why you NEVER need a UPI PIN or QR scan to receive money, cashback, or OLX payments.",
        "red_flags": [
            "Buyer or support agent sends a QR code asking you to scan it to 'receive' funds.",
            "App screen shows 'Pay' or asks for your 4/6-digit UPI PIN.",
        ],
        "defense": "UPI PIN is strictly an authorization to DEBIT money from your account—never to credit it.",
    },
    {
        "slug": "lookalike-bank-domains",
        "title": "Spotting Lookalike Bank & KYC Domains",
        "category": "Phishing & URLs",
        "summary": "How attackers hide fake domains behind subdomains like sbi.co.in.kyc-update.xyz.",
        "red_flags": [
            "Trusted brand name appears before a suspicious TLD (.xyz, .top, .click).",
            "Homoglyphs like 'sb1' (digit 1) replacing 'sbi' (letter i).",
        ],
        "defense": "Always read the registrable domain right before the first single '/' — never trust HTTPS alone.",
    },
    {
        "slug": "digital-arrest-and-electricity",
        "title": "Electricity Disconnection & 'Digital Arrest' Scams",
        "category": "Impersonation",
        "summary": "How scammers weaponize fear of immediate power cuts or fake customs/police video calls.",
        "red_flags": [
            "Threat of disconnection tonight at 9:30 PM with a personal 10-digit mobile number.",
            "Video call claiming you are under 'Digital Arrest' and must transfer money to a 'safe RBI account'.",
        ],
        "defense": "Hang up immediately. Verify via official utility apps or dial 1930 / cybercrime.gov.in.",
    },
]
