"""Multilingual language detection, 6-dimension contextual advisor, hybrid analyzer & token-safe highlighter."""
from __future__ import annotations

import html
import re
import secrets
from datetime import datetime, timezone
from typing import Any

from app.core.constants import ANALYSIS_CONTEXTS, CATEGORY_META
from app.core.ml_scorer import ml_classifier
from app.core.rules import (
    CLIENT_RULES,
    OTP_CODE_MENTION_PATTERN,
    SAFE_OTP_NOTICE_PATTERN,
)
from app.core.url_inspector import extract_urls_from_text, inspect_url_locally

HINGLISH_MARKERS = re.compile(
    r"\b(aapka|aapne|apna|abhi|turant|karo|karein|kijiye|bhejo|khata|bijli|raat|baje|"
    r"jayega|gaya|hai|mein|jeeti|kamayein|roz|dalein|dalo|karke|nahi|mat)\b",
    re.IGNORECASE,
)
NEGATED_CREDENTIAL_PREFIX = re.compile(
    r"(?:\bnever\b|\bdo\s+not\b|\bdon't\b|\bnot\b|कभी(?:\s+भी)?|नहीं|मत)\W*$",
    re.IGNORECASE,
)
NEGATED_CREDENTIAL_SUFFIX = re.compile(r"(?:\bन\s+करें\b|\bन\s+करो\b|\bमत\b)", re.IGNORECASE)


def _is_negated_credential_request(text: str, start: int, end: int) -> bool:
    prefix = text[max(0, start - 32):start]
    suffix = text[end:min(len(text), end + 32)]
    return bool(NEGATED_CREDENTIAL_PREFIX.search(prefix) or NEGATED_CREDENTIAL_SUFFIX.search(suffix))


def detect_language(text: str, hint: str = "auto") -> str:
    """Detects English, Hindi (Devanagari), Hinglish, or Indic scripts (GU/TA/BN/MR)."""
    if hint and hint != "auto" and hint in {"en", "hi", "hinglish", "gu", "ta", "bn", "mr"}:
        return hint
    if not text:
        return "en"
    if any("\u0A80" <= ch <= "\u0AFF" for ch in text):
        return "gu"
    if any("\u0B80" <= ch <= "\u0BFF" for ch in text):
        return "ta"
    if any("\u0980" <= ch <= "\u09FF" for ch in text):
        return "bn"
    if any("\u0900" <= ch <= "\u097F" for ch in text):
        if any(w in text for w in ("आहे", "होईल", "करा", "शेअर", "खाते")):
            return "mr"
        return "hi"
    if len(HINGLISH_MARKERS.findall(text)) >= 2:
        return "hinglish"
    return "en"


def highlight_evidence_in_text(raw_text: str, evidence_list: list[dict[str, Any]]) -> str:
    """Token-safe, non-overlapping HTML evidence highlighter that escapes all untrusted text first."""
    if not raw_text:
        return "<em>No raw message text stored.</em>"
    if raw_text == "[Redacted by User Privacy Preference]":
        return (
            '<span class="muted italic">[Redacted by User Privacy Preference — '
            "Enable in Settings to retain message text locally]</span>"
        )
    phrases = sorted(
        {
            str(e.get("text", "")).strip()
            for e in (evidence_list or [])
            if isinstance(e, dict) and len(str(e.get("text", "")).strip()) >= 2
        },
        key=len,
        reverse=True,
    )
    if not phrases:
        return html.escape(raw_text, quote=True)

    lower_text = raw_text.lower()
    intervals: list[list[int]] = []
    for phrase in phrases:
        lp = phrase.lower()
        pos = 0
        while (pos := lower_text.find(lp, pos)) != -1:
            intervals.append([pos, pos + len(lp)])
            pos += max(1, len(lp))

    if not intervals:
        return html.escape(raw_text, quote=True)

    intervals.sort(key=lambda pair: (pair[0], pair[1]))
    merged: list[list[int]] = [intervals[0]]
    for start, end in intervals[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        if start > cursor:
            parts.append(html.escape(raw_text[cursor:start], quote=True))
        parts.append(f'<mark class="evidence-mark">{html.escape(raw_text[start:end], quote=True)}</mark>')
        cursor = end
    if cursor < len(raw_text):
        parts.append(html.escape(raw_text[cursor:], quote=True))
    return "".join(parts)


def get_simple_safety_guidance(risk_level: str, is_hindi: bool = False) -> dict[str, Any]:
    """Plain-language safety steps for Simple Safety Mode."""
    table = {
        "high": {
            "en": {
                "title": "Treat this message as unsafe.",
                "steps": [
                    "Do not click its links or reply.",
                    "Never share an OTP, UPI PIN, password, or payment.",
                    "Contact the organization using its official app or a number you already trust.",
                ],
            },
            "hi": {
                "title": "इस संदेश को असुरक्षित मानें।",
                "steps": [
                    "इसके लिंक पर क्लिक न करें और जवाब न दें।",
                    "ओटीपी, यूपीआई पिन, पासवर्ड या पैसे साझा न करें।",
                    "संस्था से उसके आधिकारिक ऐप या भरोसेमंद नंबर से संपर्क करें।",
                ],
            },
        },
        "medium": {
            "en": {
                "title": "Pause and verify before acting.",
                "steps": [
                    "Check the sender using an official website or app you open yourself.",
                    "Do not rush because of a deadline or warning.",
                    "Never enter codes or payment details from a forwarded link.",
                ],
            },
            "hi": {
                "title": "कोई भी कदम उठाने से पहले जांच करें।",
                "steps": [
                    "आधिकारिक ऐप या वेबसाइट खुद खोलकर प्रेषक की पुष्टि करें।",
                    "समय-सीमा या चेतावनी से घबराकर जल्दबाजी न करें।",
                    "किसी भी फॉरवर्ड लिंक पर कोड या भुगतान विवरण न भरें।",
                ],
            },
        },
        "low": {
            "en": {
                "title": "No strong scam indicators found, but stay cautious.",
                "steps": [
                    "Verify unexpected requests for money or personal details.",
                    "Only sign in through official apps or bookmarked websites.",
                ],
            },
            "hi": {
                "title": "कोई मजबूत स्कैम संकेत नहीं मिला, फिर भी सतर्क रहें।",
                "steps": [
                    "पैसे या निजी जानकारी की किसी भी अनपेक्षित मांग की पुष्टि करें।",
                    "केवल आधिकारिक ऐप या वेबसाइट पर ही लॉग इन करें।",
                ],
            },
        },
    }
    lang = "hi" if is_hindi else "en"
    return table.get(risk_level, table["low"])[lang]


def evaluate_contextual_dimensions(
    text: str,
    context_id: str,
    category: str,
    evidence: list[dict[str, Any]],
    url_results: list[dict[str, Any]],
    is_safe_otp: bool,
) -> dict[str, Any]:
    """Evaluates all 6 contextual intent dimensions and builds scenario-tailored guidance."""
    ev_types = {e["type"] for e in evidence}
    has_bad_url = any(u["risk_level"] in ("high", "medium") for u in url_results)

    dimensions = {
        "sender_authenticity": "official_safety_notice" if is_safe_otp else ("spoofed_or_unverified" if ("impersonation" in ev_types or has_bad_url) else "unverified"),
        "urgency_pressure": "high" if "urgency" in ev_types else "low",
        "credential_or_payment_ask": "high" if ({"credential_request", "payment_request", "remote_access"} & ev_types) else "none",
        "link_and_channel_risk": "high" if any(u["risk_level"] == "high" for u in url_results) else ("medium" if has_bad_url else "low"),
        "scenario_alignment": context_id if context_id in ANALYSIS_CONTEXTS else "general",
        "legitimacy_safeguards": "present" if is_safe_otp else "absent",
    }

    advisory_map = {
        "employment": {
            "headline": "Job & Part-Time Recruitment Advisory",
            "advice": [
                "Legitimate employers never charge a refundable registration or onboarding fee.",
                "Ignore Telegram/WhatsApp 'like YouTube videos' or prepaid-task offers.",
                "Verify the recruiter's official corporate email domain and LinkedIn presence.",
            ],
        },
        "utility": {
            "headline": "Electricity & Government Notice Advisory",
            "advice": [
                "Electricity boards never threaten same-night disconnection via personal 10-digit mobile numbers.",
                "Law enforcement agencies never conduct 'Digital Arrest' over video calls.",
                "Check your bill status directly in your state DISCOM app or BBPS portal.",
            ],
        },
        "courier": {
            "headline": "Courier & Parcel Delivery Advisory",
            "advice": [
                "Never pay a ₹5–₹50 'redelivery fee' through an SMS link—it is used to harvest card/UPI credentials.",
                "Track parcels only on official carrier sites (indiapost.gov.in, bluedart.com, delhivery.com).",
            ],
        },
        "banking": {
            "headline": "Banking & UPI Safety Advisory",
            "advice": [
                "You NEVER need to enter a UPI PIN or scan a QR code to receive money or cashback.",
                "Banks never ask for KYC updates over SMS links or ask you to share an OTP.",
                "If money was debited, call 1930 immediately and report at cybercrime.gov.in.",
            ],
        },
        "lottery": {
            "headline": "Lottery & Crypto Investment Advisory",
            "advice": [
                "You cannot win a lottery or KBC draw you never entered—never pay GST or processing charges.",
                "Treat any 'guaranteed daily return' or VIP crypto signal group as fraud.",
            ],
        },
        "general": {
            "headline": "General Scam Verification Advisory",
            "advice": [
                "Pause before acting on urgent threats, rewards, or unexpected links.",
                "Verify through an official app or trusted phone number you already have.",
            ],
        },
    }

    effective_ctx = context_id if context_id in advisory_map and context_id != "general" else (
        "employment" if category == "job_scam" else
        "utility" if category == "government_impersonation" else
        "courier" if category == "delivery_scam" else
        "banking" if category in {"bank_impersonation", "kyc_phishing", "otp_credential_theft", "upi_payment_scam"} else
        "lottery" if category in {"prize_lottery_scam", "investment_scam"} else
        "general"
    )
    ctx_info = advisory_map[effective_ctx]
    return {
        "context_id": effective_ctx,
        "headline": ctx_info["headline"],
        "dimensions": dimensions,
        "tailored_advice": ctx_info["advice"],
    }


def analyze_message(
    text: str,
    language_hint: str = "auto",
    context_id: str = "general",
    retain_raw_text: bool = False,
) -> dict[str, Any]:
    """Runs deterministic multilingual rules, zero-visit URL inspection, and contextual scoring."""
    clean = (text or "").strip()
    detected_lang = detect_language(clean, language_hint)
    urls = extract_urls_from_text(clean)
    url_results = [inspect_url_locally(u) for u in urls]

    is_safe_otp = bool(SAFE_OTP_NOTICE_PATTERN.search(clean) and OTP_CODE_MENTION_PATTERN.search(clean))
    has_bad_url = any(u["risk_level"] in ("high", "medium") for u in url_results)

    evidence: list[dict[str, Any]] = []
    category_votes: dict[str, int] = {}
    rule_points = 0

    for rule in CLIENT_RULES:
        match = None
        for candidate in rule.pattern.finditer(clean):
            if (
                is_safe_otp
                and rule.rule_type == "credential_request"
                and _is_negated_credential_request(clean, candidate.start(), candidate.end())
            ):
                continue
            match = candidate
            break
        if match is None:
            continue
        matched_text = match.group(0).strip()
        evidence.append({
            "type": rule.rule_type,
            "text": matched_text,
            "severity": rule.severity,
            "explanation_en": rule.exp_en,
            "explanation_hi": rule.exp_hi,
        })
        rule_points += rule.weight
        if rule.cat_vote:
            category_votes[rule.cat_vote] = category_votes.get(rule.cat_vote, 0) + rule.weight

    # Add URL risk contribution
    max_url_risk = max((u["risk_index"] for u in url_results), default=0)
    url_points = int(max_url_risk * 0.65)
    for u in url_results:
        if u["impersonated_brand"]:
            category_votes["kyc_phishing"] = category_votes.get("kyc_phishing", 0) + 30
            evidence.append({
                "type": "url_spoofing",
                "text": u["submitted_url"],
                "severity": "high",
                "explanation_en": f"Suspicious URL spoofing {u['impersonated_brand']} (true owner: {u['registrable_domain']}).",
                "explanation_hi": f"संदिग्ध लिंक जो {u['impersonated_brand']} की नकल करता है (असली डोमेन: {u['registrable_domain']})।",
            })

    # Safeguard: routine urgency alone without credential/payment/impersonation/bad URL stays low risk
    only_urgency = len(evidence) > 0 and all(e["type"] == "urgency" for e in evidence) and not has_bad_url
    if is_safe_otp and not has_bad_url and not any(
        e["type"] in {"credential_request", "payment_request", "remote_access"} for e in evidence
    ):
        score_before_cap = rule_points
        score_cap = 15
        total_score = min(score_cap, score_before_cap)
        category = "legitimate_service_notice"
    elif only_urgency:
        score_before_cap = rule_points
        score_cap = 22
        total_score = min(score_cap, score_before_cap)
        category = "no_strong_indicators"
    else:
        score_before_cap = rule_points + url_points
        score_cap = 100
        total_score = min(score_cap, score_before_cap)
        if category_votes:
            category = max(category_votes.items(), key=lambda kv: kv[1])[0]
        elif total_score >= 30:
            category = "other_suspicious"
        else:
            category = "no_strong_indicators"

    if total_score >= 60:
        risk_level = "high"
        risk_band = "High Scam Risk"
        summary_en = "Strong fraud indicators detected. Do not click links, reply, or share any OTP/PIN/payment."
        summary_hi = "धोखाधड़ी के मजबूत संकेत मिले हैं। लिंक पर क्लिक न करें और ओटीपी/पिन साझा न करें।"
    elif total_score >= 30:
        risk_level = "medium"
        risk_band = "Verify Carefully"
        summary_en = "Suspicious cues detected. Independently verify the sender via an official app or trusted number."
        summary_hi = "संदिग्ध संकेत मिले हैं। किसी भी कदम से पहले आधिकारिक स्रोत से पुष्टि करें।"
    else:
        risk_level = "low"
        risk_band = "No Strong Indicators"
        summary_en = (
            "Appears to be a standard security/OTP notice with a do-not-share warning."
            if category == "legitimate_service_notice"
            else "No strong scam indicators matched. Still stay cautious with unexpected money or login requests."
        )
        summary_hi = "कोई मजबूत स्कैम संकेत नहीं मिला, फिर भी अनपेक्षित मांगों से सतर्क रहें।"

    cat_meta = CATEGORY_META.get(category, CATEGORY_META["other_suspicious"])
    contextual = evaluate_contextual_dimensions(clean, context_id, category, evidence, url_results, is_safe_otp)
    simple_en = get_simple_safety_guidance(risk_level, is_hindi=False)
    simple_hi = get_simple_safety_guidance(risk_level, is_hindi=True)

    ml_prob = ml_classifier.predict_scam_probability(clean)
    stored_text = clean if retain_raw_text else "[Redacted by User Privacy Preference]"
    highlighted_html = highlight_evidence_in_text(clean, evidence)
    risk_breakdown = {
        "rule_points": rule_points,
        "max_url_risk": max_url_risk,
        "url_points": url_points,
        "score_before_cap": score_before_cap,
        "score_cap": score_cap,
        "risk_index": total_score,
        "thresholds": {"low": "0-29", "medium": "30-59", "high": "60-100"},
        "method": "Weighted deterministic rule and structural URL signals; no external model or live lookup.",
    }

    return {
        "analysis_id": f"scan-{secrets.token_hex(4)}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detected_language": detected_lang,
        "risk_level": risk_level,
        "risk_band": risk_band,
        "risk_index": total_score,
        "risk_breakdown": risk_breakdown,
        "ml_scam_probability": ml_prob,
        "experimental_text_signal": ml_prob,
        "ml_signal_note": (
            "Experimental Naive Bayes signal trained only on bundled synthetic examples; "
            "uncalibrated and not used to calculate the risk score."
        ),
        "category": category,
        "category_label": cat_meta["label_en"],
        "category_label_hi": cat_meta["label_hi"],
        "summary": summary_en,
        "summary_hi": summary_hi,
        "raw_text": stored_text,
        "highlighted_html": highlighted_html,
        "evidence": evidence,
        "extracted_urls": url_results,
        "contextual_advisory": contextual,
        "recommended_actions": contextual["tailored_advice"],
        "simple_guidance": {"en": simple_en, "hi": simple_hi},
    }
