"""Zero-visit structural URL inspection engine with homoglyph & brand-impersonation detection."""
from __future__ import annotations

import ipaddress
import re
import secrets
import unicodedata
from typing import Any
from urllib.parse import urlparse

from app.core.constants import (
    KNOWN_SHORTENERS,
    MULTI_PART_TLDS,
    PROTECTED_BRANDS,
    SUSPICIOUS_TLDS,
)

EXPLICIT_SCHEME_PATTERN = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")
URL_WITH_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
SUSPICIOUS_QUERY_PATTERN = re.compile(r"(redirect|url=|next=|token=|otp=|session=)", re.IGNORECASE)
URL_EXTRACTION_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'\)\]]+|'
    r'\b(?:[a-zA-Z0-9-]+\.)+(?:in|com|org|net|xyz|top|click|icu|vip|online|site|live|shop|info|co\.in|gov\.in|ly|at|gy|cc)'
    r'(?:/[^\s<>"\'\)\]]*)?',
    re.IGNORECASE,
)
PHISHING_KEYWORDS: tuple[str, ...] = (
    "kyc", "verify", "update", "login", "signin", "unblock",
    "suspend", "pan", "aadhaar", "otp", "claim", "refund", "lottery",
)


def _has_non_ascii(value: str) -> bool:
    return any(ord(ch) > 127 for ch in value)


def _is_ip_host(host: str) -> bool:
    clean = host.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def normalize_homoglyphs(text: str) -> str:
    """Normalizes common leetspeak/visual homoglyphs for brand-lookalike matching."""
    return (
        unicodedata.normalize("NFKC", text)
        .lower()
        .translate(str.maketrans({
            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
            "і": "i", "ј": "j", "ӏ": "l", "α": "a", "ο": "o", "ρ": "p", "ι": "i",
            "τ": "t", "υ": "y", "χ": "x", "ν": "v", "ε": "e", "κ": "k",
        }))
        .replace("0", "o")
        .replace("1", "i")
        .replace("3", "e")
        .replace("5", "s")
        .replace("@", "a")
        .replace("rn", "m")
    )


def _is_valid_hostname(hostname: str) -> bool:
    clean = unicodedata.normalize("NFKC", hostname).rstrip(".")
    if not clean or len(clean) > 253:
        return False
    try:
        ascii_host = clean.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False
    return all(
        0 < len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in ascii_host.split(".")
    )


def _one_edit_apart(left: str, right: str) -> bool:
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    short, long = sorted((left, right), key=len)
    i = j = differences = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]:
            i += 1
            j += 1
            continue
        differences += 1
        if differences > 1:
            return False
        if len(short) == len(long):
            i += 1
        j += 1
    return differences + int(j < len(long) or i < len(short)) <= 1


def extract_registrable_domain(hostname: str) -> tuple[str, int]:
    """Estimates the registrable domain and subdomain count using a bundled suffix set."""
    clean = (hostname or "").lower().rstrip(".")
    if not clean:
        return "", 0
    if _is_ip_host(clean):
        return clean, 0
    parts = [p for p in clean.split(".") if p]
    if len(parts) <= 2:
        return clean, 0
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}", max(0, len(parts) - 3)
    return last_two, max(0, len(parts) - 2)


def extract_urls_from_text(text: str, limit: int = 8) -> list[str]:
    """Extracts up to `limit` unique URL-like strings from free-form text."""
    if not text:
        return []
    seen: list[str] = []
    for raw in URL_EXTRACTION_PATTERN.findall(text):
        cleaned = raw.rstrip(".,;:!?")
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
        if len(seen) >= limit:
            break
    return seen


def _detect_brand_impersonation(
    raw_host: str, pathname: str, reg_domain: str
) -> tuple[str | None, int, dict[str, str] | None]:
    full_lower = f"{raw_host}{pathname}".lower()
    normalized_host = normalize_homoglyphs(raw_host)
    for brand, official_domains in PROTECTED_BRANDS.items():
        domain_label = reg_domain.split(".", 1)[0].lower()
        official_labels = {domain.split(".", 1)[0] for domain in official_domains}
        exact_lookalike = brand in full_lower or brand in normalized_host
        typo_lookalike = len(brand) >= 5 and any(
            _one_edit_apart(domain_label, label) for label in {brand, *official_labels}
        )
        if (exact_lookalike or typo_lookalike) and reg_domain not in official_domains:
            return (
                brand.upper(),
                48,
                {
                    "signal": "brand_impersonation",
                    "severity": "high",
                    "explanation": (
                        f"References '{brand.upper()}' or a close lookalike spelling in the hostname/path, "
                        f"but the actual registrable domain is '{reg_domain}' instead of an official domain "
                        f"({', '.join(official_domains)})."
                    ),
                },
            )
    return None, 0, None


def inspect_url_locally(raw_url: str) -> dict[str, Any]:
    """Performs zero-visit structural URL inspection without making any outbound network call."""
    submitted = (raw_url or "").strip()
    analysis_id = f"url-{secrets.token_hex(4)}"
    if len(submitted) > 2048:
        return {
            "analysis_id": analysis_id,
            "submitted_url": submitted[:2048],
            "normalized_url": "",
            "hostname": "",
            "registrable_domain": "",
            "scheme": "invalid",
            "is_https": False,
            "is_ip_address": False,
            "is_shortened": False,
            "has_punycode_or_idn": False,
            "subdomain_count": 0,
            "impersonated_brand": None,
            "risk_level": "high",
            "risk_index": 82,
            "summary": "URL exceeds the safe inspection length.",
            "signals": [{
                "signal": "oversized_url",
                "severity": "high",
                "explanation": "The URL is too long to inspect safely.",
            }],
            "recommended_actions": ["Do not open or share an unusually long URL."],
        }
    if not submitted:
        return {
            "analysis_id": analysis_id,
            "submitted_url": "",
            "normalized_url": "",
            "hostname": "",
            "registrable_domain": "",
            "scheme": "invalid",
            "is_https": False,
            "is_ip_address": False,
            "is_shortened": False,
            "has_punycode_or_idn": False,
            "subdomain_count": 0,
            "impersonated_brand": None,
            "risk_level": "low",
            "risk_index": 0,
            "summary": "Enter a URL to inspect its structure locally without visiting it.",
            "signals": [],
            "recommended_actions": ["Paste a suspicious link to inspect its true domain owner."],
        }

    scheme_match = EXPLICIT_SCHEME_PATTERN.match(submitted)
    if scheme_match and scheme_match.group(1).lower() not in ("http", "https"):
        return {
            "analysis_id": analysis_id,
            "submitted_url": submitted,
            "normalized_url": submitted,
            "hostname": "",
            "registrable_domain": "",
            "scheme": scheme_match.group(1).lower(),
            "is_https": False,
            "is_ip_address": False,
            "is_shortened": False,
            "has_punycode_or_idn": False,
            "subdomain_count": 0,
            "impersonated_brand": None,
            "risk_level": "high",
            "risk_index": 95,
            "summary": "Executable or non-web URI scheme detected. Never open or paste this link into a browser.",
            "signals": [{
                "signal": "dangerous_uri_scheme",
                "severity": "high",
                "explanation": "Uses a non-web or executable URI scheme (such as javascript:, data:, or file:).",
            }],
            "recommended_actions": [
                "Do not click or paste this address into your browser.",
                "Delete the message immediately.",
            ],
        }

    candidate = submitted if URL_WITH_SCHEME_PATTERN.match(submitted) else f"http://{submitted}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        parsed = None

    port: int | None = None
    try:
        raw_host = (parsed.hostname or "").lower() if parsed else ""
        if parsed:
            port = parsed.port
    except ValueError:
        raw_host = ""
        parsed = None
    if (
        not parsed
        or not raw_host
        or (port is not None and not 0 <= port <= 65535)
        or ("\\" in parsed.netloc)
        or ("." not in raw_host and not _is_ip_host(raw_host))
        or (not _is_ip_host(raw_host) and not _is_valid_hostname(raw_host))
    ):
        return {
            "analysis_id": analysis_id,
            "submitted_url": submitted,
            "normalized_url": candidate,
            "hostname": raw_host,
            "registrable_domain": "",
            "scheme": "invalid",
            "is_https": False,
            "is_ip_address": False,
            "is_shortened": False,
            "has_punycode_or_idn": False,
            "subdomain_count": 0,
            "impersonated_brand": None,
            "risk_level": "high",
            "risk_index": 82,
            "summary": "Malformed or unsafe URL structure.",
            "signals": [{
                "signal": "malformed_url",
                "severity": "high",
                "explanation": "Could not be parsed as a valid standard web address.",
            }],
            "recommended_actions": ["Do not open malformed links."],
        }

    scheme = parsed.scheme.lower()
    is_https = scheme == "https"
    is_ip = _is_ip_host(raw_host)
    has_idn = "xn--" in raw_host or _has_non_ascii(raw_host)
    reg_domain, sub_count = extract_registrable_domain(raw_host)
    is_shortened = reg_domain in KNOWN_SHORTENERS

    signals: list[dict[str, str]] = []
    points = 0

    if parsed.username or parsed.password:
        points += 45
        signals.append({
            "signal": "embedded_credentials_in_url",
            "severity": "high",
            "explanation": "Contains '@' credentials in the URL authority to disguise the real destination host.",
        })
    if is_ip:
        points += 38
        signals.append({
            "signal": "raw_ip_address_host",
            "severity": "high",
            "explanation": "Uses a raw IP address instead of a registered domain name.",
        })
    if has_idn:
        points += 34
        signals.append({
            "signal": "idn_or_punycode_homograph",
            "severity": "high",
            "explanation": "Contains Punycode (xn--) or non-ASCII characters often used in homograph lookalike attacks.",
        })
    if is_shortened:
        points += 24
        signals.append({
            "signal": "url_shortener",
            "severity": "medium",
            "explanation": f"Uses a link shortener ({reg_domain}) that conceals the final destination.",
        })
    tld = reg_domain.rsplit(".", 1)[-1] if "." in reg_domain else ""
    if tld in SUSPICIOUS_TLDS:
        points += 26
        signals.append({
            "signal": "high_risk_tld",
            "severity": "medium",
            "explanation": f"Uses a top-level domain (.{tld}) frequently abused in throwaway phishing campaigns.",
        })
    if sub_count >= 2:
        points += 16
        signals.append({
            "signal": "excessive_subdomains",
            "severity": "medium",
            "explanation": f"Stacks {sub_count} subdomains before '{reg_domain}' to mimic trusted brands.",
        })
    if not is_https:
        points += 10
        signals.append({
            "signal": "unencrypted_http",
            "severity": "low",
            "explanation": "Uses unencrypted HTTP instead of HTTPS.",
        })

    impersonated_brand, brand_pts, brand_sig = _detect_brand_impersonation(
        raw_host, parsed.path or "", reg_domain
    )
    if brand_sig:
        points += brand_pts
        signals.append(brand_sig)

    path_and_sub = f"{raw_host.replace(reg_domain, '')} {parsed.path or ''}".lower()
    is_official = any(reg_domain in domains for domains in PROTECTED_BRANDS.values())
    matched_terms = [kw for kw in PHISHING_KEYWORDS if kw in path_and_sub]
    if matched_terms and not is_official:
        points += min(30, 12 * len(matched_terms))
        signals.append({
            "signal": "sensitive_action_keywords",
            "severity": "high" if len(matched_terms) > 1 else "medium",
            "explanation": f"Contains sensitive verification/login keywords ({', '.join(matched_terms[:4])}) on an unverified domain.",
        })

    if parsed.query and SUSPICIOUS_QUERY_PATTERN.search(parsed.query):
        points += 18
        signals.append({
            "signal": "suspicious_query_parameters",
            "severity": "medium",
            "explanation": "Contains redirect, token, or OTP-style query parameters often used in credential harvesting.",
        })

    risk_index = min(100, points)
    if risk_index >= 60:
        risk_level = "high"
        summary = f"High-risk URL structure. True domain owner is '{reg_domain or raw_host}'—do not open."
        actions = [
            "Do not open this link or enter any personal/banking details.",
            "Navigate manually to the official website or app instead.",
        ]
    elif risk_index >= 25:
        risk_level = "medium"
        summary = f"Suspicious structural signals detected for '{reg_domain or raw_host}'. Verify before trusting."
        actions = [
            "Verify the sender independently before clicking.",
            "Never enter OTPs, UPI PINs, or passwords on links received via SMS/WhatsApp.",
        ]
    else:
        risk_level = "low"
        summary = (
            f"No strong structural phishing indicators for '{reg_domain or raw_host}'. "
            "Note: HTTPS alone does not guarantee safety."
        )
        actions = ["Still confirm you expected this link before signing in."]

    return {
        "analysis_id": analysis_id,
        "submitted_url": submitted,
        "normalized_url": parsed.geturl(),
        "hostname": raw_host,
        "registrable_domain": reg_domain,
        "scheme": scheme,
        "is_https": is_https,
        "is_ip_address": is_ip,
        "is_shortened": is_shortened,
        "has_punycode_or_idn": has_idn,
        "subdomain_count": sub_count,
        "impersonated_brand": impersonated_brand,
        "risk_level": risk_level,
        "risk_index": risk_index,
        "summary": summary,
        "signals": signals,
        "recommended_actions": actions,
    }
