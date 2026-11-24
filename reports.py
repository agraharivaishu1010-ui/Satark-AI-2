"""Plain-text threat assessment reports, family safety alerts, and 1930 incident worksheets."""
from __future__ import annotations

from typing import Any


def build_text_report(result: dict[str, Any]) -> str:
    ev_str = " | ".join(f"[{e['type']}] {e['text']}" for e in result.get("evidence", [])) or "None"
    actions_str = " | ".join(result.get("recommended_actions", []))
    breakdown = result.get("risk_breakdown", {})
    return "\n".join([
        "SATARK AI — EXPLAINABLE CYBER THREAT ASSESSMENT REPORT",
        f"Analysis ID      : {result['analysis_id']}",
        f"Timestamp (UTC)  : {result['timestamp']}",
        f"Risk Band        : {result['risk_band']} ({result['risk_index']}/100)",
        (
            "Risk Points      : "
            f"{breakdown.get('rule_points', 0)} rules + {breakdown.get('url_points', 0)} URL points "
            f"(capped at {breakdown.get('score_cap', 100)})"
        ),
        f"Category         : {result['category_label']}",
        f"Summary          : {result['summary']}",
        f"Inspected Text   : {result['raw_text']}",
        f"Evidence         : {ev_str}",
        f"Recommended      : {actions_str}",
        "Emergency Help   : Dial 1930 or visit https://cybercrime.gov.in",
    ])


def build_1930_incident_sheet(
    date: str = "",
    amount: str = "",
    utr: str = "",
    suspect_id: str = "",
    platform: str = "WhatsApp / SMS",
    notes: str = "",
) -> str:
    return "\n".join([
        "SATARK AI — INDIA CYBERCRIME (1930 / CYBERCRIME.GOV.IN) INCIDENT WORKSHEET",
        "==========================================================================",
        f"Incident Date/Time   : {date or '[Not provided]'}",
        f"Debited Amount (INR) : {amount or '[Not provided]'}",
        f"12-Digit UTR / Ref   : {utr or '[Not provided]'}",
        f"Suspect Phone / URL  : {suspect_id or '[Not provided]'}",
        f"Channel / Platform   : {platform or 'WhatsApp / SMS'}",
        f"Additional Notes     : {notes or '[None]'}",
        "",
        "NEXT STEPS:",
        "1. Call National Cybercrime Helpline 1930 immediately (Golden Hour freeze).",
        "2. File a formal complaint at https://cybercrime.gov.in with UTR & screenshots.",
        "3. Report suspect SMS/calls on Chakshu: https://www.sancharsaathi.gov.in/",
    ])
