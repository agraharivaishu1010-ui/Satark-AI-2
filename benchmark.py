"""Confusion-matrix and per-language benchmark runner over bundled synthetic samples."""
from __future__ import annotations

from typing import Any

from app.core.analyzer import analyze_message


def format_rate(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{round(value * 100)}%"


def run_benchmark(samples: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    by_language: dict[str, dict[str, int]] = {}
    rows: list[dict[str, Any]] = []

    for sample in samples:
        res = analyze_message(sample["text"], language_hint=sample.get("language", "auto"))
        predicted_scam = res["risk_level"] in ("high", "medium")
        actual_scam = bool(sample["is_scam"])
        lang = sample.get("language", "en")
        bucket = by_language.setdefault(lang, {"total": 0, "correct": 0})
        bucket["total"] += 1

        if actual_scam and predicted_scam:
            tp += 1
            bucket["correct"] += 1
        elif not actual_scam and predicted_scam:
            fp += 1
        elif not actual_scam and not predicted_scam:
            tn += 1
            bucket["correct"] += 1
        else:
            fn += 1

        rows.append({
            "id": sample["id"],
            "title": sample["title"],
            "language": lang,
            "expected": "scam" if actual_scam else "benign",
            "predicted": res["risk_level"],
            "risk_index": res["risk_index"],
            "passed": predicted_scam == actual_scam,
        })

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    accuracy = (tp + tn) / len(samples) if samples else None

    return {
        "total": len(samples),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "precision_label": format_rate(precision),
        "recall_label": format_rate(recall),
        "accuracy_label": format_rate(accuracy),
        "by_language": by_language,
        "rows": rows,
        "limitation_note": (
            f"Evaluates {len(samples)} bundled synthetic examples for regression checking; "
            "not an independent real-world accuracy claim."
        ),
    }
