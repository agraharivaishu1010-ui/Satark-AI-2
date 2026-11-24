"""Experimental pure-Python sample-based Naive Bayes text signal (not the risk-score engine)."""
from __future__ import annotations

import math
import re
from collections import Counter

from app.data.samples import BENCHMARK_SAMPLES

TOKEN_RE = re.compile(r"[a-zA-Z0-9\u0900-\u097F\u0980-\u09FF\u0A80-\u0AFF\u0B80-\u0BFF]{2,}")


def tokenize(text: str) -> list[str]:
    return [tok.lower() for tok in TOKEN_RE.findall(text or "")]


class LightweightScamClassifier:
    """Zero-dependency classifier trained on the small bundled synthetic sample corpus."""

    def __init__(self) -> None:
        self._idf: dict[str, float] = {}
        self._scam_weights: dict[str, float] = {}
        self._benign_weights: dict[str, float] = {}
        self._scam_total: float = 0.0
        self._benign_total: float = 0.0
        self._vocab_size: int = 1
        self._prior_scam: float = 0.5
        self._fit(BENCHMARK_SAMPLES)

    def _fit(self, samples: list[dict]) -> None:
        docs = [(tokenize(s["text"]), bool(s["is_scam"])) for s in samples]
        n_docs = max(1, len(docs))
        df: Counter[str] = Counter()
        for tokens, _ in docs:
            for tok in set(tokens):
                df[tok] += 1

        self._idf = {tok: math.log((n_docs + 1) / (freq + 1)) + 1.0 for tok, freq in df.items()}
        self._vocab_size = max(1, len(df))

        scam_docs = 0
        for tokens, is_scam in docs:
            if is_scam:
                scam_docs += 1
            tf = Counter(tokens)
            for tok, count in tf.items():
                weight = (1.0 + math.log(count)) * self._idf.get(tok, 1.0)
                if is_scam:
                    self._scam_weights[tok] = self._scam_weights.get(tok, 0.0) + weight
                    self._scam_total += weight
                else:
                    self._benign_weights[tok] = self._benign_weights.get(tok, 0.0) + weight
                    self._benign_total += weight

        self._prior_scam = max(0.1, min(0.9, scam_docs / n_docs))

    def predict_scam_probability(self, text: str) -> float:
        """Return an uncalibrated corpus-relative score in [0.0, 1.0], not a probability claim."""
        tokens = tokenize(text)
        if not tokens:
            return 0.0
        alpha = 1.0
        log_scam = math.log(self._prior_scam)
        log_benign = math.log(1.0 - self._prior_scam)
        scam_denom = self._scam_total + alpha * self._vocab_size
        benign_denom = self._benign_total + alpha * self._vocab_size

        for tok in tokens:
            if tok not in self._idf:
                continue
            w_s = self._scam_weights.get(tok, 0.0) + alpha
            w_b = self._benign_weights.get(tok, 0.0) + alpha
            log_scam += math.log(w_s / scam_denom)
            log_benign += math.log(w_b / benign_denom)

        diff = max(-20.0, min(20.0, log_scam - log_benign))
        return round(1.0 / (1.0 + math.exp(-diff)), 4)


ml_classifier = LightweightScamClassifier()
