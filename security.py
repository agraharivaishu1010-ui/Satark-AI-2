"""CSRF token helpers and in-process sliding-window rate limiter."""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import deque


def generate_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def verify_csrf_token(cookie_token: str | None, submitted_token: str | None) -> bool:
    if not cookie_token or not submitted_token:
        return False
    return hmac.compare_digest(cookie_token, submitted_token)


class SlidingWindowRateLimiter:
    """Lightweight in-memory sliding-window rate limiter keyed by client identifier."""

    def __init__(self, max_requests: int = 120, window_seconds: int = 60, max_keys: int = 10000) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_prune = 0.0

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if now - self._last_prune >= self.window_seconds:
                self._prune(cutoff)
                self._last_prune = now
            bucket = self._hits.get(key)
            if bucket is None:
                if len(self._hits) >= self.max_keys:
                    return False, self.window_seconds
                bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
                return False, retry_after
            bucket.append(now)
            return True, 0

    def _prune(self, cutoff: float) -> None:
        expired_keys = []
        for key, bucket in self._hits.items():
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if not bucket:
                expired_keys.append(key)
        for key in expired_keys:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
            self._last_prune = 0.0


rate_limiter = SlidingWindowRateLimiter(max_requests=120, window_seconds=60)
