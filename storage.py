"""Session-isolated, privacy-first in-memory scan history & feedback store."""
from __future__ import annotations

from collections import OrderedDict, deque
from copy import deepcopy
from typing import Any

REDACTED = "[Redacted by User Privacy Preference]"


class SessionHistoryStore:
    """Isolates scan history per browser/API session ID so users never see each other's scans."""

    def __init__(
        self, max_items_per_session: int = 100, max_sessions: int = 1000, max_feedback_per_session: int = 100
    ) -> None:
        self._max_items = max_items_per_session
        self._max_sessions = max_sessions
        self._max_feedback_per_session = max_feedback_per_session
        self._sessions: OrderedDict[str, deque[dict[str, Any]]] = OrderedDict()
        self._feedback: dict[str, deque[dict[str, str]]] = {}

    def _ensure_session(self, session_id: str) -> deque[dict[str, Any]]:
        bucket = self._sessions.get(session_id)
        if bucket is not None:
            self._sessions.move_to_end(session_id)
            return bucket
        if len(self._sessions) >= self._max_sessions:
            oldest_id, _ = self._sessions.popitem(last=False)
            self._feedback.pop(oldest_id, None)
        bucket = deque(maxlen=self._max_items)
        self._sessions[session_id] = bucket
        return bucket

    def add_scan(self, session_id: str, result: dict[str, Any]) -> None:
        stored_result = deepcopy(result)
        if stored_result.get("raw_text") == REDACTED:
            stored_result["highlighted_html"] = REDACTED
            for evidence in stored_result.get("evidence", []):
                evidence["text"] = REDACTED
            for url_result in stored_result.get("extracted_urls", []):
                url_result["submitted_url"] = REDACTED
                url_result["normalized_url"] = REDACTED
                url_result["hostname"] = REDACTED
                url_result["registrable_domain"] = REDACTED
                url_result["summary"] = "URL details were redacted by the user's privacy preference."
                for signal in url_result.get("signals", []):
                    signal["explanation"] = "URL structural signal recorded; source details were redacted."
        self._ensure_session(session_id).appendleft(stored_result)

    def list_scans(self, session_id: str) -> list[dict[str, Any]]:
        if session_id in self._sessions:
            self._sessions.move_to_end(session_id)
        return list(self._sessions.get(session_id, ()))

    def get_scan(self, session_id: str, analysis_id: str) -> dict[str, Any] | None:
        if session_id in self._sessions:
            self._sessions.move_to_end(session_id)
        for item in self._sessions.get(session_id, ()):
            if item["analysis_id"] == analysis_id:
                return item
        return None

    def add_feedback(self, session_id: str, analysis_id: str, assessment: str) -> dict[str, str]:
        record = {"analysis_id": analysis_id, "assessment": assessment}
        self._ensure_session(session_id)
        bucket = self._feedback.setdefault(
            session_id, deque(maxlen=self._max_feedback_per_session)
        )
        bucket.append(record)
        return record

    def clear(self, session_id: str | None = None) -> None:
        if session_id is None:
            self._sessions.clear()
            self._feedback.clear()
        else:
            self._sessions.pop(session_id, None)
            self._feedback.pop(session_id, None)


history_store = SessionHistoryStore()
