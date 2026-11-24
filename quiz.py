"""Spot-the-Scam interactive quiz items."""
from __future__ import annotations

from typing import Any

QUIZ_QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "q1",
        "message": "Your SBI YONO OTP is 918273. Valid for 10 mins. NEVER share your OTP with anyone.",
        "answer": "legitimate",
        "explanation": "Contains a standard transaction OTP paired with an explicit do-not-share warning and no suspicious link.",
    },
    {
        "id": "q2",
        "message": "Your electricity will be cut tonight at 9:30 PM. Call officer 9812345678 immediately.",
        "answer": "scam",
        "explanation": "Classic electricity disconnection scam using tonight-deadline panic and a personal 10-digit number.",
    },
    {
        "id": "q3",
        "message": "Sign in to verify your KYC at https://hdfcbank.com.secure-login.xyz/kyc",
        "answer": "scam",
        "explanation": "The real registrable domain is secure-login.xyz, not hdfcbank.com.",
    },
]
