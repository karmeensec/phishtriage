import re
import unicodedata
from typing import Any


BODY_RULES = [
    {
        "rule_id": "BODY-URGENCY",
        "title": "Email uses urgent or pressuring language",
        "severity": "medium",
        "score": 10,
        "phrases": {
            "urgent",
            "immediately",
            "act now",
            "final warning",
            "within 24 hours",
        },
    },
    {
        "rule_id": "BODY-ACCOUNT",
        "title": "Email threatens account access",
        "severity": "high",
        "score": 20,
        "phrases": {
            "account will be suspended",
            "account suspended",
            "account locked",
            "access will be disabled",
            "unusual activity detected",
        },
    },
    {
        "rule_id": "BODY-CREDENTIALS",
        "title": "Email requests account credentials",
        "severity": "high",
        "score": 25,
        "phrases": {
            "verify your credentials",
            "confirm your password",
            "enter your password",
            "login credentials",
            "verify your account",
        },
    },
    {
        "rule_id": "BODY-FINANCIAL",
        "title": "Email requests a sensitive financial action",
        "severity": "high",
        "score": 25,
        "phrases": {
            "wire transfer",
            "gift card",
            "update payment details",
            "bank account information",
            "cryptocurrency payment",
        },
    },
    {
        "rule_id": "BODY-ACTION",
        "title": "Email directs the recipient to take an action",
        "severity": "medium",
        "score": 10,
        "phrases": {
            "click here",
            "open the attachment",
            "download the attachment",
            "follow this link",
        },
    },
]


def normalize_text(text: str) -> str:
    """Normalize untrusted text for consistent phrase matching."""

    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.casefold()

    return re.sub(r"\s+", " ", normalized).strip()


def analyze_body(
    subject: str,
    body: str,
) -> dict[str, Any]:
    """Analyze email text for social-engineering language."""

    combined_text = normalize_text(
        f"{subject}\n{body}"
    )

    findings: list[dict[str, Any]] = []

    for rule in BODY_RULES:
        matched_phrases = sorted(
            phrase
            for phrase in rule["phrases"]
            if phrase in combined_text
        )

        if not matched_phrases:
            continue

        # One finding per category prevents repeated words
        # from artificially inflating the risk score.
        findings.append(
            {
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "score": rule["score"],
                "evidence": {
                    "matched_phrases": matched_phrases,
                },
            }
        )

    return {
        "matched_category_count": len(findings),
        "findings": findings,
    }