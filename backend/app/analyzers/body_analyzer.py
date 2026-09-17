import re
import unicodedata
from typing import Any


MIN_OBFUSCATION_CHARACTERS = 3

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
    {
        "rule_id": "BODY-FINANCIAL-LURE",
        "title": (
            "Email uses a financial or cryptocurrency lure"
        ),
        "severity": "medium",
        "score": 15,
        "phrases": {
            "claim your tokens",
            "crypto allocation",
            "cryptocurrency allocation",
            "digital asset reward",
            "exclusive allocation",
            "guaranteed returns",
            "investment opportunity",
            "wallet verification",
            "student loan forgiveness",
            "loan forgiveness",
            "debt forgiveness",
            "debt relief",
            "eligible for forgiveness",
        },
    },
]


def is_format_character(character: str) -> bool:
    """Return whether a character is invisible formatting."""

    return unicodedata.category(character) == "Cf"


def count_embedded_format_characters(text: str) -> int:
    """Count invisible characters inserted inside words."""

    count = 0

    for index, character in enumerate(text):
        if not is_format_character(character):
            continue

        if index == 0 or index == len(text) - 1:
            continue

        previous_character = text[index - 1]
        next_character = text[index + 1]

        if (
            previous_character.isalnum()
            and next_character.isalnum()
        ):
            count += 1

    return count


def normalize_text(text: str) -> str:
    """Normalize text and remove invisible evasion characters."""

    normalized = unicodedata.normalize("NFKC", text)

    normalized = "".join(
        character
        for character in normalized
        if not is_format_character(character)
    )

    normalized = normalized.casefold()

    return re.sub(r"\s+", " ", normalized).strip()


def analyze_body(
    subject: str,
    body: str,
) -> dict[str, Any]:
    """Analyze email text for social-engineering language."""

    raw_combined_text = f"{subject}\n{body}"

    embedded_character_count = (
        count_embedded_format_characters(
            raw_combined_text
        )
    )

    combined_text = normalize_text(raw_combined_text)

    findings: list[dict[str, Any]] = []

    if (
        embedded_character_count
        >= MIN_OBFUSCATION_CHARACTERS
    ):
        findings.append(
            {
                "rule_id": "BODY-OBFUSCATION",
                "title": (
                    "Email uses invisible characters "
                    "to obscure text"
                ),
                "severity": "medium",
                "score": 20,
                "evidence": {
                    "embedded_invisible_character_count": (
                        embedded_character_count
                    ),
                },
            }
        )

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