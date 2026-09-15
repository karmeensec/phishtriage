import re
from email.utils import parseaddr
from typing import Any


AUTH_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z_-]+)",
    re.IGNORECASE,
)

SUSPICIOUS_AUTH_RESULTS = {
    "fail",
    "softfail",
    "temperror",
    "permerror",
}

UNVERIFIED_DMARC_RESULTS = {
    "bestguesspass",
    "none",
    "neutral",
}


def extract_email_domain(header_value: str) -> str | None:
    """Extract and normalize the domain from an email header."""

    _, email_address = parseaddr(header_value)

    if "@" not in email_address:
        return None

    domain = email_address.rsplit("@", 1)[1]
    domain = domain.strip().lower().rstrip(".")

    return domain or None


def parse_authentication_results(
    authentication_header: str,
) -> dict[str, str]:
    """Extract SPF, DKIM and DMARC results."""

    results = {
        "spf": "not_found",
        "dkim": "not_found",
        "dmarc": "not_found",
    }

    for mechanism, status in AUTH_RESULT_PATTERN.findall(
        authentication_header
    ):
        results[mechanism.lower()] = status.lower()

    return results


def parse_spam_confidence_level(
    header_value: str,
) -> int | None:
    """Parse a Microsoft spam-confidence-level header."""

    try:
        return int(header_value.strip())
    except (AttributeError, TypeError, ValueError):
        return None


def analyze_headers(
    sender: str,
    reply_to: str,
    authentication_header: str,
    spam_confidence_header: str = "",
) -> dict[str, Any]:
    """Analyze sender identity and authentication headers."""

    sender_domain = extract_email_domain(sender)
    reply_to_domain = extract_email_domain(reply_to)

    authentication = parse_authentication_results(
        authentication_header
    )

    spam_confidence_level = parse_spam_confidence_level(
        spam_confidence_header
    )

    findings: list[dict[str, Any]] = []

    if (
        sender_domain
        and reply_to_domain
        and sender_domain != reply_to_domain
    ):
        findings.append(
            {
                "rule_id": "HDR-001",
                "title": (
                    "Sender and Reply-To domains do not match"
                ),
                "severity": "medium",
                "score": 20,
                "evidence": {
                    "sender_domain": sender_domain,
                    "reply_to_domain": reply_to_domain,
                },
            }
        )

    dmarc_status = authentication["dmarc"]

    if dmarc_status in UNVERIFIED_DMARC_RESULTS:
        findings.append(
            {
                "rule_id": "HDR-DMARC-UNVERIFIED",
                "title": (
                    "DMARC did not return a verified pass"
                ),
                "severity": "medium",
                "score": 10,
                "evidence": {
                    "mechanism": "dmarc",
                    "result": dmarc_status,
                },
            }
        )

    if (
        spam_confidence_level is not None
        and spam_confidence_level >= 5
    ):
        high_confidence = spam_confidence_level >= 7

        findings.append(
            {
                "rule_id": "HDR-SCL",
                "title": (
                    "Microsoft classified the email as spam"
                ),
                "severity": (
                    "high"
                    if high_confidence
                    else "medium"
                ),
                "score": 25 if high_confidence else 10,
                "evidence": {
                    "spam_confidence_level": (
                        spam_confidence_level
                    ),
                },
            }
        )

    for mechanism, status in authentication.items():
        if status not in SUSPICIOUS_AUTH_RESULTS:
            continue

        high_severity = status in {
            "fail",
            "permerror",
        }

        findings.append(
            {
                "rule_id": f"HDR-{mechanism.upper()}",
                "title": (
                    f"{mechanism.upper()} authentication returned "
                    f"{status}"
                ),
                "severity": (
                    "high"
                    if high_severity
                    else "medium"
                ),
                "score": 25 if high_severity else 10,
                "evidence": {
                    "mechanism": mechanism,
                    "result": status,
                },
            }
        )

    return {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "authentication": authentication,
        "spam_confidence_level": spam_confidence_level,
        "findings": findings,
    }