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

MULTI_LABEL_SUFFIXES = {
    "co.uk",
    "com.au",
    "com.br",
    "com.mx",
    "co.nz",
    "co.za",
}


def extract_email_domain(header_value: str) -> str | None:
    """Extract and normalize an email domain."""

    _, email_address = parseaddr(header_value)

    if "@" not in email_address:
        return None

    domain = email_address.rsplit("@", 1)[1]
    domain = domain.strip().lower().rstrip(".")

    return domain or None


def organizational_domain(domain: str) -> str:
    """Return the main organizational portion of a domain."""

    normalized = domain.lower().rstrip(".")
    labels = normalized.split(".")

    if len(labels) < 2:
        return normalized

    last_two = ".".join(labels[-2:])

    if (
        last_two in MULTI_LABEL_SUFFIXES
        and len(labels) >= 3
    ):
        return ".".join(labels[-3:])

    return last_two


def domains_are_related(
    first_domain: str,
    second_domain: str,
) -> bool:
    """Check whether two domains belong to the same organization."""

    return organizational_domain(
        first_domain
    ) == organizational_domain(second_domain)


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
    return_path: str = "",
) -> dict[str, Any]:
    """Analyze sender identity and authentication headers."""

    sender_domain = extract_email_domain(sender)
    reply_to_domain = extract_email_domain(reply_to)
    return_path_domain = extract_email_domain(return_path)

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
        and not domains_are_related(
            sender_domain,
            reply_to_domain,
        )
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

    if (
        sender_domain
        and return_path_domain
        and not domains_are_related(
            sender_domain,
            return_path_domain,
        )
    ):
        findings.append(
            {
                "rule_id": "HDR-RETURN-PATH",
                "title": (
                    "Sender and Return-Path domains do not match"
                ),
                "severity": "medium",
                "score": 15,
                "evidence": {
                    "sender_domain": sender_domain,
                    "return_path_domain": return_path_domain,
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
        "return_path_domain": return_path_domain,
        "authentication": authentication,
        "spam_confidence_level": spam_confidence_level,
        "findings": findings,
    }