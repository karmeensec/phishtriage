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


def extract_email_domain(header_value: str) -> str | None:

    _, email_address = parseaddr(header_value)

    if "@" not in email_address:
        return None

    domain = email_address.rsplit("@", 1)[1]
    domain = domain.strip().lower().rstrip(".")

    return domain or None


def parse_authentication_results(
    authentication_header: str,
) -> dict[str, str]:

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


def analyze_headers(
    sender: str,
    reply_to: str,
    authentication_header: str,
) -> dict[str, Any]:

    sender_domain = extract_email_domain(sender)
    reply_to_domain = extract_email_domain(reply_to)
    authentication = parse_authentication_results(
        authentication_header
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
                "title": "Sender and Reply-To domains do not match",
                "severity": "medium",
                "score": 20,
                "evidence": {
                    "sender_domain": sender_domain,
                    "reply_to_domain": reply_to_domain,
                },
            }
        )

    for mechanism, status in authentication.items():
        if status not in SUSPICIOUS_AUTH_RESULTS:
            continue

        high_severity = status in {"fail", "permerror"}

        findings.append(
            {
                "rule_id": f"HDR-{mechanism.upper()}",
                "title": (
                    f"{mechanism.upper()} authentication returned "
                    f"{status}"
                ),
                "severity": "high" if high_severity else "medium",
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
        "findings": findings,
    }