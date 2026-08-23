from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit


def create_url_finding(
    rule_id: str,
    title: str,
    severity: str,
    score: int,
    url: str,
) -> dict[str, Any]:
    """Create a consistent and explainable URL finding."""

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "score": score,
        "evidence": {
            "url": url,
        },
    }


def analyze_url(url: str) -> dict[str, Any]:
    """Analyze a URL without making a network request."""

    findings: list[dict[str, Any]] = []

    try:
        parsed_url = urlsplit(url)
        hostname = parsed_url.hostname
    except ValueError:
        return {
            "url": url,
            "hostname": None,
            "findings": [
                create_url_finding(
                    rule_id="URL-MALFORMED",
                    title="URL could not be parsed safely",
                    severity="medium",
                    score=10,
                    url=url,
                )
            ],
        }

    if parsed_url.scheme.lower() == "http":
        findings.append(
            create_url_finding(
                rule_id="URL-HTTP",
                title="URL uses unencrypted HTTP",
                severity="medium",
                score=10,
                url=url,
            )
        )

    if parsed_url.username or parsed_url.password:
        findings.append(
            create_url_finding(
                rule_id="URL-CREDENTIALS",
                title="URL contains embedded user information",
                severity="high",
                score=25,
                url=url,
            )
        )

    if hostname:
        try:
            ip_address(hostname)
        except ValueError:
            pass
        else:
            findings.append(
                create_url_finding(
                    rule_id="URL-IP",
                    title="URL uses an IP address instead of a domain",
                    severity="high",
                    score=25,
                    url=url,
                )
            )

        hostname_labels = hostname.lower().split(".")

        if any(
            label.startswith("xn--")
            for label in hostname_labels
        ):
            findings.append(
                create_url_finding(
                    rule_id="URL-PUNYCODE",
                    title="URL contains a Punycode domain",
                    severity="medium",
                    score=20,
                    url=url,
                )
            )

    return {
        "url": url,
        "hostname": hostname,
        "findings": findings,
    }


def analyze_urls(urls: list[str]) -> dict[str, Any]:
    """Analyze multiple URLs and combine their findings."""

    analyses = [
        analyze_url(url)
        for url in urls
    ]

    findings = [
        finding
        for analysis in analyses
        for finding in analysis["findings"]
    ]

    return {
        "analyzed_count": len(analyses),
        "analyses": analyses,
        "findings": findings,
    }