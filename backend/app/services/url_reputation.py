"""Optional external domain-reputation analysis."""

import asyncio
import json
import os
from ipaddress import ip_address
from json import JSONDecodeError
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


VIRUSTOTAL_API_URL = (
    "https://www.virustotal.com/api/v3/domains"
)

MAX_REPUTATION_DOMAINS = 4
MAX_RESPONSE_SIZE = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 4

EXCLUDED_DOMAIN_SUFFIXES = (
    ".example",
    ".invalid",
    ".localhost",
    ".test",
)


def reputation_enabled() -> bool:
    """Return whether external reputation checks are enabled."""

    enabled_value = os.getenv(
        "URL_REPUTATION_ENABLED",
        "false",
    )

    return enabled_value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def extract_public_domains(
    urls: list[str],
) -> list[str]:
    """Extract unique public domain names without URL paths."""

    domains: set[str] = set()

    for url in urls:
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            continue

        if not hostname:
            continue

        hostname = hostname.lower().rstrip(".")

        try:
            ip_address(hostname)
        except ValueError:
            pass
        else:
            continue

        if "." not in hostname:
            continue

        if hostname.endswith(EXCLUDED_DOMAIN_SUFFIXES):
            continue

        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            continue

        domains.add(hostname)

    return sorted(domains)[:MAX_REPUTATION_DOMAINS]


def _safe_count(value: object) -> int:
    """Return a safe nonnegative reputation count."""

    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    ):
        return value

    return 0


def _fetch_domain_report(
    domain: str,
    api_key: str,
) -> dict[str, int] | None:
    """Retrieve an existing VirusTotal domain report."""

    request = Request(
        url=(
            f"{VIRUSTOTAL_API_URL}/"
            f"{quote(domain, safe='')}"
        ),
        headers={
            "Accept": "application/json",
            "x-apikey": api_key,
        },
        method="GET",
    )

    try:
        with urlopen(
            request,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as response:
            response_content = response.read(
                MAX_RESPONSE_SIZE + 1
            )
    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        ValueError,
    ):
        return None

    if len(response_content) > MAX_RESPONSE_SIZE:
        return None

    try:
        payload = json.loads(response_content)
    except (JSONDecodeError, UnicodeDecodeError):
        return None

    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    if not isinstance(stats, dict):
        return None

    return {
        "malicious": _safe_count(
            stats.get("malicious")
        ),
        "suspicious": _safe_count(
            stats.get("suspicious")
        ),
        "harmless": _safe_count(
            stats.get("harmless")
        ),
        "undetected": _safe_count(
            stats.get("undetected")
        ),
    }


async def analyze_url_reputation(
    urls: list[str],
) -> dict[str, Any]:
    """Check URL domains without visiting suspicious websites."""

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not reputation_enabled() or not api_key:
        return {
            "provider": "VirusTotal",
            "enabled": False,
            "checked_domain_count": 0,
            "findings": [],
        }

    domains = extract_public_domains(urls)

    reports = await asyncio.gather(
        *[
            asyncio.to_thread(
                _fetch_domain_report,
                domain,
                api_key,
            )
            for domain in domains
        ]
    )

    checked_reports = [
        {
            "domain": domain,
            **report,
        }
        for domain, report in zip(
            domains,
            reports,
            strict=True,
        )
        if report is not None
    ]

    flagged_domains = [
        report
        for report in checked_reports
        if (
            report["malicious"] >= 1
            or report["suspicious"] >= 2
        )
    ]

    findings: list[dict[str, Any]] = []

    if flagged_domains:
        high_confidence = any(
            report["malicious"] >= 2
            for report in flagged_domains
        )

        findings.append(
            {
                "rule_id": "URL-REPUTATION",
                "title": (
                    "External reputation providers flagged "
                    "a linked domain"
                ),
                "severity": (
                    "high"
                    if high_confidence
                    else "medium"
                ),
                "score": 30 if high_confidence else 15,
                "evidence": {
                    "provider": "VirusTotal",
                    "flagged_domains": flagged_domains,
                },
            }
        )

    return {
        "provider": "VirusTotal",
        "enabled": True,
        "requested_domain_count": len(domains),
        "checked_domain_count": len(checked_reports),
        "findings": findings,
    }