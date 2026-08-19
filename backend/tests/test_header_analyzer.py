from backend.app.analyzers.header_analyzer import (
    analyze_headers,
    extract_email_domain,
    parse_authentication_results,
)


def test_extract_email_domain() -> None:
    result = extract_email_domain(
        "Security Team <security@example.com>"
    )

    assert result == "example.com"


def test_parse_successful_authentication_results() -> None:
    header = (
        "mail.example.net; "
        "spf=pass; "
        "dkim=pass; "
        "dmarc=pass"
    )

    result = parse_authentication_results(header)

    assert result == {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
    }


def test_detects_sender_reply_to_mismatch() -> None:
    result = analyze_headers(
        sender="Support <support@example.com>",
        reply_to="Attacker <steal@example.net>",
        authentication_header=(
            "spf=pass; dkim=pass; dmarc=pass"
        ),
    )

    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule_id"] == "HDR-001"
    assert result["findings"][0]["severity"] == "medium"


def test_detects_authentication_failures() -> None:
    result = analyze_headers(
        sender="Security <security@example.com>",
        reply_to="security@example.com",
        authentication_header=(
            "spf=fail; dkim=fail; dmarc=fail"
        ),
    )

    rule_ids = {
        finding["rule_id"]
        for finding in result["findings"]
    }

    assert rule_ids == {
        "HDR-SPF",
        "HDR-DKIM",
        "HDR-DMARC",
    }

    assert all(
        finding["severity"] == "high"
        for finding in result["findings"]
    )