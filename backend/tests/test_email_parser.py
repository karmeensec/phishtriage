from pathlib import Path

import pytest

from backend.app.analyzers.email_parser import (
    EmailValidationError,
    extract_urls,
    parse_email,
    validate_email_file,
)


SAMPLE_EMAIL = (
    Path(__file__).parent
    / "sample_emails"
    / "legitimate_email.eml"
)

PHISHING_EMAIL = (
    Path(__file__).parent
    / "sample_emails"
    / "phishing_email.eml"
)

ATTACHMENT_EMAIL = (
    Path(__file__).parent
    / "sample_emails"
    / "attachment_phishing_email.eml"
)


def test_parse_email_extracts_expected_information() -> None:
    result = parse_email(str(SAMPLE_EMAIL))

    assert result["file"] == "legitimate_email.eml"
    assert result["subject"] == "Security portal notification"
    assert result["from"] == "Security Team <security@example.com>"
    assert result["reply_to"] == "security@example.com"

    assert result["urls"] == [
        "https://portal.example.com/security"
    ]

    assert result["attachments"] == []

    # The legitimate email should have no suspicious findings.
    assert result["header_analysis"]["findings"] == []
    assert result["url_analysis"]["findings"] == []
    assert result["findings"] == []
    assert result["attachment_analysis"]["findings"] == []
    assert result["body_analysis"]["findings"] == []

    assert result["risk_assessment"]["score"] == 0
    assert result["risk_assessment"]["level"] == "low"


def test_phishing_email_produces_header_findings() -> None:
    result = parse_email(str(PHISHING_EMAIL))

    header_analysis = result["header_analysis"]

    assert header_analysis["sender_domain"] == (
        "microsoft-security.example"
    )

    assert header_analysis["reply_to_domain"] == (
        "credential-check.example"
    )

    assert header_analysis["authentication"] == {
        "spf": "fail",
        "dkim": "fail",
        "dmarc": "fail",
    }

    header_rule_ids = {
        finding["rule_id"]
        for finding in header_analysis["findings"]
    }

    assert header_rule_ids == {
        "HDR-001",
        "HDR-SPF",
        "HDR-DKIM",
        "HDR-DMARC",
    }

    url_rule_ids = {
        finding["rule_id"]
        for finding in result["url_analysis"]["findings"]
    }

    assert url_rule_ids == {
        "URL-HTTP",
        "URL-IP",
    }

    body_rule_ids = {
        finding["rule_id"]
        for finding in result["body_analysis"]["findings"]
    }

    assert body_rule_ids == {
        "BODY-URGENCY",
        "BODY-ACCOUNT",
        "BODY-CREDENTIALS",
    }

    combined_rule_ids = {
        finding["rule_id"]
        for finding in result["findings"]
    }

    assert combined_rule_ids == {
        "HDR-001",
        "HDR-SPF",
        "HDR-DKIM",
        "HDR-DMARC",
        "URL-HTTP",
        "URL-IP",
        "BODY-URGENCY",
        "BODY-ACCOUNT",
        "BODY-CREDENTIALS",
    }

    # The raw score is 185, but the public score is capped at 100.
    assert result["risk_assessment"]["uncapped_score"] == 185
    assert result["risk_assessment"]["score"] == 100
    assert result["risk_assessment"]["level"] == "critical"
    assert result["risk_assessment"]["finding_count"] == 9


def test_extract_urls_removes_duplicates() -> None:
    text = """
    Visit https://example.com/login.
    Visit https://example.com/login again.
    Also review https://example.net/security.
    """

    result = extract_urls(text)

    assert result == [
        "https://example.com/login",
        "https://example.net/security",
    ]


def test_rejects_non_eml_file(tmp_path: Path) -> None:
    invalid_file = tmp_path / "message.txt"
    invalid_file.write_text("Not an email", encoding="utf-8")

    with pytest.raises(
        EmailValidationError,
        match="Only .eml files are supported",
    ):
        validate_email_file(invalid_file)


def test_rejects_empty_email(tmp_path: Path) -> None:
    empty_email = tmp_path / "empty.eml"
    empty_email.write_bytes(b"")

    with pytest.raises(
        EmailValidationError,
        match="email file is empty",
    ):
        validate_email_file(empty_email)


def test_rejects_missing_email(tmp_path: Path) -> None:
    missing_email = tmp_path / "missing.eml"

    with pytest.raises(
        EmailValidationError,
        match="does not exist",
    ):
        validate_email_file(missing_email)


def test_attachment_email_produces_attachment_findings() -> None:
    result = parse_email(str(ATTACHMENT_EMAIL))

    assert len(result["attachments"]) == 1
    assert result["attachments"][0]["filename"] == (
        "invoice.pdf.exe"
    )

    attachment_rule_ids = {
        finding["rule_id"]
        for finding in result["attachment_analysis"]["findings"]
    }

    assert attachment_rule_ids == {
        "ATT-DANGEROUS",
        "ATT-DOUBLE",
    }

    assert result["risk_assessment"]["uncapped_score"] == 55
    assert result["risk_assessment"]["score"] == 55
    assert result["risk_assessment"]["level"] == "high"
    assert result["risk_assessment"]["finding_count"] == 2