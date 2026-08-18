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