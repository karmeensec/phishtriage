import hashlib
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from backend.app.analyzers.attachment_analyzer import (
    analyze_attachments,
)
from backend.app.analyzers.body_analyzer import analyze_body
from backend.app.analyzers.header_analyzer import analyze_headers
from backend.app.analyzers.risk_scorer import calculate_risk
from backend.app.analyzers.url_analyzer import analyze_urls


MAX_EMAIL_SIZE = 2 * 1024 * 1024

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"\])]+",
    re.IGNORECASE,
)


class EmailValidationError(ValueError):
    """Raised when an uploaded email fails validation."""


def validate_email_file(file_path: Path) -> None:
    """Validate a local email file before reading it."""

    if not file_path.exists():
        raise EmailValidationError(
            "The email file does not exist."
        )

    if not file_path.is_file():
        raise EmailValidationError(
            "The supplied path is not a file."
        )

    if file_path.suffix.lower() != ".eml":
        raise EmailValidationError(
            "Only .eml files are supported."
        )

    file_size = file_path.stat().st_size

    if file_size == 0:
        raise EmailValidationError(
            "The email file is empty."
        )

    if file_size > MAX_EMAIL_SIZE:
        raise EmailValidationError(
            "The email exceeds the 2 MB size limit."
        )


def validate_email_bytes(
    file_content: bytes,
    file_name: str,
) -> None:
    """Validate an uploaded filename and its byte content."""

    if not file_name:
        raise EmailValidationError(
            "The uploaded file must have a filename."
        )

    # Reject path components rather than trusting a client filename.
    if (
        "/" in file_name
        or "\\" in file_name
        or "\x00" in file_name
    ):
        raise EmailValidationError(
            "The uploaded filename is invalid."
        )

    if Path(file_name).suffix.lower() != ".eml":
        raise EmailValidationError(
            "Only .eml files are supported."
        )

    if not file_content:
        raise EmailValidationError(
            "The email file is empty."
        )

    if len(file_content) > MAX_EMAIL_SIZE:
        raise EmailValidationError(
            "The email exceeds the 2 MB size limit."
        )


def extract_text(message: Any) -> str:
    """Extract readable text without executing embedded content."""

    text_sections: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            if disposition == "attachment":
                continue

            if content_type not in {
                "text/plain",
                "text/html",
            }:
                continue

            try:
                content = part.get_content()
            except (LookupError, UnicodeDecodeError):
                continue

            if isinstance(content, str):
                text_sections.append(content)
    else:
        try:
            content = message.get_content()
        except (LookupError, UnicodeDecodeError):
            content = ""

        if isinstance(content, str):
            text_sections.append(content)

    return "\n".join(text_sections)


def extract_urls(text: str) -> list[str]:
    """Extract, clean and deduplicate HTTP and HTTPS URLs."""

    trailing_punctuation = ".,;:!?)]}"

    cleaned_urls = {
        url.rstrip(trailing_punctuation)
        for url in URL_PATTERN.findall(text)
    }

    return sorted(
        url
        for url in cleaned_urls
        if url
    )


def extract_attachments(
    message: Any,
) -> list[dict[str, Any]]:
    """Collect metadata without opening or executing attachments."""

    attachments: list[dict[str, Any]] = []

    for part in message.iter_attachments():
        # Decode only as bounded bytes for hashing and metadata.
        content = part.get_payload(decode=True) or b""

        attachments.append(
            {
                "filename": (
                    part.get_filename() or "unnamed"
                ),
                "content_type": part.get_content_type(),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(
                    content
                ).hexdigest(),
            }
        )

    return attachments


def build_analysis_result(
    message: Any,
    file_name: str,
) -> dict[str, Any]:
    """Run all analyzers against a parsed email message."""

    subject = str(message.get("Subject", ""))
    email_text = extract_text(message)
    email_urls = extract_urls(email_text)
    attachments = extract_attachments(message)

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))

    authentication_results = str(
        message.get("Authentication-Results", "")
    )

    spam_confidence_header = str(
        message.get(
            "X-MS-Exchange-Organization-SCL",
            "",
        )
    )

    header_analysis = analyze_headers(
        sender=sender,
        reply_to=reply_to,
        return_path=return_path,
        authentication_header=authentication_results,
        spam_confidence_header=spam_confidence_header,
    )

    url_analysis = analyze_urls(email_urls)
    attachment_analysis = analyze_attachments(attachments)

    body_analysis = analyze_body(
        subject=subject,
        body=email_text,
    )

    combined_findings = [
        *header_analysis["findings"],
        *url_analysis["findings"],
        *attachment_analysis["findings"],
        *body_analysis["findings"],
    ]

    risk_assessment = calculate_risk(combined_findings)

    return {
        "file": file_name,
        "subject": subject,
        "from": sender,
        "to": str(message.get("To", "")),
        "reply_to": reply_to,
        "return_path": return_path,
        "date": str(message.get("Date", "")),
        "message_id": str(message.get("Message-ID", "")),
        "authentication_results": authentication_results,
        "received_header_count": len(
            message.get_all("Received", [])
        ),
        "urls": email_urls,
        "attachments": attachments,
        "header_analysis": header_analysis,
        "url_analysis": url_analysis,
        "attachment_analysis": attachment_analysis,
        "body_analysis": body_analysis,
        "findings": combined_findings,
        "risk_assessment": risk_assessment,
    }


def parse_email_bytes(
    file_content: bytes,
    file_name: str,
) -> dict[str, Any]:
    """Safely analyze uploaded email bytes without saving them."""

    validate_email_bytes(file_content, file_name)

    try:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(file_content)
    except (TypeError, ValueError) as error:
        raise EmailValidationError(
            "The email content could not be parsed."
        ) from error

    recognizable_headers = (
        "From",
        "To",
        "Subject",
        "Date",
        "Message-ID",
    )

    if not any(
        message.get(header)
        for header in recognizable_headers
    ):
        raise EmailValidationError(
            "The file does not contain recognizable email headers."
        )

    return build_analysis_result(
        message=message,
        file_name=file_name,
    )


def parse_email(file_name: str) -> dict[str, Any]:
    """Safely analyze a local .eml file."""

    file_path = Path(file_name)
    validate_email_file(file_path)

    file_content = file_path.read_bytes()

    return parse_email_bytes(
        file_content=file_content,
        file_name=file_path.name,
    )