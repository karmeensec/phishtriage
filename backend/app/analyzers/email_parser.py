import hashlib
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


MAX_EMAIL_SIZE = 2 * 1024 * 1024  # 2 MB

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"\])]+",
    re.IGNORECASE,
)


class EmailValidationError(ValueError):
    """Raised when an uploaded email fails validation."""


def validate_email_file(file_path: Path) -> None:
    """Validate an email file before parsing it."""

    if not file_path.exists():
        raise EmailValidationError("The email file does not exist.")

    if not file_path.is_file():
        raise EmailValidationError("The supplied path is not a file.")

    if file_path.suffix.lower() != ".eml":
        raise EmailValidationError("Only .eml files are supported.")

    if file_path.stat().st_size == 0:
        raise EmailValidationError("The email file is empty.")

    if file_path.stat().st_size > MAX_EMAIL_SIZE:
        raise EmailValidationError("The email exceeds the 2 MB size limit.")


def extract_text(message: Any) -> str:
    """Extract readable text without executing embedded content."""

    text_sections: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            if disposition == "attachment":
                continue

            if content_type not in {"text/plain", "text/html"}:
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

    return sorted(url for url in cleaned_urls if url)


def extract_attachments(message: Any) -> list[dict[str, Any]]:
    """Collect attachment metadata without opening or executing files."""

    attachments: list[dict[str, Any]] = []

    for part in message.iter_attachments():
        content = part.get_payload(decode=True) or b""

        attachments.append(
            {
                "filename": part.get_filename() or "unnamed",
                "content_type": part.get_content_type(),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )

    return attachments


def parse_email(file_name: str) -> dict[str, Any]:
    """Safely parse an email and return structured investigation data."""

    file_path = Path(file_name)
    validate_email_file(file_path)

    with file_path.open("rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    email_text = extract_text(message)

    return {
        "file": file_path.name,
        "subject": str(message.get("Subject", "")),
        "from": str(message.get("From", "")),
        "to": str(message.get("To", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "date": str(message.get("Date", "")),
        "message_id": str(message.get("Message-ID", "")),
        "authentication_results": str(
            message.get("Authentication-Results", "")
        ),
        "received_header_count": len(message.get_all("Received", [])),
        "urls": extract_urls(email_text),
        "attachments": extract_attachments(message),
    }