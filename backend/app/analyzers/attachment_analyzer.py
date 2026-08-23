from pathlib import Path
from typing import Any


DANGEROUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
}

MACRO_DOCUMENT_EXTENSIONS = {
    ".docm",
    ".pptm",
    ".xlsm",
}


def normalize_filename(filename: str) -> str:
    """Remove path components from an untrusted filename."""

    normalized = filename.replace("\\", "/")
    safe_filename = normalized.rsplit("/", 1)[-1].strip()

    return safe_filename or "unnamed"


def create_attachment_finding(
    rule_id: str,
    title: str,
    severity: str,
    score: int,
    filename: str,
) -> dict[str, Any]:
    """Create a consistent attachment finding."""

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "score": score,
        "evidence": {
            "filename": filename,
        },
    }


def analyze_attachment(
    attachment: dict[str, Any],
) -> dict[str, Any]:
    """Analyze attachment metadata without opening the file."""

    original_filename = str(
        attachment.get("filename", "unnamed")
    )

    safe_filename = normalize_filename(original_filename)

    suffixes = [
        suffix.lower()
        for suffix in Path(safe_filename).suffixes
    ]

    final_extension = suffixes[-1] if suffixes else ""
    findings: list[dict[str, Any]] = []

    if original_filename != safe_filename:
        findings.append(
            create_attachment_finding(
                rule_id="ATT-PATH",
                title="Attachment filename contains path components",
                severity="high",
                score=25,
                filename=original_filename,
            )
        )

    if final_extension in DANGEROUS_EXTENSIONS:
        findings.append(
            create_attachment_finding(
                rule_id="ATT-DANGEROUS",
                title=(
                    "Attachment uses a potentially dangerous "
                    "file extension"
                ),
                severity="high",
                score=30,
                filename=safe_filename,
            )
        )

    if (
        len(suffixes) >= 2
        and final_extension in DANGEROUS_EXTENSIONS
    ):
        findings.append(
            create_attachment_finding(
                rule_id="ATT-DOUBLE",
                title=(
                    "Attachment uses a deceptive double extension"
                ),
                severity="high",
                score=25,
                filename=safe_filename,
            )
        )

    if final_extension in MACRO_DOCUMENT_EXTENSIONS:
        findings.append(
            create_attachment_finding(
                rule_id="ATT-MACRO",
                title="Attachment is a macro-enabled document",
                severity="medium",
                score=20,
                filename=safe_filename,
            )
        )

    return {
        **attachment,
        "original_filename": original_filename,
        "safe_filename": safe_filename,
        "extension": final_extension,
        "findings": findings,
    }


def analyze_attachments(
    attachments: list[dict[str, Any]],
) -> dict[str, Any]:
    """Analyze multiple attachments and combine findings."""

    analyses = [
        analyze_attachment(attachment)
        for attachment in attachments
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