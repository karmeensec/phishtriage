from backend.app.analyzers.attachment_analyzer import (
    analyze_attachment,
)


def get_rule_ids(result: dict) -> set[str]:
    return {
        finding["rule_id"]
        for finding in result["findings"]
    }


def create_attachment(filename: str) -> dict:
    return {
        "filename": filename,
        "content_type": "application/octet-stream",
        "size_bytes": 100,
        "sha256": "example-hash",
    }


def test_normal_pdf_has_no_findings() -> None:
    result = analyze_attachment(
        create_attachment("report.pdf")
    )

    assert result["safe_filename"] == "report.pdf"
    assert result["extension"] == ".pdf"
    assert result["findings"] == []


def test_detects_executable_attachment() -> None:
    result = analyze_attachment(
        create_attachment("payload.exe")
    )

    assert get_rule_ids(result) == {
        "ATT-DANGEROUS",
    }


def test_detects_double_extension() -> None:
    result = analyze_attachment(
        create_attachment("invoice.pdf.exe")
    )

    assert get_rule_ids(result) == {
        "ATT-DANGEROUS",
        "ATT-DOUBLE",
    }


def test_detects_macro_enabled_document() -> None:
    result = analyze_attachment(
        create_attachment("invoice.docm")
    )

    assert get_rule_ids(result) == {
        "ATT-MACRO",
    }


def test_removes_path_components() -> None:
    result = analyze_attachment(
        create_attachment("../../payload.exe")
    )

    assert result["safe_filename"] == "payload.exe"

    assert get_rule_ids(result) == {
        "ATT-PATH",
        "ATT-DANGEROUS",
    }