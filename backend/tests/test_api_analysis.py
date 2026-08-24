from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.analyzers.email_parser import MAX_EMAIL_SIZE
from backend.app.main import app


client = TestClient(app)

SAMPLE_DIRECTORY = (
    Path(__file__).parent
    / "sample_emails"
)

PHISHING_EMAIL = (
    SAMPLE_DIRECTORY
    / "phishing_email.eml"
)


def test_analyzes_uploaded_phishing_email() -> None:
    file_content = PHISHING_EMAIL.read_bytes()

    response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "phishing_email.eml",
                file_content,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200

    result = response.json()

    assert result["file"] == "phishing_email.eml"
    assert result["risk_assessment"]["score"] == 100
    assert result["risk_assessment"]["level"] == "critical"
    assert result["risk_assessment"]["finding_count"] == 9


def test_rejects_incorrect_extension() -> None:
    response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "email.txt",
                b"From: test@example.com",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Only .eml files are supported."
    )


def test_rejects_empty_upload() -> None:
    response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "empty.eml",
                b"",
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "The email file is empty."
    )


def test_rejects_oversized_upload() -> None:
    oversized_content = b"A" * (
        MAX_EMAIL_SIZE + 1
    )

    response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "oversized.eml",
                oversized_content,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 413
    assert response.json()["detail"] == (
        "The email exceeds the 2 MB size limit."
    )


def test_rejects_fake_email_content() -> None:
    response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "fake.eml",
                b"This is not an email.",
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 400
    assert "recognizable email headers" in (
        response.json()["detail"]
    )


def test_rejects_filename_with_path_components() -> None:
    file_content = PHISHING_EMAIL.read_bytes()

    response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "../phishing_email.eml",
                file_content,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "The uploaded filename is invalid."
    )


def test_requires_an_uploaded_file() -> None:
    response = client.post("/api/v1/analyze")

    assert response.status_code == 422