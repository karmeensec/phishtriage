from collections.abc import Generator
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.analyzers.email_parser import MAX_EMAIL_SIZE
from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models import AnalysisRecord
from sqlalchemy import create_engine, select


client = TestClient(app)

SAMPLE_DIRECTORY = (
    Path(__file__).parent
    / "sample_emails"
)

PHISHING_EMAIL = (
    SAMPLE_DIRECTORY
    / "phishing_email.eml"
)

@pytest.fixture(autouse=True)
def isolated_database(
) -> Generator[sessionmaker[Session], None, None]:
    """Use a fresh in-memory database for every API test."""

    test_engine = create_engine(
    "sqlite+pysqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

    Base.metadata.create_all(test_engine)

    test_session_factory = sessionmaker(
        bind=test_engine,
        autoflush=False,
        expire_on_commit=False,
    )

    def override_get_db(
    ) -> Generator[Session, None, None]:
        with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    yield test_session_factory

    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(test_engine)
    test_engine.dispose()


def test_analyzes_uploaded_phishing_email(
    isolated_database: sessionmaker[Session],
) -> None:
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
    assert isinstance(result["analysis_id"], int)

    with isolated_database() as session:
        saved_record = session.scalar(
            select(AnalysisRecord)
        )

    assert saved_record is not None
    assert saved_record.id == result["analysis_id"]
    assert saved_record.risk_score == 100
    assert saved_record.risk_level == "critical"
    assert saved_record.file_sha256 == sha256(
        file_content
    ).hexdigest()


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


def test_lists_recent_analysis_history(
    isolated_database: sessionmaker[Session],
) -> None:
    file_content = PHISHING_EMAIL.read_bytes()

    first_response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "first_email.eml",
                file_content,
                "message/rfc822",
            )
        },
    )

    second_response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                "second_email.eml",
                file_content,
                "message/rfc822",
            )
        },
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    response = client.get(
        "/api/v1/analyses?limit=1&offset=0"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["total"] == 2
    assert result["limit"] == 1
    assert result["offset"] == 0
    assert len(result["items"]) == 1

    newest_record = result["items"][0]

    assert newest_record["file_name"] == (
        "second_email.eml"
    )
    assert newest_record["risk_score"] == 100
    assert newest_record["risk_level"] == "critical"

    # Sensitive or detailed fields are excluded from listings.
    assert "file_sha256" not in newest_record
    assert "findings" not in newest_record

    assert newest_record["created_at"].endswith(
        ("Z", "+00:00")
    )


def test_rejects_invalid_history_pagination() -> None:
    invalid_limits = [
        client.get("/api/v1/analyses?limit=0"),
        client.get("/api/v1/analyses?limit=101"),
        client.get("/api/v1/analyses?offset=-1"),
    ]

    assert all(
        response.status_code == 422
        for response in invalid_limits
    )