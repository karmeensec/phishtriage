"""Tests for the database configuration."""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from backend.app.database import Base
import pytest
from sqlalchemy.exc import IntegrityError

from backend.app.models import AnalysisRecord

def test_database_session_executes_query() -> None:
    """Verify that SQLAlchemy can use an isolated SQLite database."""

    test_engine = create_engine(
        "sqlite+pysqlite:///:memory:"
    )

    Base.metadata.create_all(test_engine)

    with Session(test_engine) as session:
        result = session.scalar(text("SELECT 1"))

    assert result == 1


def test_analysis_record_can_be_saved() -> None:
    """Verify that a safe analysis summary can be persisted."""

    test_engine = create_engine(
        "sqlite+pysqlite:///:memory:"
    )

    Base.metadata.create_all(test_engine)

    record = AnalysisRecord(
        file_name="phishing_email.eml",
        file_sha256="a" * 64,
        subject="Urgent account verification",
        sender="attacker@example.test",
        risk_score=100,
        risk_level="critical",
        finding_count=2,
        findings=[
            {
                "rule_id": "HDR-SPF",
                "severity": "high",
                "score": 25,
            }
        ],
    )

    with Session(test_engine) as session:
        session.add(record)
        session.commit()

        saved_record = session.get(
            AnalysisRecord,
            record.id,
        )

        assert saved_record is not None
        assert saved_record.risk_score == 100
        assert saved_record.risk_level == "critical"
        assert saved_record.file_sha256 == "a" * 64


def test_database_rejects_invalid_risk_score() -> None:
    """Verify that the database rejects scores above 100."""

    test_engine = create_engine(
        "sqlite+pysqlite:///:memory:"
    )

    Base.metadata.create_all(test_engine)

    invalid_record = AnalysisRecord(
        file_name="invalid.eml",
        file_sha256="b" * 64,
        subject=None,
        sender=None,
        risk_score=101,
        risk_level="critical",
        finding_count=0,
        findings=[],
    )

    with Session(test_engine) as session:
        session.add(invalid_record)

        with pytest.raises(IntegrityError):
            session.commit()