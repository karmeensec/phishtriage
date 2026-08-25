"""Services for safely persisting analysis history."""

from hashlib import sha256
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models import AnalysisRecord
from sqlalchemy import func, select


def _safe_filename(file_name: str) -> str:
    """Remove path components and control characters."""

    normalized_name = file_name.replace("\\", "/")

    safe_name = (
        normalized_name
        .rsplit("/", maxsplit=1)[-1]
        .replace("\x00", "")
        .strip()
    )

    return (safe_name or "unnamed.eml")[:255]


def _optional_text(
    value: object,
    maximum_length: int,
) -> str | None:
    """Convert optional metadata to bounded database text."""

    if value is None:
        return None

    return str(value)[:maximum_length]


def save_analysis_record(
    db: Session,
    *,
    file_name: str,
    file_content: bytes,
    analysis: dict[str, Any],
) -> AnalysisRecord:
    """Save a minimized analysis summary and return its record."""

    risk_assessment = analysis["risk_assessment"]
    findings = analysis.get("findings", [])

    record = AnalysisRecord(
        file_name=_safe_filename(file_name),
        file_sha256=sha256(file_content).hexdigest(),
        subject=_optional_text(
            analysis.get("subject"),
            998,
        ),
        sender=_optional_text(
            analysis.get("from"),
            512,
        ),
        risk_score=int(risk_assessment["score"]),
        risk_level=str(risk_assessment["level"]),
        finding_count=int(
            risk_assessment["finding_count"]
        ),
        findings=findings,
    )

    db.add(record)

    try:
        db.commit()
        db.refresh(record)
    except SQLAlchemyError:
        db.rollback()
        raise

    return record


def list_analysis_records(
    db: Session,
    *,
    limit: int,
    offset: int,
) -> tuple[list[AnalysisRecord], int]:
    """Return recent analyses and the total record count."""

    statement = (
        select(AnalysisRecord)
        .order_by(
            AnalysisRecord.created_at.desc(),
            AnalysisRecord.id.desc(),
        )
        .offset(offset)
        .limit(limit)
    )

    records = list(
        db.scalars(statement).all()
    )

    total = db.scalar(
        select(func.count(AnalysisRecord.id))
    ) or 0

    return records, total