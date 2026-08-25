"""SQLAlchemy database models."""

from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Integer,
    JSON,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base


class AnalysisRecord(Base):
    """Persist a privacy-conscious summary of an email analysis."""

    __tablename__ = "analysis_records"

    __table_args__ = (
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_analysis_risk_score",
        ),
        CheckConstraint(
            "finding_count >= 0",
            name="ck_analysis_finding_count",
        ),
        CheckConstraint(
            (
                "risk_level IN "
                "('low', 'medium', 'high', 'critical')"
            ),
            name="ck_analysis_risk_level",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    file_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    file_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    subject: Mapped[str | None] = mapped_column(
        String(998),
        nullable=True,
    )

    sender: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    finding_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    findings: Mapped[list[dict[str, object]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        default=lambda: datetime.now(timezone.utc),
    )