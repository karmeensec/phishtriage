"""Pydantic response schemas for the API."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)



class AnalysisSummary(BaseModel):
    """Safe summary returned in analysis-history listings."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    file_name: str
    subject: str | None
    sender: str | None
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal[
        "low",
        "medium",
        "high",
        "critical",
    ]
    finding_count: int = Field(ge=0)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def ensure_utc_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        """Ensure database timestamps are explicitly UTC."""

        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)


class AnalysisHistoryResponse(BaseModel):
    """Paginated analysis-history response."""

    items: list[AnalysisSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)