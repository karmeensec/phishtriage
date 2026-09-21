"""API endpoints for analysis history."""

from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    status,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.config import public_demo_mode_enabled
from backend.app.database import get_db
from backend.app.models import AnalysisRecord
from backend.app.schemas import (
    AnalysisDetail,
    AnalysisHistoryResponse,
)
from backend.app.services.analysis_history import (
    get_analysis_record,
    list_analysis_records,
)


router = APIRouter(
    prefix="/analyses",
    tags=["Analysis History"],
)


@router.get(
    "",
    response_model=AnalysisHistoryResponse,
)
def get_analysis_history(
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[
        int,
        Query(ge=1, le=100),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0),
    ] = 0,
    search: Annotated[
        str | None,
        Query(max_length=200),
    ] = None,
    risk_level: Annotated[
        Literal[
            "low",
            "medium",
            "high",
            "critical",
        ] | None,
        Query(),
    ] = None,
) -> AnalysisHistoryResponse:
    """Return filtered analysis summaries with pagination."""

    if public_demo_mode_enabled():
        return AnalysisHistoryResponse(
            items=[],
            total=0,
            limit=limit,
            offset=offset,
            persistence_enabled=False,
        )

    try:
        records, total = list_analysis_records(
            db,
            limit=limit,
            offset=offset,
            search=search,
            risk_level=risk_level,
        )
    except SQLAlchemyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Analysis history is temporarily unavailable."
            ),
        ) from error

    return AnalysisHistoryResponse(
        items=records,
        total=total,
        limit=limit,
        offset=offset,
        persistence_enabled=True,
    )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisDetail,
)
def get_analysis_detail(
    db: Annotated[Session, Depends(get_db)],
    analysis_id: Annotated[
        int,
        Path(ge=1),
    ],
) -> AnalysisRecord:
    """Return one saved analysis without raw email content."""

    if public_demo_mode_enabled():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Analysis history is unavailable "
                "in public demo mode."
            ),
        )

    try:
        record = get_analysis_record(
            db,
            analysis_id=analysis_id,
        )
    except SQLAlchemyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Analysis history is temporarily unavailable."
            ),
        ) from error

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis record was not found.",
        )

    return record