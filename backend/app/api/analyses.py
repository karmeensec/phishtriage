"""API endpoints for analysis history."""

from typing import Annotated
from backend.app.models import AnalysisRecord

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

from backend.app.database import get_db
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
) -> AnalysisHistoryResponse:
    """Return recent analysis summaries with pagination."""

    try:
        records, total = list_analysis_records(
            db,
            limit=limit,
            offset=offset,
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