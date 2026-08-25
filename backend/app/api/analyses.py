"""API endpoints for analysis history."""

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas import AnalysisHistoryResponse
from backend.app.services.analysis_history import (
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