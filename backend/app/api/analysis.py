from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.analyzers.email_parser import (
    MAX_EMAIL_SIZE,
    EmailValidationError,
    parse_email_bytes,
)
from backend.app.config import public_demo_mode_enabled
from backend.app.database import get_db
from backend.app.services.analysis_history import (
    save_analysis_record,
)


router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)


@router.post("")
async def analyze_email(
    file: Annotated[
        UploadFile,
        File(description="Email file in .eml format"),
    ],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """Analyze an email and optionally save safe history."""

    try:
        file_content = await file.read(
            MAX_EMAIL_SIZE + 1
        )
    finally:
        await file.close()

    if len(file_content) > MAX_EMAIL_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="The email exceeds the 2 MB size limit.",
        )

    try:
        analysis_result = parse_email_bytes(
            file_content=file_content,
            file_name=file.filename or "",
        )
    except EmailValidationError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    if public_demo_mode_enabled():
        return {
            **analysis_result,
            "analysis_id": None,
            "persisted": False,
        }

    try:
        record = save_analysis_record(
            db,
            file_name=analysis_result["file"],
            file_content=file_content,
            analysis=analysis_result,
        )
    except SQLAlchemyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Analysis history is temporarily unavailable."
            ),
        ) from error

    return {
        **analysis_result,
        "analysis_id": record.id,
        "persisted": True,
    }