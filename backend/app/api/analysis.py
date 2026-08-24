from typing import Annotated, Any

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    UploadFile,
    status,
)

from backend.app.analyzers.email_parser import (
    MAX_EMAIL_SIZE,
    EmailValidationError,
    parse_email_bytes,
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
) -> dict[str, Any]:
    """Analyze one uploaded email without permanent storage."""

    try:
        # Read one extra byte so an oversized upload is detectable.
        file_content = await file.read(
            MAX_EMAIL_SIZE + 1
        )
    finally:
        # Release the upload resource even when reading fails.
        await file.close()

    if len(file_content) > MAX_EMAIL_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="The email exceeds the 2 MB size limit.",
        )

    try:
        return parse_email_bytes(
            file_content=file_content,
            file_name=file.filename or "",
        )
    except EmailValidationError as error:
        # Return only controlled validation messages.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error