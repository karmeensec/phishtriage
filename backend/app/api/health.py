from fastapi import APIRouter


router = APIRouter(
    prefix="/health",
    tags=["Health"],
)


@router.get("")
def health_check() -> dict[str, str]:
    """Confirm that the API service is available."""

    # Return minimal information to avoid leaking internal details.
    return {
        "status": "ok",
    }