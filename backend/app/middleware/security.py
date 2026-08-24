from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import Request
from starlette.responses import Response


CallNext = Callable[[Request], Awaitable[Response]]


async def add_security_headers(
    request: Request,
    call_next: CallNext,
) -> Response:
    """Add defensive headers and a unique request identifier."""

    # Generate our own ID instead of trusting a client-provided value.
    request_id = str(uuid4())
    request.state.request_id = request_id

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "frame-ancestors 'none'"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response