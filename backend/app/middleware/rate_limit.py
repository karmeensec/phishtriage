"""Lightweight rate limiting for expensive API operations."""

import math
import os
from collections import deque
from threading import Lock
from time import monotonic

from fastapi import HTTPException, Request, status


def get_positive_integer_setting(
    name: str,
    default: int,
) -> int:
    """Read a positive integer environment setting."""

    raw_value = os.getenv(name)

    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except ValueError as error:
        raise ValueError(
            f"{name} must be a positive integer."
        ) from error

    if value < 1:
        raise ValueError(
            f"{name} must be a positive integer."
        )

    return value


ANALYSIS_RATE_LIMIT_REQUESTS = (
    get_positive_integer_setting(
        "ANALYSIS_RATE_LIMIT_REQUESTS",
        20,
    )
)

ANALYSIS_RATE_LIMIT_WINDOW_SECONDS = (
    get_positive_integer_setting(
        "ANALYSIS_RATE_LIMIT_WINDOW_SECONDS",
        60,
    )
)


class InMemoryRateLimiter:
    """Track recent requests for each client identifier."""

    def __init__(
        self,
        *,
        maximum_requests: int,
        window_seconds: int,
    ) -> None:
        self.maximum_requests = maximum_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = {}
        self._lock = Lock()
        self._last_cleanup = monotonic()

    def check(self, client_identifier: str) -> int | None:
        """Record a request or return required retry seconds."""

        current_time = monotonic()
        cutoff = current_time - self.window_seconds

        with self._lock:
            self._remove_expired_clients(
                current_time=current_time,
                cutoff=cutoff,
            )

            request_times = self._requests.setdefault(
                client_identifier,
                deque(),
            )

            while (
                request_times
                and request_times[0] <= cutoff
            ):
                request_times.popleft()

            if len(request_times) >= self.maximum_requests:
                retry_after = math.ceil(
                    self.window_seconds
                    - (current_time - request_times[0])
                )

                return max(1, retry_after)

            request_times.append(current_time)

        return None

    def _remove_expired_clients(
        self,
        *,
        current_time: float,
        cutoff: float,
    ) -> None:
        """Periodically remove inactive client entries."""

        if (
            current_time - self._last_cleanup
            < self.window_seconds
        ):
            return

        expired_clients = [
            client_identifier
            for client_identifier, request_times
            in self._requests.items()
            if not request_times
            or request_times[-1] <= cutoff
        ]

        for client_identifier in expired_clients:
            self._requests.pop(client_identifier, None)

        self._last_cleanup = current_time

    def reset(self) -> None:
        """Clear stored request timestamps for testing."""

        with self._lock:
            self._requests.clear()
            self._last_cleanup = monotonic()


analysis_rate_limiter = InMemoryRateLimiter(
    maximum_requests=ANALYSIS_RATE_LIMIT_REQUESTS,
    window_seconds=ANALYSIS_RATE_LIMIT_WINDOW_SECONDS,
)


async def enforce_analysis_rate_limit(
    request: Request,
) -> None:
    """Reject excessive analysis attempts from one client."""

    client_identifier = (
        request.client.host
        if request.client is not None
        else "unknown-client"
    )

    retry_after = analysis_rate_limiter.check(
        client_identifier
    )

    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many analysis requests. "
                "Please try again later."
            ),
            headers={
                "Retry-After": str(retry_after),
            },
        )