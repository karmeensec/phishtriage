from uuid import UUID

from fastapi.testclient import TestClient
from pytest import MonkeyPatch

from backend.app.main import (
    app,
    get_allowed_origins,
)

from backend.app.middleware.rate_limit import (
    ANALYSIS_RATE_LIMIT_REQUESTS,
    analysis_rate_limiter,
)


client = TestClient(app)


def test_security_headers_are_present() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == (
        "nosniff"
    )
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == (
        "no-referrer"
    )
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == (
        "frame-ancestors 'none'"
    )


def test_request_id_is_valid_uuid() -> None:
    response = client.get("/api/v1/health")

    request_id = response.headers["x-request-id"]
    parsed_id = UUID(request_id)

    assert parsed_id.version == 4


def test_each_request_receives_unique_id() -> None:
    first_response = client.get("/api/v1/health")
    second_response = client.get("/api/v1/health")

    assert (
        first_response.headers["x-request-id"]
        != second_response.headers["x-request-id"]
    )


def test_react_origin_is_allowed() -> None:
    response = client.options(
        "/api/v1/analyze",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers[
        "access-control-allow-origin"
    ] == "http://localhost:5173"


def test_alternate_vite_origin_is_allowed() -> None:
    response = client.options(
        "/api/v1/analyze",
        headers={
            "Origin": "http://localhost:5174",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers[
        "access-control-allow-origin"
    ] == "http://localhost:5174"


def test_unknown_origin_is_not_allowed() -> None:
    response = client.options(
        "/api/v1/analyze",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in (
        response.headers
    )


def test_allowed_origins_can_come_from_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ALLOWED_ORIGINS",
        (
            "https://phishtriage.example,"
            " https://www.phishtriage.example/"
        ),
    )

    assert get_allowed_origins() == [
        "https://phishtriage.example",
        "https://www.phishtriage.example",
    ]


def test_analysis_endpoint_is_rate_limited() -> None:
    analysis_rate_limiter.reset()

    try:
        for _ in range(ANALYSIS_RATE_LIMIT_REQUESTS):
            response = client.post(
                "/api/v1/analyze",
                files={
                    "file": (
                        "invalid.txt",
                        b"Not an email",
                        "text/plain",
                    )
                },
            )

            assert response.status_code == 400

        blocked_response = client.post(
            "/api/v1/analyze",
            files={
                "file": (
                    "invalid.txt",
                    b"Not an email",
                    "text/plain",
                )
            },
        )

        assert blocked_response.status_code == 429
        assert blocked_response.json()["detail"] == (
            "Too many analysis requests. "
            "Please try again later."
        )
        assert int(
            blocked_response.headers["retry-after"]
        ) >= 1
    finally:
        analysis_rate_limiter.reset()