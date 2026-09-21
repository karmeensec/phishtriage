"""FastAPI application configuration."""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.analyses import router as analyses_router
from backend.app.api.analysis import router as analysis_router
from backend.app.api.health import router as health_router
from backend.app.middleware.security import (
    add_security_headers,
)


DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
)


def get_allowed_origins() -> list[str]:
    """Return explicitly permitted frontend origins."""

    configured_origins = os.getenv("ALLOWED_ORIGINS", "")

    if not configured_origins.strip():
        return list(DEFAULT_ALLOWED_ORIGINS)

    origins = [
        origin.strip().rstrip("/")
        for origin in configured_origins.split(",")
        if origin.strip()
    ]

    if "*" in origins:
        raise ValueError(
            "ALLOWED_ORIGINS must contain explicit origins."
        )

    return origins


ALLOWED_ORIGINS = get_allowed_origins()


app = FastAPI(
    title="PhishTriage API",
    description=(
        "Secure phishing email analysis and incident triage API."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

app.middleware("http")(add_security_headers)

app.include_router(
    health_router,
    prefix="/api/v1",
)

app.include_router(
    analysis_router,
    prefix="/api/v1",
)

app.include_router(
    analyses_router,
    prefix="/api/v1",
)