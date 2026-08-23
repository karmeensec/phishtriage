from fastapi import FastAPI

from backend.app.api.health import router as health_router


app = FastAPI(
    title="PhishTriage API",
    description=(
        "Secure phishing email analysis and incident triage API."
    ),
    version="0.1.0",
)

app.include_router(
    health_router,
    prefix="/api/v1",
)