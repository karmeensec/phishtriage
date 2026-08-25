"""Database connection and session configuration."""

from collections.abc import Generator
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


BACKEND_DIRECTORY = Path(__file__).resolve().parent.parent
SQLITE_DATABASE_FILE = BACKEND_DIRECTORY / "phishtriage.db"

DEFAULT_DATABASE_URL = (
    f"sqlite:///{SQLITE_DATABASE_FILE.as_posix()}"
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    DEFAULT_DATABASE_URL,
)

connect_args = (
    {"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class inherited by database models."""


def get_db() -> Generator[Session, None, None]:
    """Provide a database session and always close it afterward."""

    with SessionLocal() as session:
        yield session