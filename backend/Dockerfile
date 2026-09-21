FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt

RUN pip install \
    --no-cache-dir \
    --requirement /app/backend/requirements.txt

COPY alembic.ini /app/alembic.ini
COPY backend /app/backend

RUN useradd --create-home appuser \
    && mkdir --parents /data \
    && chown --recursive appuser:appuser /app /data

USER appuser

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]