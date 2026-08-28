# Result Writer: единственный сервис с доступом к PostgreSQL.
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "pydantic>=2.9" "pydantic-settings>=2.6" "redis>=5.2" "asyncpg>=0.30" \
    "opentelemetry-api>=1.29" "opentelemetry-sdk>=1.29" \
    "opentelemetry-exporter-otlp-proto-http>=1.29" "prometheus-client>=0.21"

COPY packages/vscommon /app/vscommon
COPY services/writer/writerapp /app/writerapp
COPY services/writer/migrations /app/migrations

RUN adduser --disabled-password --uid 10001 writer \
    && chown -R writer:writer /app
USER writer

ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
CMD ["python", "-m", "writerapp.main"]
