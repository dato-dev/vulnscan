FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
RUN pip install --no-cache-dir "pydantic>=2.9" "pydantic-settings>=2.6" "httpx>=0.28" \
    "fastapi>=0.115" "uvicorn[standard]>=0.32" \
    "opentelemetry-api>=1.29" "opentelemetry-sdk>=1.29" \
    "opentelemetry-exporter-otlp-proto-http>=1.29" "prometheus-client>=0.21"

COPY packages/vscommon /app/vscommon
COPY services/bot/botapp /app/botapp

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan
USER 10001

CMD ["python", "-m", "botapp.main"]
