FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Системных зависимостей нет: gateway парсеров не запускает.
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "fastapi>=0.115" "uvicorn[standard]>=0.32" "pydantic>=2.9" \
    "pydantic-settings>=2.6" "redis>=5.2" "httpx>=0.28" \
    "python-multipart>=0.0.12" "boto3>=1.35" \
    "opentelemetry-api>=1.29" "opentelemetry-sdk>=1.29" \
    "opentelemetry-exporter-otlp-proto-http>=1.29" "prometheus-client>=0.21"

COPY packages/vscommon /app/vscommon
COPY services/gateway/gateway_app /app/gateway_app

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan
USER 10001

EXPOSE 8080
CMD ["uvicorn", "gateway_app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
