# Notifier: доставка результатов клиентам.
#
# Единственный сервис, кроме gateway, которому нужны ключи тенантов. Он не
# разбирает недоверенный контент — только ходит HTTP наружу, поэтому секреты
# здесь допустимы, в отличие от воркера.
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "pydantic>=2.9" "pydantic-settings>=2.6" "redis>=5.2" "httpx>=0.28" \
    "opentelemetry-api>=1.29" "opentelemetry-sdk>=1.29" \
    "opentelemetry-exporter-otlp-proto-http>=1.29" "prometheus-client>=0.21"

COPY packages/vscommon /app/vscommon
COPY services/notifier/notifierapp /app/notifierapp

RUN adduser --disabled-password --uid 10001 notifier \
    && chown -R notifier:notifier /app
USER notifier

ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
CMD ["python", "-m", "notifierapp.main"]
