# Result Writer: единственный сервис с доступом к PostgreSQL.
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "pydantic>=2.9" "pydantic-settings>=2.6" "redis>=5.2" "asyncpg>=0.30"

# Версии SDK наблюдаемости — из одного файла на все образы. Через `>=` каждая
# пересборка могла принести другую версию, а какая работает на стенде —
# выяснялось бы только изнутри контейнера.
COPY requirements-telemetry.txt requirements-metrics.txt ./
RUN pip install --no-cache-dir -r requirements-telemetry.txt

COPY packages/vscommon /app/vscommon
COPY services/writer/writerapp /app/writerapp
COPY services/writer/migrations /app/migrations

RUN adduser --disabled-password --uid 10001 writer \
    && chown -R writer:writer /app
USER writer

ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
CMD ["python", "-m", "writerapp.main"]
