FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
RUN pip install --no-cache-dir "pydantic>=2.9" "pydantic-settings>=2.6" "httpx>=0.28" \
    "fastapi>=0.115" "uvicorn[standard]>=0.32"

# Версии SDK наблюдаемости — из одного файла на все образы. Через `>=` каждая
# пересборка могла принести другую версию, а какая работает на стенде —
# выяснялось бы только изнутри контейнера.
COPY requirements-telemetry.txt requirements-metrics.txt ./
RUN pip install --no-cache-dir -r requirements-telemetry.txt

COPY packages/vscommon /app/vscommon
COPY services/bot/botapp /app/botapp

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan
USER 10001

CMD ["python", "-m", "botapp.main"]
