FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Системных зависимостей нет: gateway парсеров не запускает.
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
    "fastapi>=0.115" "uvicorn[standard]>=0.32" "pydantic>=2.9" \
    "pydantic-settings>=2.6" "redis>=5.2" "httpx>=0.28" \
    "python-multipart>=0.0.12" "boto3>=1.35"

# Версии SDK наблюдаемости — из одного файла на все образы. Через `>=` каждая
# пересборка могла принести другую версию, а какая работает на стенде —
# выяснялось бы только изнутри контейнера.
COPY requirements-telemetry.txt requirements-metrics.txt ./
RUN pip install --no-cache-dir -r requirements-telemetry.txt

COPY packages/vscommon /app/vscommon
COPY services/gateway/gateway_app /app/gateway_app

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan
USER 10001

EXPOSE 8080
CMD ["uvicorn", "gateway_app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
