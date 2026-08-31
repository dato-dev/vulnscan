FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# ghostscript нужен профилю CDR strict (растеризация PDF),
# libmagic1 — определению фактического типа файла.
# qpdf отдельно не ставим: он идёт внутри wheel'а pikepdf.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ghostscript libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir \
    "pydantic>=2.9" "pydantic-settings>=2.6" "redis>=5.2" "httpx>=0.28" \
    "boto3>=1.35" "pikepdf>=9.4" "pillow>=11.0" "clamd>=1.0.2" "yara-python>=4.5" \
    "python-magic>=0.4.27"

# Версии SDK наблюдаемости — из одного файла на все образы. Через `>=` каждая
# пересборка могла принести другую версию, а какая работает на стенде —
# выяснялось бы только изнутри контейнера.
COPY requirements-telemetry.txt requirements-metrics.txt ./
RUN pip install --no-cache-dir -r requirements-telemetry.txt

COPY packages/vscommon /app/vscommon
COPY services/worker/worker_app /app/worker_app
COPY rules /app/rules

# Файлы разбираются под непривилегированным пользователем с read-only корнем.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan
USER 10001

CMD ["python", "-m", "worker_app.main"]
