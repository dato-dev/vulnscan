FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# ghostscript нужен профилю CDR strict (растеризация PDF),
# libmagic1 — определению фактического типа файла.
# qpdf отдельно не ставим: он идёт внутри wheel'а pikepdf.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ghostscript libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# uv приезжает готовым бинарником из своего образа. Раньше он ставился pip'ом —
# это был единственный вызов pip во всём репозитории; теперь pip не участвует
# в сборке вовсе.
#
# Цена решения названа честно: в цепочку сборки добавился ghcr.io. Раньше от
# него отказывались именно поэтому. Размен принят ради того, чтобы установщик
# был один и тот же локально и в образе, без промежуточного pip.
#
# Версия закреплена точно. Плавающий тег установщика означал бы, что состав
# образа меняется от пересборки к пересборке при неизменных исходниках.
COPY --from=ghcr.io/astral-sh/uv:0.11.25 /uv /usr/local/bin/uv

# Состав образа берётся из `uv.lock`, и только из своей группы. Общий список
# зависимостей означал бы, что gateway тащит pikepdf, pillow и yara-python —
# три библиотеки на C, разбирающие недоверенный ввод, в образ, который ничего
# не разбирает.
#
# `--frozen`: лок не пересчитывается при сборке. Без этого образ мог бы уехать
# на версиях, которых никто не видел, и разошлось бы это молча.
# Хэши в экспорте не отключаются: сборка проверяет, что скачала именно то, что
# записано в локе.
# `--system`: виртуальное окружение в контейнере с одним процессом — лишний
# слой без выгоды.
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-default-groups --group worker --group telemetry \
        -o /tmp/requirements.txt \
    && uv pip install --system --no-cache -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY packages/vscommon /app/vscommon
COPY services/worker/worker_app /app/worker_app
COPY rules /app/rules

# Файлы разбираются под непривилегированным пользователем с read-only корнем.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan
USER 10001

CMD ["python", "-m", "worker_app.main"]
