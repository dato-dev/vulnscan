# Result Writer: единственный сервис с доступом к PostgreSQL.
FROM python:3.12-slim

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
RUN uv export --frozen --no-default-groups --group writer --group telemetry \
        -o /tmp/requirements.txt \
    && uv pip install --system --no-cache -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY packages/vscommon /app/vscommon
COPY services/writer/writerapp /app/writerapp
COPY services/writer/migrations /app/migrations

RUN adduser --disabled-password --uid 10001 writer \
    && chown -R writer:writer /app
USER writer

ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
CMD ["python", "-m", "writerapp.main"]
