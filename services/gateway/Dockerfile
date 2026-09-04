FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Системных зависимостей нет: gateway парсеров не запускает.
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
RUN uv export --frozen --no-default-groups --group gateway --group telemetry \
        -o /tmp/requirements.txt \
    && uv pip install --system --no-cache -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY packages/vscommon /app/vscommon
COPY services/gateway/gateway_app /app/gateway_app

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan
USER 10001

EXPOSE 8080
CMD ["uvicorn", "gateway_app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
