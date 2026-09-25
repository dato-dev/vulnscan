# Локальное зеркало баз ClamAV.
#
# Существует по требованию самого ClamAV: их CDN режет тех, кто ходит за
# базами часто и полными файлами. Один хост забирает обновления, остальные
# берут у него. Побочный и более важный эффект — clamd перестаёт нуждаться в
# выходе в интернет: наружу ходит только этот контейнер.
FROM python:3.12-alpine

# uv приезжает готовым бинарником из своего образа, а не ставится pip'ом.
# Здесь берётся musl-сборка: базовый образ alpine, и glibc-бинарник в нём не
# запустится — причём ошибка будет невнятной, вида «not found» на существующем
# файле.
COPY --from=ghcr.io/astral-sh/uv:0.11.25-alpine /usr/local/bin/uv /usr/local/bin/uv

# Зависимости — из общего `uv.lock`, группа `cvdmirror` плюс `metrics`.
# Раньше `cvdupdate` назывался версией прямо здесь, а клиент Prometheus
# приезжал отдельным файлом: два источника на один образ. Теперь один.
#
# Клиент метрик обязан совпадать по версии с остальными образами: разъехавшись,
# они дают разный формат экспозиции, и Prometheus молча перестаёт разбирать
# часть рядов.
COPY pyproject.toml uv.lock /tmp/build/
RUN uv export --frozen --no-default-groups --group cvdmirror --group metrics \
        --project /tmp/build -o /tmp/requirements.txt \
    && adduser -D -u 10001 cvd \
    && uv pip install --system --no-cache -r /tmp/requirements.txt \
    && rm -rf /tmp/build /tmp/requirements.txt \
    && mkdir -p /db \
    && chown -R cvd:cvd /db

# Каталог создан и передан пользователю ДО объявления тома: Docker переносит
# владельца в свежий именованный том. Иначе он достался бы root, а процесс
# работает под непривилегированным пользователем и писать бы не смог.
VOLUME ["/db"]

COPY services/cvdmirror/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY services/cvdmirror/exporter.py /usr/local/bin/exporter.py
COPY services/cvdmirror/probe.py /usr/local/bin/probe.py
RUN chmod +x /usr/local/bin/entrypoint.sh

USER cvd
WORKDIR /db
EXPOSE 8000 9104

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
