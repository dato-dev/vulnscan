# Локальное зеркало баз ClamAV.
#
# Существует по требованию самого ClamAV: их CDN режет тех, кто ходит за
# базами часто и полными файлами. Один хост забирает обновления, остальные
# берут у него. Побочный и более важный эффект — clamd перестаёт нуждаться в
# выходе в интернет: наружу ходит только этот контейнер.
FROM python:3.12-alpine

RUN adduser -D -u 10001 cvd \
    && pip install --no-cache-dir "cvdupdate>=1.1" \
    && mkdir -p /db \
    && chown -R cvd:cvd /db

# Каталог создан и передан пользователю ДО объявления тома: Docker переносит
# владельца в свежий именованный том. Иначе он достался бы root, а процесс
# работает под непривилегированным пользователем и писать бы не смог.
VOLUME ["/db"]

COPY services/cvdmirror/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER cvd
WORKDIR /db
EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
