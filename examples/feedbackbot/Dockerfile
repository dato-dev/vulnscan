FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
# Установщик и порядок установки — как у остальных образов: см. examples/telegram-bot/Dockerfile.
COPY --from=ghcr.io/astral-sh/uv:0.11.25 /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv export --frozen --no-default-groups --group feedbackbot --group telemetry \
        -o /tmp/requirements.txt \
    && uv pip install --system --no-cache -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# К сканеру бот ходит через публичную библиотеку клиента, как чужая команда:
# подпись и разбор вердикта — её, а не наши внутренние модули. Общий код
# `vscommon` нужен только для формата логов.
COPY packages/vscommon /app/vscommon
COPY packages/vulnscan_client /app/vulnscan_client
COPY examples/feedbackbot/feedbackapp /app/feedbackapp

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin feedback
USER 10001

CMD ["python", "-m", "feedbackapp.main"]
