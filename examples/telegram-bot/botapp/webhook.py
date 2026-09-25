"""Приёмник коллбэков от сканера.

Публичный адрес не нужен: сканер обращается к боту по внутренней сети, а не
из интернета. Наружу этот порт не публикуется.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response, status

from vscommon.models import ScanResult
from vscommon.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify

from .config import settings

logger = logging.getLogger(__name__)

WEBHOOK_PATH = "/webhooks/vulnscan"

ResultHandler = Callable[[ScanResult], Awaitable[None]]


def build_app(handle: ResultHandler) -> FastAPI:
    app = FastAPI(title="vulnscan bot webhook", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(WEBHOOK_PATH)
    async def receive(request: Request) -> Response:
        body = await request.body()
        timestamp = request.headers.get(TIMESTAMP_HEADER, "")
        signature = request.headers.get(SIGNATURE_HEADER, "")

        if not verify(settings.hmac_secret, body, timestamp, signature):
            # Подпись и её отсутствие различать наружу незачем.
            logger.warning("коллбэк с неверной подписью отклонён")
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)

        try:
            result = ScanResult.model_validate_json(body)
        except ValueError:
            logger.warning("коллбэк с нечитаемым телом")
            return Response(status_code=status.HTTP_400_BAD_REQUEST)

        await handle(result)
        # Отвечаем успехом всегда, когда подпись верна: иначе сканер будет
        # ретраить то, что мы уже обработали.
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app
