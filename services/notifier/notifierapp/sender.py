"""Доставка результата клиенту с подписью ключом тенанта."""

from __future__ import annotations

import logging

import httpx

from vscommon.keys import KeyRegistry
from vscommon.models import CallbackTask
from vscommon.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign

from .config import settings

logger = logging.getLogger(__name__)

RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
"""Коды, при которых повтор осмыслен. Остальные 4xx — отказ по существу."""


class Delivery:
    """Исход попытки."""

    def __init__(self, delivered: bool, retryable: bool, detail: str) -> None:
        self.delivered = delivered
        self.retryable = retryable
        self.detail = detail


class CallbackSender:
    def __init__(self, keys: KeyRegistry) -> None:
        self._keys = keys
        self._client = httpx.AsyncClient(timeout=settings.callback_timeout_s)

    def rebind(self, keys: KeyRegistry) -> None:
        """Подхватывает перезагруженный реестр ключей."""
        self._keys = keys

    async def close(self) -> None:
        await self._client.aclose()

    async def send(self, task: CallbackTask) -> Delivery:
        """URL и подпись в логи не пишем — только хост и код ответа."""
        key = self._keys.get(task.key_id)
        if key is None:
            # Ключ отозван или переименован. Повторять бессмысленно: подписать
            # нечем, и через час будет то же самое.
            logger.error(
                "ключ для подписи коллбэка недоступен, доставка отменена",
                extra={"key_id": task.key_id, "scan_id": task.scan_id},
            )
            return Delivery(False, retryable=False, detail="ключ недоступен")

        body = task.payload.encode()
        timestamp, signature = sign(key.secret, body)
        headers = {
            "Content-Type": "application/json",
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: signature,
        }

        try:
            response = await self._client.post(task.url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            return Delivery(False, retryable=True, detail=type(exc).__name__)

        if response.status_code < 400:
            return Delivery(True, retryable=False, detail=str(response.status_code))
        if response.status_code in RETRY_STATUS:
            return Delivery(False, retryable=True, detail=str(response.status_code))
        return Delivery(False, retryable=False, detail=str(response.status_code))
