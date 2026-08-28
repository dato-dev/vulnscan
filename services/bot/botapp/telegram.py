"""Тонкая обёртка над Bot API. Только то, что нужно этому боту."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .config import settings

logger = logging.getLogger(__name__)


class TelegramError(RuntimeError):
    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status

    @property
    def bad_token(self) -> bool:
        """Telegram отвечает 404 на неизвестный токен и 401 на отозванный."""
        return self.status in (401, 404)


class TelegramClient:
    def __init__(self) -> None:
        self._http = httpx.AsyncClient(timeout=settings.poll_timeout_s + 10)
        self._base = f"{settings.telegram_api}/bot{settings.telegram_token}"
        self._file_base = f"{settings.telegram_api}/file/bot{settings.telegram_token}"

    async def close(self) -> None:
        await self._http.aclose()

    async def _call(self, method: str, **params: Any) -> Any:
        """Токен в URL, поэтому в логи попадает только имя метода."""
        response = await self._http.post(f"{self._base}/{method}", json=params)
        payload = response.json()
        if not payload.get("ok"):
            raise TelegramError(
                f"{method}: {payload.get('description', 'ошибка')}", response.status_code
            )
        return payload["result"]

    async def get_updates(self, offset: int) -> list[dict]:
        return await self._call(
            "getUpdates",
            offset=offset,
            timeout=settings.poll_timeout_s,
            allowed_updates=["message"],
        )

    async def send_message(self, chat_id: int, text: str) -> None:
        await self._call("sendMessage", chat_id=chat_id, text=text)

    async def download(self, file_id: str) -> tuple[bytes, str] | None:
        """Возвращает (содержимое, имя). None — файл слишком велик или недоступен."""
        info = await self._call("getFile", file_id=file_id)
        size = int(info.get("file_size", 0))
        if size > settings.max_file_mb * 1024 * 1024:
            return None

        path = info["file_path"]
        response = await self._http.get(f"{self._file_base}/{path}")
        response.raise_for_status()
        return response.content, path.rsplit("/", 1)[-1]

    async def send_document(
        self, chat_id: int, content: bytes, filename: str, caption: str
    ) -> None:
        response = await self._http.post(
            f"{self._base}/sendDocument",
            data={"chat_id": str(chat_id), "caption": caption},
            files={"document": (filename, content, "application/octet-stream")},
        )
        payload = response.json()
        if not payload.get("ok"):
            raise TelegramError(
                f"sendDocument: {payload.get('description', 'ошибка')}", response.status_code
            )
