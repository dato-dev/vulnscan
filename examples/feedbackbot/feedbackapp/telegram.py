"""Тонкая обёртка над Bot API: long polling, сообщения, скачивание файла."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class TelegramError(RuntimeError):
    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class FileTooBigError(TelegramError):
    """Файл больше предела. Скачивание прервано, а не дочитано до конца."""


class Telegram:
    def __init__(self, api: str, token: str, proxy: str | None, poll_timeout_s: int) -> None:
        # Прокси — только отсюда, `trust_env=False`: переменные окружения
        # сервера не должны решать, через кого идёт трафик бота.
        self._http = httpx.AsyncClient(timeout=poll_timeout_s + 10, proxy=proxy, trust_env=False)
        self._base = f"{api}/bot{token}"
        self._file_base = f"{api}/file/bot{token}"
        self._poll_timeout = poll_timeout_s

    async def close(self) -> None:
        await self._http.aclose()

    async def _call(self, method: str, **params: Any) -> Any:
        """Токен в адресе, поэтому ошибка называет только метод."""
        try:
            response = await self._http.post(f"{self._base}/{method}", json=params)
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise TelegramError(f"{method}: {type(exc).__name__}") from exc
        if not payload.get("ok"):
            raise TelegramError(
                f"{method}: {payload.get('description', '?')}", response.status_code
            )
        return payload["result"]

    async def updates(self, offset: int) -> list[dict[str, Any]]:
        result = await self._call(
            "getUpdates",
            offset=offset,
            timeout=self._poll_timeout,
            allowed_updates=["message"],
        )
        return list(result)

    async def send(self, chat_id: int, text: str) -> None:
        await self._call("sendMessage", chat_id=chat_id, text=text)

    async def download(self, file_id: str, limit: int) -> bytes:
        """Файл целиком в память, но не больше `limit` байт."""
        info = await self._call("getFile", file_id=file_id)
        if int(info.get("file_size") or 0) > limit:
            raise FileTooBigError("файл больше предела")
        chunks: list[bytes] = []
        total = 0
        try:
            async with self._http.stream("GET", f"{self._file_base}/{info['file_path']}") as resp:
                if resp.status_code >= 400:
                    raise TelegramError("скачивание файла", resp.status_code)
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > limit:
                        raise FileTooBigError("файл больше предела")
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise TelegramError(f"скачивание файла: {type(exc).__name__}") from exc
        return b"".join(chunks)
