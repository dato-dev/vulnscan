"""Асинхронный клиент API проверки вложений."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "X-Vulnscan-Signature"
TIMESTAMP_HEADER = "X-Vulnscan-Timestamp"
KEY_ID_HEADER = "X-Vulnscan-Key"

MAX_SKEW_S = 300

SAFE_VERDICTS = frozenset({"clean"})
"""Что считается пригодным без оговорок.

Список положительный, а не отрицательный, намеренно: незнакомый вердикт —
например, добавленный в сервисе позже — должен считаться небезопасным. Список
запрещённого молча пропустил бы его.
"""


class VulnscanError(RuntimeError):
    """Сервис недоступен или ответил ошибкой."""


class CallbackVerificationError(VulnscanError):
    """Коллбэк не прошёл проверку подписи."""


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    scan_id: str
    verdict: str
    score: int
    status: str
    pending: bool
    sanitized: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        """Файл нельзя отдавать пользователю."""
        return self.verdict == "malicious"

    @property
    def safe(self) -> bool:
        """Пригоден без оговорок.

        Обратите внимание: `not blocked` и `safe` — разные вещи. Файл, который
        не удалось проверить, не заблокирован, но и безопасным не является.
        """
        return self.verdict in SAFE_VERDICTS

    @property
    def unscannable(self) -> bool:
        """Проверить не удалось: формат не поддержан, файл зашифрован и т.п."""
        return self.verdict in {"unsupported", "encrypted"}


def _sign(secret: str, payload: bytes, timestamp: int | None = None) -> tuple[str, str]:
    ts = str(timestamp if timestamp is not None else int(time.time()))
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256)
    return ts, f"sha256={mac.hexdigest()}"


def _canonical(method: str, path: str, key_id: str) -> bytes:
    return f"{method.upper()}\n{path}\n{key_id}".encode()


def verify_callback(secret: str, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    """Проверяет подпись входящего коллбэка и возвращает разобранное тело.

    Вызывать ОБЯЗАТЕЛЬНО. Без проверки эндпоинт принимает вердикт от кого
    угодно, и «файл чист» может прислать тот, кто этот файл и подсунул.
    """
    timestamp = headers.get(TIMESTAMP_HEADER) or headers.get(TIMESTAMP_HEADER.lower(), "")
    signature = headers.get(SIGNATURE_HEADER) or headers.get(SIGNATURE_HEADER.lower(), "")
    if not timestamp or not signature:
        raise CallbackVerificationError("коллбэк не подписан")

    try:
        skew = abs(int(time.time()) - int(timestamp))
    except ValueError as exc:
        raise CallbackVerificationError("некорректная отметка времени") from exc
    if skew > MAX_SKEW_S:
        raise CallbackVerificationError(
            f"расхождение часов {skew} с при допустимых {MAX_SKEW_S} — "
            "проверьте синхронизацию времени"
        )

    _, expected = _sign(secret, body, int(timestamp))
    try:
        candidate = signature.encode("ascii")
    except UnicodeEncodeError as exc:
        raise CallbackVerificationError("подпись содержит недопустимые символы") from exc
    if not hmac.compare_digest(expected.encode("ascii"), candidate):
        raise CallbackVerificationError("подпись не сошлась")

    return dict(json.loads(body))


class VulnscanClient:
    def __init__(
        self,
        base_url: str,
        key_id: str,
        secret: str,
        *,
        timeout_s: float = 30.0,
        wait_ms: int = 2000,
        callback_url: str | None = None,
        retries: int = 3,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._key_id = key_id
        self._secret = secret
        self._wait_ms = wait_ms
        self._callback_url = callback_url
        self._retries = retries
        self._http = httpx.AsyncClient(timeout=timeout_s)

    async def __aenter__(self) -> VulnscanClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    def _headers(self, payload: bytes) -> dict[str, str]:
        timestamp, signature = _sign(self._secret, payload)
        return {
            KEY_ID_HEADER: self._key_id,
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: signature,
        }

    async def scan(
        self,
        content: bytes,
        filename: str,
        content_type: str = "application/octet-stream",
        profile: str | None = None,
    ) -> ScanOutcome:
        """Отправляет файл на проверку.

        Возвращает готовый вердикт, если сервис уложился в `wait_ms`, иначе
        `pending=True` — результат придёт коллбэком либо его можно забрать
        через `result()`.
        """
        path = "/v1/scan"
        meta: dict[str, Any] = {"wait_ms": self._wait_ms, "filename": filename}
        if profile:
            meta["profile"] = profile
        if self._callback_url:
            meta["callback_url"] = self._callback_url

        # Загрузка подписывает канонический запрос, а не тело: тело multipart
        # сервис не может прочитать до аутентификации.
        headers = self._headers(_canonical("POST", path, self._key_id))
        headers["Idempotency-Key"] = hashlib.sha256(content).hexdigest()

        files = {"file": (filename, content, content_type)}
        payload = await self._request(
            "POST", path, headers=headers, files=files, data={"meta": json.dumps(meta)}
        )
        return _to_outcome(payload)

    async def result(self, scan_id: str) -> ScanOutcome | None:
        """Забирает результат по идентификатору. `None` — ещё не готов."""
        path = f"/v1/scan/{scan_id}"
        headers = self._headers(_canonical("GET", path, self._key_id))
        try:
            payload = await self._request("GET", path, headers=headers)
        except VulnscanError as exc:
            if "404" in str(exc):
                return None
            raise
        return _to_outcome(payload)

    async def download_clean(self, scan_id: str) -> bytes:
        """Скачивает обезвреженную копию."""
        path = f"/v1/scan/{scan_id}/clean"
        headers = self._headers(_canonical("GET", path, self._key_id))
        response = await self._http.get(f"{self._base}{path}", headers=headers)
        if response.status_code >= 400:
            raise VulnscanError(f"обезвреженная копия недоступна: {response.status_code}")
        return response.content

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        """Повторяет только то, что осмысленно повторять.

        `401` и `400` повторять бессмысленно: через секунду будет то же самое,
        а лишние попытки только съедают квоту.
        """
        last: Exception | None = None
        for attempt in range(1, self._retries + 1):
            try:
                response = await self._http.request(method, f"{self._base}{path}", **kwargs)
            except httpx.HTTPError as exc:
                last = exc
            else:
                if response.status_code < 400:
                    return dict(response.json())
                if response.status_code < 500 and response.status_code != 429:
                    raise VulnscanError(f"сервис отклонил запрос: {response.status_code}")
                last = VulnscanError(f"сервис ответил {response.status_code}")

            if attempt < self._retries:
                await _sleep(0.5 * 2 ** (attempt - 1))

        raise VulnscanError(f"сервис недоступен: {last}")


def _to_outcome(payload: dict[str, Any]) -> ScanOutcome:
    status = str(payload.get("status", ""))
    return ScanOutcome(
        scan_id=str(payload.get("scan_id", "")),
        verdict=str(payload.get("verdict", "")),
        score=int(payload.get("score", 0)),
        status=status,
        pending=status in {"queued", "running"},
        sanitized=payload.get("sanitized") is not None,
        findings=list(payload.get("findings") or []),
        raw=payload,
    )


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)
