"""Асинхронный клиент API проверки вложений."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import ssl
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "X-Vulnscan-Signature"
TIMESTAMP_HEADER = "X-Vulnscan-Timestamp"
KEY_ID_HEADER = "X-Vulnscan-Key"

MAX_SKEW_S = 300

PENDING_STATUSES = frozenset({"queued", "scanning"})
"""Проверка идёт, вердикта ещё нет — читать его нельзя."""

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


@dataclass(frozen=True, slots=True)
class CleanCopy:
    """Пересобранная копия вместе с тем, что о ней сказал сервис.

    Формат копии не обязан совпадать с присланным: GIF пересобирается в PNG,
    PDF в профиле `strict` — в страницы-картинки. Угадывать его по имени
    исходника — значит отдать посетителю файл с чужим расширением.
    """

    content: bytes
    content_type: str
    filename: str
    """Имя, которое предложил сервис. Состоит из идентификатора и расширения,
    имени исходного файла в нём нет."""


def resolve_ca_file(path: str) -> str | bool:
    """Значение `verify` для клиента по пути к сертификату своего центра.

    * пусто или не обычный файл-устройство вроде `/dev/null` — `True`,
      системные центры. Так в docker compose выглядит необязательное
      монтирование: `${CA:-/dev/null}:/путь/ca.crt`;
    * читаемый непустой файл — путь к нему;
    * всё остальное — `ValueError` с объяснением.

    Без этой проверки ошибка выглядит как `PermissionError` из глубины `ssl`
    при создании клиента: не сказано ни какой файл, ни чего не хватает. А
    причины у неё почти всегда одни и те же — ниже они и названы.
    """
    if not path:
        return True
    target = Path(path)
    try:
        info = target.stat()
    except PermissionError:
        raise ValueError(
            f"{path}: нет доступа к каталогу, в котором лежит файл, у uid {os.getuid()}. "
            "Часто это путь внутри /root: процесс в контейнере запущен не от root."
        ) from None
    except FileNotFoundError:
        raise ValueError(f"{path}: файла нет — сертификат не смонтирован по этому пути") from None
    if stat.S_ISCHR(info.st_mode):
        return True  # /dev/null: свой центр не задан
    if stat.S_ISDIR(info.st_mode):
        raise ValueError(
            f"{path}: это каталог. Docker создаёт его сам, если файла, который "
            "монтируют, на хосте нет, — проверьте путь на хосте."
        )
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise ValueError(f"{path}: не файл сертификата или файл пустой")
    if not os.access(target, os.R_OK):
        raise ValueError(
            f"{path}: не читается процессом с uid {os.getuid()}. Сертификат центра — "
            "не секрет: на хосте ему достаточно `chmod 644`."
        )
    try:
        ssl.create_default_context(cafile=path)
    except ssl.SSLError as exc:
        raise ValueError(
            f"{path}: не разбирается как сертификат в формате PEM"
            + (f" ({exc.reason})" if exc.reason else "")
            + ". "
            "Нужен сертификат ЦЕНТРА, а не сервера, и в тексте: "
            "-----BEGIN CERTIFICATE-----. DER переводится так: "
            "openssl x509 -inform der -in ca.der -out ca.crt"
        ) from None
    return path


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
        trace_context: Callable[[], str | None] | None = None,
        verify: bool | str = True,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._key_id = key_id
        self._secret = secret
        self._wait_ms = wait_ms
        self._callback_url = callback_url
        self._retries = retries
        self._trace_context = trace_context
        # `verify` — путь к сертификату своего центра сертификации, если сервис
        # стоит за TLS, выпущенным не публичным центром. Отключать проверку
        # (`False`) допустимо только на стенде: ключ подписи уходит в каждом
        # запросе, и без проверки сертификата его заберёт любой посредник.
        self._http = httpx.AsyncClient(timeout=timeout_s, verify=verify)

    async def __aenter__(self) -> VulnscanClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    def _headers(self, payload: bytes) -> dict[str, str]:
        timestamp, signature = _sign(self._secret, payload)
        headers = {
            KEY_ID_HEADER: self._key_id,
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: signature,
        }
        # Контекст трассировки, если вызывающая сторона его ведёт. Библиотека
        # не зависит от OpenTelemetry намеренно: подключающейся команде не
        # должно навязываться ничего, кроме httpx. Поэтому не импорт, а
        # функция, которую передают снаружи.
        #
        # На подпись это не влияет: подписывается канонический запрос
        # (метод, путь, идентификатор ключа) либо тело, а заголовки в неё не
        # входят. Иначе добавление заголовка ломало бы совместимость.
        if self._trace_context is not None:
            traceparent = self._trace_context()
            if traceparent:
                headers["traceparent"] = traceparent
        return headers

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
        """Скачивает обезвреженную копию. Тип и имя — см. `download_clean_copy`."""
        return (await self.download_clean_copy(scan_id)).content

    async def download_clean_copy(self, scan_id: str) -> CleanCopy:
        """Скачивает обезвреженную копию вместе с её типом и именем."""
        path = f"/v1/scan/{scan_id}/clean"
        headers = self._headers(_canonical("GET", path, self._key_id))
        try:
            response = await self._http.get(f"{self._base}{path}", headers=headers)
        except httpx.HTTPError as exc:
            raise VulnscanError(f"обезвреженная копия недоступна: {exc}") from exc
        if response.status_code >= 400:
            raise VulnscanError(f"обезвреженная копия недоступна: {response.status_code}")
        return CleanCopy(
            content=response.content,
            content_type=response.headers.get("content-type", "application/octet-stream"),
            filename=_filename(response.headers.get("content-disposition", "")) or scan_id,
        )

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


def _filename(disposition: str) -> str:
    """Имя из `Content-Disposition`. Только последний сегмент пути и без кавычек:
    имя придумал сервер, но класть его на диск как есть всё равно нельзя."""
    for part in disposition.split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "filename":
            name = value.strip().strip('"').replace("\\", "/").rsplit("/", 1)[-1]
            return name if name not in ("", ".", "..") else ""
    return ""


def _to_outcome(payload: dict[str, Any]) -> ScanOutcome:
    status = str(payload.get("status", ""))
    return ScanOutcome(
        scan_id=str(payload.get("scan_id", "")),
        verdict=str(payload.get("verdict", "")),
        score=int(payload.get("score", 0)),
        status=status,
        # Статусы из протокола (docs/protocol.md). Здесь было `running` —
        # такого статуса сервис не отдаёт, а настоящий `scanning` проходил как
        # завершённая проверка без вердикта: опрос прекращался посреди работы.
        pending=status in PENDING_STATUSES,
        sanitized=payload.get("sanitized") is not None,
        findings=list(payload.get("findings") or []),
        raw=payload,
    )


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)
