"""Клиент сервиса проверки.

Здесь же живёт то, что в ROADMAP значится как SDK (M3.1): таймаут, размыкатель
и заранее решённое поведение при недоступном сканере. Бот не имеет права
зависнуть или пропустить непроверенный файл только потому, что сканер лёг.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass

import httpx

from vscommon.keys import KEY_ID_HEADER
from vscommon.signing import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    canonical_request,
    sign,
)
from vscommon.telemetry import current_traceparent
from vulnscan_client import resolve_ca_file

from .config import settings

logger = logging.getLogger(__name__)

BREAKER_FAILURES = 5
BREAKER_COOLDOWN_S = 30.0


@dataclass(slots=True)
class ScanOutcome:
    verdict: str
    score: int
    scan_id: str
    clean_url: str | None = None
    clean_suffix: str = ""
    """Расширение обезвреженной копии: профиль CDR может сменить формат."""

    reasons: list[str] | None = None
    """Коды значащих признаков. Нулевые сюда не попадают — они справочные."""

    shadow: bool = False
    """Сервис в теневом режиме: вердикт честный, но действовать по нему нельзя."""
    available: bool = True
    """False — сканер недоступен. Файл считаем непроверенным."""

    @property
    def pending(self) -> bool:
        """Проверка ещё идёт: ответ придёт вебхуком либо опросом."""
        return self.verdict == "pending"

    @property
    def blocking(self) -> bool:
        """Стоит ли отказывать пользователю.

        В теневом режиме — никогда: вердикт считается, но на людей не влияет.
        """
        return self.verdict == "malicious" and not self.shadow

    @property
    def deliverable(self) -> bool:
        """Можно ли отдавать пользователю обезвреженную копию."""
        if not self.available or not self.clean_url:
            return False
        return self.verdict in ("clean", "suspicious") or self.shadow


class CircuitBreaker:
    """После череды отказов перестаём ходить в сканер и отвечаем сразу."""

    def __init__(self) -> None:
        self._failures = 0
        self._opened_at = 0.0

    @property
    def open(self) -> bool:
        if self._failures < BREAKER_FAILURES:
            return False
        if time.monotonic() - self._opened_at > BREAKER_COOLDOWN_S:
            self._failures = 0
            return False
        return True

    def record_success(self) -> None:
        self._failures = 0

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures == BREAKER_FAILURES:
            self._opened_at = time.monotonic()
            logger.error("сканер признан недоступным, размыкатель открыт")


class ScannerClient:
    def __init__(self) -> None:
        # `trust_env=False`: прокси из окружения стоит ради Telegram, и запросы
        # к сканеру с подписью ушли бы через него. В Kubernetes это прикрывал
        # `NO_PROXY`; на отдельном сервере прикрыть было бы нечем.
        self._http = httpx.AsyncClient(
            timeout=settings.request_timeout_s,
            verify=resolve_ca_file(settings.scanner_ca_file),
            trust_env=False,
        )
        self._breaker = CircuitBreaker()

    async def close(self) -> None:
        await self._http.aclose()

    def _auth(self, method: str, path: str, body: bytes | None = None) -> dict[str, str]:
        """Заголовки аутентификации.

        Загрузка подписывает канонический запрос без тела: подписать multipart
        можно только прочитав его, а сервис читает тело уже после проверки.
        Остальные ручки подписывают то же самое — тела у них нет.

        Тенант больше не заголовок: он выводится из ключа на стороне сервиса.
        """
        payload = body if body is not None else canonical_request(method, path, settings.key_id)
        timestamp, signature = sign(settings.hmac_secret, payload)
        headers = {
            KEY_ID_HEADER: settings.key_id,
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: signature,
        }
        # Контекст трассировки едет заголовком: бот начинает трейс, gateway его
        # продолжает. Без этого «что делал бот» и «что делал сервис» — два
        # несвязанных трейса, и вопрос «где потерялось время» не отвечается.
        #
        # В подпись заголовок не входит: подписывается канонический запрос
        # (метод, путь, идентификатор ключа), поэтому добавление безопасно.
        traceparent = current_traceparent()
        if traceparent:
            headers["traceparent"] = traceparent
        return headers

    async def scan(self, content: bytes, filename: str, mime: str | None) -> ScanOutcome:
        if self._breaker.open:
            logger.warning("запрос не отправлен: размыкатель открыт")
            return ScanOutcome(verdict="unknown", score=0, scan_id="", available=False)

        meta: dict[str, object] = {
            "mode": "both",
            "wait_ms": settings.wait_ms,
            "filename": filename,
        }
        if settings.webhook_url:
            meta["callback_url"] = settings.webhook_url
        try:
            response = await self._http.post(
                f"{settings.scanner_url}/v1/scan",
                files={"file": (filename, content, mime or "application/octet-stream")},
                data={"meta": json.dumps(meta, ensure_ascii=False)},
                headers=self._auth("POST", "/v1/scan"),
            )
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            logger.warning("сканер недоступен", extra={"reason": type(exc).__name__})
            return ScanOutcome(verdict="unknown", score=0, scan_id="", available=False)

        if response.status_code == 429:
            self._breaker.record_failure()
            logger.warning("сканер ограничил частоту")
            return ScanOutcome(verdict="unknown", score=0, scan_id="", available=False)
        if response.status_code >= 400 and response.status_code != 202:
            self._breaker.record_failure()
            logger.warning("сканер вернул ошибку", extra={"code": response.status_code})
            return ScanOutcome(verdict="unknown", score=0, scan_id="", available=False)

        self._breaker.record_success()
        payload = response.json()

        if response.status_code == 202:
            return ScanOutcome(
                verdict="pending", score=0, scan_id=payload["scan_id"], available=True
            )

        return self._to_outcome(payload)

    def outcome_of(self, payload: dict) -> ScanOutcome:
        """Разбор результата, пришедшего вебхуком."""
        return self._to_outcome(payload)

    async def await_result(self, scan_id: str) -> ScanOutcome | None:
        """Опрос как подстраховка: вебхук может не дойти или бот перезапуститься."""
        payload = await self._await_result(scan_id)
        return self._to_outcome(payload) if payload else None

    async def _await_result(self, scan_id: str) -> dict | None:
        """Опрос до готовности.

        Вебхук был бы дешевле, но требует публичного адреса; для лёгкого бота
        опрос честнее (см. ROADMAP M3.2).
        """
        deadline = time.monotonic() + settings.scan_timeout_s
        delay = 0.25
        while time.monotonic() < deadline:
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 3.0)
            try:
                response = await self._http.get(
                    f"{settings.scanner_url}/v1/scan/{scan_id}",
                    headers=self._auth("GET", f"/v1/scan/{scan_id}"),
                )
            except httpx.HTTPError:
                continue
            if response.status_code == 404:
                continue
            payload = response.json()
            if payload.get("status") in ("done", "failed", "manual_review"):
                return payload
        logger.warning("проверка не завершилась в отведённое время")
        return None

    def _to_outcome(self, payload: dict) -> ScanOutcome:
        scan_id = payload["scan_id"]
        sanitized = payload.get("sanitized")
        key = ((sanitized or {}).get("ref") or {}).get("key", "")
        suffix = f".{key.rsplit('.', 1)[-1]}" if "." in key else ""

        return ScanOutcome(
            verdict=payload.get("verdict", "unknown"),
            score=payload.get("score", 0),
            scan_id=scan_id,
            clean_url=(f"{settings.scanner_url}/v1/scan/{scan_id}/clean" if sanitized else None),
            clean_suffix=suffix,
            shadow=bool(payload.get("shadow", False)),
            reasons=[f["code"] for f in payload.get("findings", []) if f.get("score", 0) > 0],
        )

    async def fetch_clean(self, url: str) -> bytes | None:
        try:
            path = url.replace(settings.scanner_url, "", 1)
            response = await self._http.get(url, headers=self._auth("GET", path))
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("не удалось забрать артефакт", extra={"reason": type(exc).__name__})
            return None
        return response.content
