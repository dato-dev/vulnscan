"""Журнал попыток: хлебная крошка, переживающая жёсткий краш процесса.

Питоновское исключение в стадии ловится и превращается в признак. Но segfault
в C-расширении или OOM-kill убивают воркер целиком, не оставляя следов в логах.
Отметка «начал разбирать этот файл на этой стадии», записанная до опасной
работы и снятая после, позволяет следующей попытке понять, что предыдущая
умерла именно здесь.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Attempt:
    scan_id: str
    attempt: int
    stage: str
    started_at: float

    def elapsed_s(self) -> float:
        return time.time() - self.started_at


class AttemptJournal:
    def __init__(self, redis: Redis, ttl_s: int = 3600) -> None:
        self._redis = redis
        self._ttl = ttl_s

    @staticmethod
    def _key(scan_id: str) -> str:
        return f"attempt:{scan_id}"

    async def load(self, scan_id: str) -> Attempt | None:
        """Незакрытая отметка означает, что прошлая попытка не дошла до конца."""
        raw = await self._redis.get(self._key(scan_id))
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
            return Attempt(**payload)
        except (ValueError, TypeError):
            logger.warning("битая отметка попытки, игнорирую")
            return None

    async def begin(self, scan_id: str, attempt: int, stage: str = "fetch") -> None:
        await self._write(Attempt(scan_id, attempt, stage, time.time()))

    async def mark(self, scan_id: str, attempt: int, stage: str) -> None:
        await self._write(Attempt(scan_id, attempt, stage, time.time()))

    async def finish(self, scan_id: str) -> None:
        """Снимается только при штатном завершении — в том числе с ошибкой Python."""
        await self._redis.delete(self._key(scan_id))

    async def _write(self, attempt: Attempt) -> None:
        await self._redis.set(
            self._key(attempt.scan_id),
            json.dumps(asdict(attempt)),
            ex=self._ttl,
        )
