"""Учёт теневого режима: что сервис заблокировал бы, если бы блокировал.

Смысл режима — измерить долю ложных срабатываний на реальном потоке, ничего
при этом не ломая пользователям. Поэтому «тень» не меняет вердикт: он честный
и именно его мы считаем. Меняется только то, действует ли клиент по нему.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

STATS_KEY = "shadow:stats"
CODES_KEY = "shadow:codes"
SAMPLES_KEY = "shadow:samples"
MAX_SAMPLES = 200
CODES_REPORTED = 15


@dataclass(slots=True)
class ShadowReport:
    since: float = 0.0
    total: int = 0
    would_block: int = 0
    by_verdict: dict[str, int] = field(default_factory=dict)
    top_codes: list[tuple[str, int]] = field(default_factory=list)
    recent_blocks: list[str] = field(default_factory=list)

    @property
    def would_block_ratio(self) -> float:
        return round(self.would_block / self.total, 4) if self.total else 0.0


class ShadowLedger:
    """Счётчики в Redis.

    Полноценные метрики появятся в M4.3; до тех пор это единственный способ
    увидеть, во что обошлось бы включение блокировок.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def record(self, verdict: str, would_block: bool, codes: list[str], sha256: str) -> None:
        """`would_block` — пользователю отказали бы.

        Это шире, чем вердикт `malicious`: файл, который не удалось
        пересобрать, до человека тоже не дойдёт.
        """
        pipe = self._redis.pipeline()
        pipe.hsetnx(STATS_KEY, "since", int(time.time()))
        pipe.hincrby(STATS_KEY, "total", 1)
        pipe.hincrby(STATS_KEY, f"verdict:{verdict}", 1)
        if would_block:
            pipe.hincrby(STATS_KEY, "would_block", 1)
            for code in set(codes):
                pipe.zincrby(CODES_KEY, 1, code)
            # Хвост примеров для разбора: sha усечён, содержимое не хранится.
            pipe.lpush(SAMPLES_KEY, f"{sha256[:12]}:{verdict}")
            pipe.ltrim(SAMPLES_KEY, 0, MAX_SAMPLES - 1)
        await pipe.execute()

    async def report(self) -> ShadowReport:
        stats = await self._redis.hgetall(STATS_KEY) or {}
        codes = await self._redis.zrevrange(CODES_KEY, 0, CODES_REPORTED - 1, withscores=True)
        samples = await self._redis.lrange(SAMPLES_KEY, 0, 19)

        return ShadowReport(
            since=float(stats.get("since", 0) or 0),
            total=int(stats.get("total", 0) or 0),
            would_block=int(stats.get("would_block", 0) or 0),
            by_verdict={
                key.removeprefix("verdict:"): int(value)
                for key, value in stats.items()
                if key.startswith("verdict:")
            },
            top_codes=[(code, int(score)) for code, score in codes],
            recent_blocks=list(samples),
        )

    async def reset(self) -> None:
        await self._redis.delete(STATS_KEY, CODES_KEY, SAMPLES_KEY)
