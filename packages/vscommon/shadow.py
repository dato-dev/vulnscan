"""Учёт теневого режима: что сервис заблокировал бы, если бы блокировал.

Смысл режима — измерить долю ложных срабатываний на реальном потоке, ничего
при этом не ломая пользователям. Поэтому «тень» не меняет вердикт: он честный
и именно его мы считаем. Меняется только то, действует ли клиент по нему.
"""

from __future__ import annotations

import collections
import logging
import time
from dataclasses import dataclass, field

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

KEY_PREFIX = "shadow"
MAX_SAMPLES = 200
CODES_REPORTED = 15
ALL_TENANTS = "*"
"""Сводка по всем тенантам. Доступна только администратору (M7.7)."""


def keys_of(tenant: str) -> tuple[str, str, str]:
    """Ключи учёта одного тенанта: счётчики, коды, хвост примеров.

    Тенант в ключе, а не в поле, потому что учёт теневого режима читается
    целиком: `hgetall` по общему ключу отдал бы соседей вместе со своими. А
    теневой режим включают по одному тенанту (`TenantPolicy.shadow_mode`) —
    то есть общая доля «заблокировали бы» описывала бы поток тех, у кого
    режим включён, и выдавалась бы за долю спрашивающего.
    """
    return (
        f"{KEY_PREFIX}:{tenant}:stats",
        f"{KEY_PREFIX}:{tenant}:codes",
        f"{KEY_PREFIX}:{tenant}:samples",
    )


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

    async def record(
        self, tenant: str, verdict: str, would_block: bool, codes: list[str], sha256: str
    ) -> None:
        """`would_block` — пользователю отказали бы.

        Это шире, чем вердикт `malicious`: файл, который не удалось
        пересобрать, до человека тоже не дойдёт.
        """
        stats_key, codes_key, samples_key = keys_of(tenant)
        pipe = self._redis.pipeline()
        pipe.hsetnx(stats_key, "since", int(time.time()))
        pipe.hincrby(stats_key, "total", 1)
        pipe.hincrby(stats_key, f"verdict:{verdict}", 1)
        if would_block:
            pipe.hincrby(stats_key, "would_block", 1)
            for code in set(codes):
                pipe.zincrby(codes_key, 1, code)
            # Хвост примеров для разбора: sha усечён, содержимое не хранится.
            pipe.lpush(samples_key, f"{sha256[:12]}:{verdict}")
            pipe.ltrim(samples_key, 0, MAX_SAMPLES - 1)
        await pipe.execute()

    async def report(self, tenant: str) -> ShadowReport:
        """Отчёт одного тенанта. `ALL_TENANTS` — сводка по всем.

        Сводка считается сложением, а не отдельным общим счётчиком: второй
        счётчик того же события пришлось бы держать согласованным, а
        расходятся такие пары молча.
        """
        if tenant == ALL_TENANTS:
            return await self._aggregate()
        return await self._report_of(tenant)

    async def tenants(self) -> list[str]:
        """У кого есть учёт. Нужно администратору для сводки."""
        prefix = f"{KEY_PREFIX}:"
        names = [
            key.removeprefix(prefix).removesuffix(":stats")
            async for key in self._redis.scan_iter(match=f"{prefix}*:stats", count=100)
        ]
        return sorted(names)

    async def _aggregate(self) -> ShadowReport:
        codes: collections.Counter[str] = collections.Counter()
        total = would_block = 0
        since = 0.0
        by_verdict: collections.Counter[str] = collections.Counter()
        recent: list[str] = []

        for tenant in await self.tenants():
            part = await self._report_of(tenant)
            total += part.total
            would_block += part.would_block
            by_verdict.update(part.by_verdict)
            codes.update(dict(part.top_codes))
            recent.extend(part.recent_blocks)
            # Самое раннее начало наблюдения: сводка описывает окно целиком.
            since = part.since if not since else min(since, part.since or since)

        return ShadowReport(
            since=since,
            total=total,
            would_block=would_block,
            by_verdict=dict(by_verdict),
            top_codes=codes.most_common(CODES_REPORTED),
            recent_blocks=recent[:20],
        )

    async def _report_of(self, tenant: str) -> ShadowReport:
        stats_key, codes_key, samples_key = keys_of(tenant)
        stats = await self._redis.hgetall(stats_key) or {}
        codes = await self._redis.zrevrange(codes_key, 0, CODES_REPORTED - 1, withscores=True)
        samples = await self._redis.lrange(samples_key, 0, 19)

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

    async def reset(self, tenant: str) -> None:
        await self._redis.delete(*keys_of(tenant))
