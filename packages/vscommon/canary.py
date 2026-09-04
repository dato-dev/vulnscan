"""Журнал расхождений набора-кандидата с действующим (M7.2).

Метрики отвечают «сколько», журнал — «на чём». Для решения о выкатке нужно и
то, и другое: доля расхождений говорит, стоит ли смотреть, а хвост примеров —
что именно смотреть. Без второго остаётся только гадать, широкое ли правило
или ему честно попались вредоносные файлы.

Устройство намеренно то же, что у `ShadowLedger`: счётчики плюс короткий хвост
усечённых хэшей. Содержимого файлов здесь нет и быть не может — по хэшу
исходник ищется в карантине.

Ключи общие, без тенанта: набор правил — свойство установки, а не клиента, и
решение о выкатке принимает тот, кто её выполняет. Поэтому отчёт
административный.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

STATS_KEY = "canary:stats"
CANDIDATE_KEY = "canary:candidate"
ACTIVE_KEY = "canary:active"
SAMPLES_KEY = "canary:samples"

MAX_SAMPLES = 200
RULES_REPORTED = 15


@dataclass(slots=True)
class CanaryReport:
    since: float = 0.0
    disagreements: int = 0
    candidate_only: list[tuple[str, int]] = field(default_factory=list)
    """Правила кандидата, которых не было у действующего набора.

    Это будущие ложные срабатывания — по ним и принимается решение.
    """

    active_only: list[tuple[str, int]] = field(default_factory=list)
    """Правила, которые кандидат перестал ловить: цена выкатки в детекте."""

    samples: list[str] = field(default_factory=list)


class CanaryLedger:
    """Накопитель расхождений. Пишет воркер, читает администратор."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def record(self, sha256: str, active: frozenset[str], candidate: frozenset[str]) -> None:
        """Одно расхождение. Совпадения не пишутся: их считают метрики.

        Хранить каждое совпадение значило бы вести второй счётчик того же
        события — а расходятся такие пары молча.
        """
        pipe = self._redis.pipeline()
        pipe.hsetnx(STATS_KEY, "since", int(time.time()))
        pipe.hincrby(STATS_KEY, "disagreements", 1)
        for rule in candidate - active:
            pipe.zincrby(CANDIDATE_KEY, 1, rule)
        for rule in active - candidate:
            pipe.zincrby(ACTIVE_KEY, 1, rule)

        added = ",".join(sorted(candidate - active)) or "—"
        lost = ",".join(sorted(active - candidate)) or "—"
        pipe.lpush(SAMPLES_KEY, f"{sha256[:12]} +{added} -{lost}")
        pipe.ltrim(SAMPLES_KEY, 0, MAX_SAMPLES - 1)
        await pipe.execute()

    async def report(self) -> CanaryReport:
        stats = await self._redis.hgetall(STATS_KEY) or {}
        candidate = await self._redis.zrevrange(
            CANDIDATE_KEY, 0, RULES_REPORTED - 1, withscores=True
        )
        active = await self._redis.zrevrange(ACTIVE_KEY, 0, RULES_REPORTED - 1, withscores=True)
        samples = await self._redis.lrange(SAMPLES_KEY, 0, 19)

        return CanaryReport(
            since=float(stats.get("since", 0) or 0),
            disagreements=int(stats.get("disagreements", 0) or 0),
            candidate_only=[(rule, int(score)) for rule, score in candidate],
            active_only=[(rule, int(score)) for rule, score in active],
            samples=list(samples),
        )

    async def reset(self) -> None:
        """Обнуляет наблюдение. Зовётся при смене кандидата.

        Иначе отчёт складывал бы расхождения двух разных наборов и отвечал бы
        на вопрос, которого никто не задавал.
        """
        await self._redis.delete(STATS_KEY, CANDIDATE_KEY, ACTIVE_KEY, SAMPLES_KEY)
