"""Ограничители на стороне gateway: частота запросов и параллелизм.

Одного счётчика запросов мало. Тенант, укладывающийся в свою частоту, всё
равно может занять очередь воркеров большими файлами — и латентность вырастет
у всех остальных. Поэтому ограничителя два:

* **частота** — сколько запросов в минуту принимаем;
* **параллелизм** — сколько проверок этого тенанта одновременно в работе.

Второй и защищает latency соседей: он прямо ограничивает долю очереди.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

WINDOW_S = 60


@dataclass(frozen=True, slots=True)
class RateDecision:
    allowed: bool
    retry_after_s: int = 0
    observed: float = 0.0


class RateLimiter:
    """Скользящее окно на двух счётчиках.

    Фиксированное окно пропускало бы двойной всплеск на стыке; полный лог
    запросов точнее, но хранит запись на каждый запрос. Взвешенная сумма
    текущего и предыдущего окна даёт достаточную точность за два счётчика.

    Отклонённый запрос тоже расходует такт: иначе клиент, долбящийся в стену,
    получал бы возможность обходить лимит, просто повторяя попытки.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    @staticmethod
    def _key(tenant: str, bucket: int) -> str:
        return f"rl:{tenant}:{bucket}"

    async def check(self, tenant: str, limit_per_min: int) -> RateDecision:
        if limit_per_min <= 0:
            return RateDecision(allowed=True)

        now = time.time()
        bucket = int(now // WINDOW_S)
        elapsed = (now % WINDOW_S) / WINDOW_S

        pipe = self._redis.pipeline()
        pipe.incr(self._key(tenant, bucket))
        pipe.expire(self._key(tenant, bucket), WINDOW_S * 2)
        pipe.get(self._key(tenant, bucket - 1))
        current, _, previous_raw = await pipe.execute()

        previous = int(previous_raw or 0)
        observed = previous * (1 - elapsed) + int(current)

        if observed > limit_per_min:
            return RateDecision(
                allowed=False,
                retry_after_s=max(1, int(WINDOW_S - (now % WINDOW_S))),
                observed=observed,
            )
        return RateDecision(allowed=True, observed=observed)


class ConcurrencyLimiter:
    """Сколько проверок тенанта одновременно в работе.

    Множество с временными метками: запись, пережившая самый долгий разумный
    проход, отбрасывается сама. Так счётчик не «протекает», если воркер умер,
    не сняв свою задачу.
    """

    def __init__(self, redis: Redis, stale_after_s: int = 300) -> None:
        self._redis = redis
        self._stale = stale_after_s

    @staticmethod
    def _key(tenant: str) -> str:
        return f"inflight:tenant:{tenant}"

    async def acquire(self, tenant: str, scan_id: str, limit: int) -> bool:
        """Занимает слот. Возвращает False, если свободных нет.

        Порядок «добавить, узнать ранг, при переполнении убрать себя» корректен
        и без Lua: метки времени задают полный порядок, поэтому ровно `limit`
        участников имеют ранг меньше лимита — даже когда заявки приходят
        одновременно.
        """
        if limit <= 0:
            return True

        key = self._key(tenant)
        now = time.time()

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - self._stale)
        pipe.zadd(key, {scan_id: now})
        pipe.zrank(key, scan_id)
        pipe.expire(key, self._stale * 2)
        _, _, rank, _ = await pipe.execute()

        if rank is not None and rank >= limit:
            await self._redis.zrem(key, scan_id)
            return False
        return True

    async def release(self, tenant: str, scan_id: str) -> None:
        await self._redis.zrem(self._key(tenant), scan_id)

    async def current(self, tenant: str) -> int:
        key = self._key(tenant)
        await self._redis.zremrangebyscore(key, 0, time.time() - self._stale)
        return int(await self._redis.zcard(key))
