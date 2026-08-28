"""Кому принадлежит скан.

Раньше результат и обезвреженная копия отдавались любому, кто знает `scan_id`.
Идентификатор не секрет: он попадает в логи клиента, в переписку, в тикеты —
и «знание идентификатора» никогда не было доказательством права на документ.

Отдельная запись, а не поле в `ScanResult`: результат отдаётся клиенту, и
владелец не должен ехать в ответе. Знать, чей это скан, нужно сервису, а не
получателю.
"""

from __future__ import annotations

import logging

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class Ownership:
    def __init__(self, redis: Redis, ttl_s: int) -> None:
        self._redis = redis
        self._ttl = ttl_s

    @staticmethod
    def _key(scan_id: str) -> str:
        return f"owner:{scan_id}"

    async def claim(self, scan_id: str, tenant: str | None) -> None:
        """Запоминает владельца. TTL совпадает со сроком жизни результата."""
        await self._redis.set(self._key(scan_id), tenant or "", ex=self._ttl)

    async def owner(self, scan_id: str) -> str | None:
        raw = await self._redis.get(self._key(scan_id))
        return None if raw is None else str(raw)

    async def allows(self, scan_id: str, tenant: str | None) -> bool:
        """Может ли этот тенант видеть скан.

        Неизвестный владелец — отказ, а не разрешение. Записи истекают вместе
        с результатом, и если владелец потерялся раньше результата, отдавать
        документ наугад нельзя.
        """
        owner = await self.owner(scan_id)
        if owner is None:
            return False
        return owner == (tenant or "")
