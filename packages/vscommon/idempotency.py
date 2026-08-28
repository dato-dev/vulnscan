"""Дедупликация сканов: один файл — один scan_id.

Кэш вердиктов закрывает повтор уже проверенного файла. Здесь закрывается
другой случай: тот же файл прислали, пока первая проверка ещё идёт. Без
этого пользователь, дважды нажавший «отправить», оплачивает два прохода CDR.
"""

from __future__ import annotations

import logging

from redis.asyncio import Redis

from vscommon.models import POLICY_VERSION

logger = logging.getLogger(__name__)


class ScanRegistry:
    def __init__(self, redis: Redis, ttl_s: int = 300) -> None:
        self._redis = redis
        self._ttl = ttl_s

    @staticmethod
    def _key(sha256: str, profile: str) -> str:
        return f"inflight:scan:{sha256}:{profile}:{POLICY_VERSION}"

    async def claim(self, sha256: str, profile: str, scan_id: str) -> str:
        """Возвращает scan_id, под которым файл проверяется.

        Совпал с переданным — заявка наша, задачу надо поставить в очередь.
        Отличается — файл уже проверяется, надо дождаться чужого результата.
        """
        key = self._key(sha256, profile)
        if await self._redis.set(key, scan_id, nx=True, ex=self._ttl):
            return scan_id

        existing: str | None = await self._redis.get(key)
        if existing is not None:
            return existing

        # Ключ истёк между SET и GET. Второй заход: либо выигрываем, либо
        # читаем победителя. Третьего исхода нет, цикл здесь не нужен.
        if await self._redis.set(key, scan_id, nx=True, ex=self._ttl):
            return scan_id
        return await self._redis.get(key) or scan_id

    async def release(self, sha256: str, profile: str) -> None:
        """Снять заявку досрочно. Штатно ключ истекает сам."""
        await self._redis.delete(self._key(sha256, profile))
