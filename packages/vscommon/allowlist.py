"""Список файлов, которым доверяем вопреки вердикту.

Нужен для одного: снять блокировку с конкретного файла, не выкатывая релиз.
Разбор ложных срабатываний — регулярная работа, и ждать сборки, пока у клиента
не проходит документ, нельзя.

Это механизм ослабления проверки, поэтому:

* живёт на сервере, клиент на него не влияет;
* запись требует автора и причины — «потом разберёмся» не проходит;
* у записи есть срок; вечный список превращается в дыру, о которой все забыли;
* каждое применение пишется в лог — запись, срабатывающая часто, означает либо
  системную ошибку детекта, либо злоупотребление.

Снятие блокировки не отменяет пересборку: файл всё равно уходит в CDR, и
пользователь получает обезвреженную копию.
"""

from __future__ import annotations

import json
import logging
import math
import time

from pydantic import BaseModel, Field, computed_field
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

ANY_TENANT = "*"
KEY_PREFIX = "allowlist"
INDEX_KEY = "allowlist:index"


class AllowlistEntry(BaseModel):
    sha256: str
    reason: str = Field(min_length=8)
    """Зачем внесли. Короткие отписки не принимаются."""

    author: str = Field(min_length=2)
    tenant: str = ANY_TENANT
    """`*` — для всех. Иначе действует только для одного клиента."""

    created_at: float = Field(default_factory=time.time)
    expires_at: float = 0.0

    def applies_to(self, tenant: str | None) -> bool:
        return self.tenant == ANY_TENANT or self.tenant == (tenant or "")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def days_left(self) -> int:
        """Сколько записи осталось жить. Видно в ответе — чтобы пересматривать.

        Округление вверх: назначив срок в семь дней, оператор ожидает увидеть
        семь, а не шесть.
        """
        if not self.expires_at:
            return 0
        return max(0, math.ceil((self.expires_at - time.time()) / 86400))


class Allowlist:
    def __init__(self, redis: Redis, default_ttl_days: int = 30) -> None:
        self._redis = redis
        self._default_ttl_days = default_ttl_days

    @staticmethod
    def _key(sha256: str) -> str:
        return f"{KEY_PREFIX}:{sha256}"

    async def add(self, entry: AllowlistEntry, ttl_days: int | None = None) -> AllowlistEntry:
        days = ttl_days or self._default_ttl_days
        entry.expires_at = time.time() + days * 86400

        pipe = self._redis.pipeline()
        pipe.set(self._key(entry.sha256), entry.model_dump_json(), ex=days * 86400)
        pipe.zadd(INDEX_KEY, {entry.sha256: entry.expires_at})
        await pipe.execute()

        logger.info(
            "запись добавлена в список доверенных",
            extra={
                "sha": entry.sha256[:12],
                "author": entry.author,
                "tenant": entry.tenant,
                "days": days,
            },
        )
        return entry

    async def get(self, sha256: str, tenant: str | None) -> AllowlistEntry | None:
        raw = await self._redis.get(self._key(sha256))
        if raw is None:
            return None
        try:
            entry = AllowlistEntry.model_validate_json(raw)
        except ValueError:
            logger.warning("битая запись списка доверенных", extra={"sha": sha256[:12]})
            return None
        return entry if entry.applies_to(tenant) else None

    async def remove(self, sha256: str, author: str) -> bool:
        removed = await self._redis.delete(self._key(sha256))
        await self._redis.zrem(INDEX_KEY, sha256)
        if removed:
            logger.info(
                "запись удалена из списка доверенных",
                extra={"sha": sha256[:12], "author": author},
            )
        return bool(removed)

    async def entries(self, limit: int = 200) -> list[AllowlistEntry]:
        """Действующие записи, ближайшие к истечению — первыми."""
        await self._redis.zremrangebyscore(INDEX_KEY, 0, time.time())
        digests = await self._redis.zrange(INDEX_KEY, 0, limit - 1)
        if not digests:
            return []

        raws = await self._redis.mget([self._key(d) for d in digests])
        found: list[AllowlistEntry] = []
        for digest, raw in zip(digests, raws, strict=True):
            if raw is None:
                # Ключ истёк, а индекс отстал — подчищаем.
                await self._redis.zrem(INDEX_KEY, digest)
                continue
            try:
                found.append(AllowlistEntry.model_validate_json(raw))
            except ValueError:
                continue
        return found


SERVER_FIELDS = frozenset({"created_at", "expires_at"})
"""Проставляются сервером. Принимать их из запроса нельзя: иначе срок жизни
записи назначал бы тот, кто её вносит."""


def entry_from_request(payload: dict) -> AllowlistEntry:
    """Разбор тела запроса. Серверные и лишние поля отбрасываются."""
    allowed = set(AllowlistEntry.model_fields) - SERVER_FIELDS
    return AllowlistEntry.model_validate({k: v for k, v in payload.items() if k in allowed})


def audit_line(entry: AllowlistEntry) -> str:
    return json.dumps(
        {
            "sha": entry.sha256[:12],
            "author": entry.author,
            "tenant": entry.tenant,
            "reason": entry.reason,
            "days_left": entry.days_left,
        },
        ensure_ascii=False,
    )
