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


def index_key(tenant: str) -> str:
    return f"{KEY_PREFIX}:index:{tenant}"


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
    def _key(tenant: str, sha256: str) -> str:
        """Тенант — в ключе, а не только в проверке на чтении (M7.7).

        Раньше ключ был один на sha256, а разграничение жило в `applies_to()`.
        Читать чужую запись это не давало, зато давало худшее: запись тенанта
        `b` **затирала** запись тенанта `a` по тому же файлу. Список доверенных
        ослабляет проверку, и его молчаливая пропажа возвращает блокировку
        документа, который вручную разобрали и разрешили, — то есть выглядит
        как новое ложное срабатывание, а не как потеря настройки.
        """
        return f"{KEY_PREFIX}:{tenant}:{sha256}"

    async def add(self, entry: AllowlistEntry, ttl_days: int | None = None) -> AllowlistEntry:
        days = ttl_days or self._default_ttl_days
        entry.expires_at = time.time() + days * 86400

        pipe = self._redis.pipeline()
        pipe.set(self._key(entry.tenant, entry.sha256), entry.model_dump_json(), ex=days * 86400)
        pipe.zadd(index_key(entry.tenant), {entry.sha256: entry.expires_at})
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
        """Запись тенанта, иначе — общая. Именно в этом порядке.

        Своя запись должна перекрывать общую: она заведена под конкретного
        клиента и знает про него больше.
        """
        candidates = [self._key(tenant or "", sha256), self._key(ANY_TENANT, sha256)]
        for raw in await self._redis.mget(candidates):
            if raw is None:
                continue
            try:
                entry = AllowlistEntry.model_validate_json(raw)
            except ValueError:
                logger.warning("битая запись списка доверенных", extra={"sha": sha256[:12]})
                continue
            # Проверка остаётся, хотя ключ уже разграничивает: запись могли
            # положить прежней версией кода, до появления тенанта в ключе.
            if entry.applies_to(tenant):
                return entry
        return None

    async def remove(self, sha256: str, author: str, tenant: str = ANY_TENANT) -> bool:
        """Удаляет запись **одного** тенанта.

        Тенант обязателен по умыслу: без него удаление сняло бы разрешение у
        соседа, который о нём не просил.
        """
        removed = await self._redis.delete(self._key(tenant, sha256))
        await self._redis.zrem(index_key(tenant), sha256)
        if removed:
            logger.info(
                "запись удалена из списка доверенных",
                extra={"sha": sha256[:12], "author": author, "tenant": tenant},
            )
        return bool(removed)

    async def entries(self, tenant: str | None = None, limit: int = 200) -> list[AllowlistEntry]:
        """Действующие записи, ближайшие к истечению — первыми.

        `tenant` — чьи записи отдавать: свои и общие. `None` означает «все»,
        и это отдельное право (M7.7): в записи есть автор и причина, то есть
        рассказ о том, какие документы клиенту приходится разрешать вручную.
        """
        scopes = await self._known_scopes() if tenant is None else sorted({tenant, ANY_TENANT})

        found: list[AllowlistEntry] = []
        for scope in scopes:
            found.extend(await self._entries_of(scope, limit))
        found.sort(key=lambda e: e.expires_at)
        return found[:limit]

    async def _known_scopes(self) -> list[str]:
        """Тенанты, у которых есть записи. Нужно только администратору.

        `scan_iter` вместо `keys`: индексов столько же, сколько тенантов с
        разрешениями, но блокировать Redis перебором мы не хотим и на десяти.
        """
        prefix = f"{KEY_PREFIX}:index:"
        scopes = [
            key.removeprefix(prefix)
            async for key in self._redis.scan_iter(match=f"{prefix}*", count=100)
        ]
        return sorted(scopes)

    async def _entries_of(self, tenant: str, limit: int) -> list[AllowlistEntry]:
        index = index_key(tenant)
        await self._redis.zremrangebyscore(index, 0, time.time())
        digests = await self._redis.zrange(index, 0, limit - 1)
        if not digests:
            return []

        raws = await self._redis.mget([self._key(tenant, d) for d in digests])
        found: list[AllowlistEntry] = []
        for digest, raw in zip(digests, raws, strict=True):
            if raw is None:
                # Ключ истёк, а индекс отстал — подчищаем.
                await self._redis.zrem(index, digest)
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
