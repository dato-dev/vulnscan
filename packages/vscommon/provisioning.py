"""Заведение тенантов и ключей без правки файлов на сервере.

Файл остаётся начальной загрузкой: с него сервис поднимается, когда в Redis
ещё пусто, и им заводится первый административный ключ. Всё, что появляется
дальше, живёт в Redis и подхватывается без рестарта.

Почему не только файл: новая команда означала ssh, редактор и перезапуск —
то есть окно, в которое сервис не принимает файлы, ради добавления строки.
Почему не только Redis: тогда потеря Redis означала бы потерю доступа для
всех, включая администратора.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any

from redis.asyncio import Redis

from vscommon.keys import MIN_SECRET_LEN, AccessKey

logger = logging.getLogger(__name__)

KEYS_HASH = "provision:keys"
POLICIES_HASH = "provision:policies"

SECRET_BYTES = 32


def generate_secret() -> str:
    """Секрет для нового ключа.

    Генерируется на сервере, а не принимается от клиента: присланный секрет
    мог бы оказаться коротким, повторно использованным или подсмотренным.
    """
    return secrets.token_urlsafe(SECRET_BYTES)


class TenantStore:
    """Ключи и политики, заведённые через API."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def put_key(
        self,
        key_id: str,
        tenant: str,
        secret: str,
        callback_hosts: tuple[str, ...] = (),
        admin: bool = False,
    ) -> None:
        if len(secret) < MIN_SECRET_LEN:
            raise ValueError("секрет короче допустимого")
        payload = {
            "tenant": tenant,
            "secret": secret,
            "callback_hosts": list(callback_hosts),
            "admin": admin,
            "disabled": False,
        }
        await self._redis.hset(KEYS_HASH, key_id, json.dumps(payload))
        # Секрет в лог не попадает — только факт появления ключа.
        logger.info("ключ заведён", extra={"key_id": key_id, "tenant": tenant})

    async def revoke_key(self, key_id: str) -> bool:
        """Отзывает ключ. Возвращает, был ли он вообще.

        Удаляем, а не помечаем: отозванный ключ не должен оставаться в
        хранилище вместе с рабочим секретом.
        """
        removed = bool(await self._redis.hdel(KEYS_HASH, key_id))
        if removed:
            logger.info("ключ отозван", extra={"key_id": key_id})
        return removed

    async def all_keys(self) -> dict[str, AccessKey]:
        raw = await self._redis.hgetall(KEYS_HASH)
        keys: dict[str, AccessKey] = {}
        for raw_id, value in (raw or {}).items():
            # Клиент Redis может отдавать байты: приводим явно, иначе ключ
            # словаря окажется не строкой и сравнение с key_id не сработает.
            key_id = raw_id.decode() if isinstance(raw_id, bytes) else str(raw_id)
            try:
                entry = json.loads(value)
            except ValueError:
                logger.warning("битая запись ключа в хранилище", extra={"key_id": key_id})
                continue
            keys[key_id] = AccessKey(
                key_id=key_id,
                tenant=entry.get("tenant", ""),
                secret=entry.get("secret", ""),
                disabled=bool(entry.get("disabled", False)),
                callback_hosts=tuple(entry.get("callback_hosts") or ()),
                admin=bool(entry.get("admin", False)),
            )
        return keys

    async def put_policy(self, tenant: str, policy: dict[str, Any]) -> None:
        await self._redis.hset(POLICIES_HASH, tenant, json.dumps(policy))
        logger.info("политика тенанта обновлена", extra={"tenant": tenant})

    async def all_policies(self) -> dict[str, dict[str, Any]]:
        raw = await self._redis.hgetall(POLICIES_HASH)
        policies: dict[str, dict[str, Any]] = {}
        for raw_tenant, value in (raw or {}).items():
            tenant = raw_tenant.decode() if isinstance(raw_tenant, bytes) else str(raw_tenant)
            try:
                policies[tenant] = json.loads(value)
            except ValueError:
                logger.warning("битая запись политики", extra={"tenant": tenant})
        return policies

    async def tenants(self) -> tuple[str, ...]:
        keys = await self.all_keys()
        return tuple(sorted({key.tenant for key in keys.values()}))
