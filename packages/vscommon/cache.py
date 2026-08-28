"""Двухуровневый кэш результатов.

Базы ClamAV обновляются несколько раз в сутки. Если версия баз входит в общий
ключ, после каждого freshclam кэш обнуляется целиком — и мы теряем главный
источник низкой задержки. Поэтому уровня два:

* **структурный** — тип, разбор, YARA и артефакт CDR. Зависит от наших правил
  и весов, живёт долго;
* **антивирусный** — только вердикт clamd. Зависит от версии баз, живёт до
  их следующего обновления.

Кэшируются признаки, а не готовый вердикт: пороги и веса у тенантов разные.
"""

from __future__ import annotations

import logging
import time
import uuid

from redis.asyncio import Redis

from vscommon.hashing import short
from vscommon.models import (
    POLICY_VERSION,
    CachedAv,
    CachedStructural,
    ScanResult,
    ScanStatus,
    TenantPolicy,
    Verdict,
)
from vscommon.scoring import verdict_of

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS_KEY = "default"


def weights_key_for(policy: TenantPolicy) -> str:
    """Тенанты без своих весов делят одну запись, со своими — не делят.

    Признаки хранятся с уже посчитанными баллами, поэтому переопределение
    весов обязано разводить записи.
    """
    return policy.tenant if policy.weight_overrides else DEFAULT_WEIGHTS_KEY


class StructuralCache:
    """Уровень 1. Ключ не содержит версию антивирусных баз."""

    def __init__(self, redis: Redis, ttl_s: int) -> None:
        self._redis = redis
        self._ttl = ttl_s

    @staticmethod
    def _key(sha256: str, profile: str, rules_version: str, weights_key: str) -> str:
        return f"scan:struct:{sha256}:{profile}:{rules_version}:{weights_key}:{POLICY_VERSION}"

    async def get(
        self, sha256: str, profile: str, rules_version: str, weights_key: str
    ) -> CachedStructural | None:
        raw = await self._redis.get(self._key(sha256, profile, rules_version, weights_key))
        if raw is None:
            return None
        try:
            return CachedStructural.model_validate_json(raw)
        except ValueError:
            logger.warning("битая запись кэша, игнорирую", extra={"sha": short(sha256)})
            return None

    async def put(self, entry: CachedStructural, weights_key: str) -> None:
        await self._redis.set(
            self._key(entry.sha256, entry.profile.value, entry.rules_version, weights_key),
            entry.model_dump_json(),
            ex=self._ttl,
        )


class AvCache:
    """Уровень 2. Самоинвалидируется версией баз, TTL только ограничивает память."""

    def __init__(self, redis: Redis, ttl_s: int) -> None:
        self._redis = redis
        self._ttl = ttl_s

    @staticmethod
    def _key(sha256: str, av_db_version: str) -> str:
        return f"scan:av:{sha256}:{av_db_version}"

    async def get(self, sha256: str, av_db_version: str) -> CachedAv | None:
        raw = await self._redis.get(self._key(sha256, av_db_version))
        if raw is None:
            return None
        try:
            return CachedAv.model_validate_json(raw)
        except ValueError:
            logger.warning("битая запись AV-кэша, игнорирую", extra={"sha": short(sha256)})
            return None

    async def put(self, entry: CachedAv) -> None:
        await self._redis.set(
            self._key(entry.sha256, entry.av_db_version),
            entry.model_dump_json(),
            ex=self._ttl,
        )


def assemble(structural: CachedStructural, av: CachedAv, policy: TenantPolicy) -> ScanResult:
    """Собирает ответ из двух половин, пересчитывая вердикт под тенанта.

    Вердикт не берётся из кэша: пороги и веса у тенантов разные, и общая
    запись с чужим вердиктом дала бы неверный ответ.
    """
    facts = structural.facts.merge(av.facts)
    verdict, score = verdict_of(facts, policy)

    return ScanResult(
        scan_id=uuid.uuid4().hex,
        sha256=structural.sha256,
        status=ScanStatus.DONE,
        verdict=verdict,
        score=score,
        findings=facts.findings,
        engines={**structural.engines, **av.engines},
        stages=structural.stages,
        sanitized=structural.sanitized if verdict is not Verdict.MALICIOUS else None,
        from_cache=True,
        created_at=time.time(),
    )
