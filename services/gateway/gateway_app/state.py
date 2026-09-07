"""Разделяемые ресурсы процесса gateway: Redis, очередь, кэш, хранилище."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from redis.asyncio import Redis

from vscommon.allowlist import Allowlist
from vscommon.cache import AvCache, StructuralCache
from vscommon.canary import CanaryLedger
from vscommon.freshness import HOUR, Age, age_of
from vscommon.idempotency import ScanRegistry
from vscommon.keys import KeyRegistry
from vscommon.metrics import metrics
from vscommon.ownership import Ownership
from vscommon.policy import PolicyRegistry
from vscommon.provisioning import TenantStore
from vscommon.queue import DeadLetterQueue, JobQueue, ResultChannel, ResultStream
from vscommon.quota import DailyQuota
from vscommon.ratelimit import ConcurrencyLimiter, RateLimiter
from vscommon.redis_client import create_redis
from vscommon.rules_control import RulesControl
from vscommon.shadow import ShadowLedger
from vscommon.storage import ObjectStore, S3Store, build_store
from vscommon.tickets import StatusTicketStore, TicketStore

from .config import settings

logger = logging.getLogger(__name__)


def _reload_counted(kind: str, *, failed: bool) -> None:
    """Исход перезагрузки конфигурации на живом gateway.

    Воркер считает так же (`kind="weights"`, `"yara"`), но там счёт идёт по
    факту изменения: правила перечитываются, только если сменилась подпись
    файла. Здесь ключи и политики перечитываются безусловно, раз в
    `config_reload_interval_s`, поэтому единица счёта — попытка. Разница
    полезная: ровный `applied` — это пульс цикла перезагрузки, и его
    исчезновение видно раньше, чем устаревший ключ кого-нибудь пустит.
    """
    metrics().config_reloads.labels(kind=kind, outcome="failed" if failed else "applied").inc()


@dataclass(slots=True)
class AppState:
    redis: Redis
    queue: JobQueue
    results: ResultChannel
    history: ResultStream
    structural: StructuralCache
    av_cache: AvCache
    store: ObjectStore
    policies: PolicyRegistry
    dlq: DeadLetterQueue
    registry: ScanRegistry
    rate_limiter: RateLimiter
    concurrency: ConcurrencyLimiter
    shadow: ShadowLedger
    allowlist: Allowlist
    rule_control: RulesControl
    """Выключатель отдельного правила: откат без выката (M7.2)."""

    canary: CanaryLedger
    """Расхождения набора-кандидата с действующим (M7.2)."""

    keys: KeyRegistry
    ownership: Ownership
    tenants: TenantStore
    tickets: TicketStore
    """Одноразовые талоны на загрузку из браузера (M12.1)."""

    status_tickets: StatusTicketStore
    """Талоны на наблюдение за сканом из браузера (M12.7)."""

    quota: DailyQuota
    """Суточный расход публичных ключей (M12.5)."""

    async def rules_version(self) -> str:
        """Версия правил и весов; публикуется воркером."""
        return await self.redis.get("engine:rules:version") or "unknown"

    async def libmagic_state(self) -> str:
        """`off` означает, что тип определяется только таблицей сигнатур."""
        return await self.redis.get("engine:libmagic") or "unknown"

    async def engine_version(self) -> str:
        """Версия баз AV публикуется воркером; при недоступности — заглушка."""
        value = await self.redis.get("engine:clamav:version")
        return value or settings.engine_version

    async def av_database_age(self) -> Age:
        """Возраст баз антивируса. Публикуется воркером.

        Отсутствие значения — не «свежо», а `unknown`: воркер мог не запуститься
        вовсе, и молчание здесь означает, что проверять файлы некому.
        """
        raw = await self.redis.get("engine:clamav:built_at")
        try:
            built_at = float(raw) if raw else None
        except ValueError:
            built_at = None
        return age_of(
            built_at,
            stale_after_s=settings.av_db_stale_after_h * HOUR,
            expired_after_s=settings.av_db_expired_after_h * HOUR,
        )

    async def reload_keys(self) -> None:
        """Перечитывает реестр: файл плюс заведённое через API.

        Отзыв ключа обязан работать без рестарта: скомпрометированный ключ
        нельзя оставлять действующим до окна обслуживания.
        """
        from_file = KeyRegistry.load(settings.keys_file)
        try:
            self.keys = from_file.merged_with(await self.tenants.all_keys())
            _reload_counted("keys", failed=False)
        except Exception:
            # Хранилище недоступно — работаем на файле. Он и заведён затем,
            # чтобы потеря Redis не отрезала доступ всем, включая админа.
            logger.exception("не удалось прочитать ключи из хранилища, беру только файл")
            self.keys = from_file
            # Снаружи это неотличимо от исправной работы: сервис отвечает,
            # ключи из файла действуют. Не действуют только заведённые через
            # API — то есть отзыв ключа, сделанный через API, не применится, а
            # мы будем считать, что применился.
            _reload_counted("keys", failed=True)
        # Файл ключей задан и не прочитан — реестр неполон. Отдельно от исхода
        # перезагрузки: тот про попытку, этот про состояние.
        metrics().report_degraded("keys", self.keys.degraded)

    async def reload_policies(self) -> None:
        """Подхватывает политики, заведённые через API."""
        self.policies = PolicyRegistry.load(settings, await self.tenants.all_policies())
        # Файл политик задан, но не прочитан — работаем на встроенных. Пороги
        # при этом чужие, а вердикты продолжают выдаваться как ни в чём не бывало.
        metrics().report_degraded("policies", self.policies.degraded)
        _reload_counted("policies", failed=self.policies.degraded)

    async def close(self) -> None:
        await self.redis.aclose()


async def build_state() -> AppState:
    # blocking=True: ожидание результата держит подписку pub/sub открытой.
    redis = create_redis(settings.redis_url, blocking=True)
    queue = JobQueue(redis, settings.jobs_stream, settings.jobs_group)
    await queue.ensure_group()

    store = build_store(settings)
    if isinstance(store, S3Store):
        store.ensure_buckets(settings.raw_bucket, settings.clean_bucket)

    logger.info("gateway готов", extra={"stream": settings.jobs_stream})
    return AppState(
        redis=redis,
        queue=queue,
        results=ResultChannel(redis),
        history=ResultStream(redis, settings.results_stream, settings.results_group),
        structural=StructuralCache(redis, settings.verdict_ttl_s),
        av_cache=AvCache(redis, settings.av_cache_ttl_s),
        store=store,
        policies=PolicyRegistry.load(settings),
        dlq=DeadLetterQueue(redis, settings.dlq_stream, settings.dlq_maxlen),
        registry=ScanRegistry(redis, settings.inflight_ttl_s),
        rate_limiter=RateLimiter(redis),
        concurrency=ConcurrencyLimiter(redis, settings.inflight_ttl_s),
        shadow=ShadowLedger(redis),
        allowlist=Allowlist(redis, settings.allowlist_ttl_days),
        rule_control=RulesControl(redis),
        canary=CanaryLedger(redis),
        keys=KeyRegistry.load(settings.keys_file),
        ownership=Ownership(redis, settings.verdict_ttl_s),
        tenants=TenantStore(redis),
        tickets=TicketStore(redis, settings.ticket_ttl_s),
        status_tickets=StatusTicketStore(redis),
        quota=DailyQuota(redis),
    )
