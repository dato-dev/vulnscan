"""Точка входа воркера: чтение очереди, подхват зависших задач, обработка."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from collections import deque

from vscommon.allowlist import Allowlist, audit_line
from vscommon.cache import AvCache, StructuralCache, weights_key_for
from vscommon.canary import CanaryLedger
from vscommon.freshness import HOUR, Freshness, age_of, parse_clamav_built_at
from vscommon.hashing import short
from vscommon.journal import AttemptJournal
from vscommon.logging import log_context, setup_logging
from vscommon.metrics import (
    CACHED_NONE,
    CACHED_STRUCTURAL,
    metrics,
    setup_metrics,
    tenant_label,
)
from vscommon.metrics import serve as serve_metrics
from vscommon.models import (
    REQUEST_DERIVED_CODES,
    TERMINAL_STATUSES,
    CachedAv,
    CachedStructural,
    CallbackTask,
    DeadLetter,
    DeadLetterReason,
    DeliveryTask,
    Finding,
    ScanFacts,
    ScanJob,
    ScanMode,
    ScanRecord,
    ScanResult,
    ScanStatus,
    Severity,
    Verdict,
)
from vscommon.queue import (
    CallbackQueue,
    DeadLetterQueue,
    DeliveryQueue,
    Heartbeat,
    JobQueue,
    ResultChannel,
    ResultStream,
)
from vscommon.ratelimit import ConcurrencyLimiter
from vscommon.redis_client import create_redis
from vscommon.rules_control import RulesControl
from vscommon.shadow import ShadowLedger
from vscommon.storage import S3Store, build_store
from vscommon.telemetry import (
    continue_trace,
    current_traceparent,
    setup_tracing,
    shutdown_tracing,
)

from .config import settings
from .deep import deep_job, deep_reason, reason_code
from .failure import crashed_on_content, should_retry
from .pipeline import Pipeline
from .reclaim import StuckJobReclaimer
from .scoring import verdict_on_failure

logger = logging.getLogger(__name__)

_VERDICT_RANK = {Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}
"""Порядок строгости вердиктов. `unsupported`, `encrypted` и `error` в него не
входят намеренно: это не «мягче» и не «строже», а «не проверено»."""

CANARY_BUFFER = 5_000
"""Сколько расхождений канарейки держать до сброса в Redis.

Верхняя граница на память: расхождения приходят со скоростью проверок, а
сбрасываются раз в `reload_interval_s`. Переполнение считается отдельным
исходом в метрике — потерянные наблюдения делают кандидата чище, чем он есть.
"""


class Worker:
    def __init__(self) -> None:
        # blocking=True: воркер читает очередь через XREADGROUP ... BLOCK.
        self._redis = create_redis(settings.redis_url, blocking=True)
        self._deep_mode = settings.worker_mode == "deep"
        stream = settings.deep_stream if self._deep_mode else settings.jobs_stream
        self._queue = JobQueue(self._redis, stream, settings.jobs_group)
        self._deep_queue = JobQueue(self._redis, settings.deep_stream, settings.jobs_group)
        self._results = ResultChannel(self._redis)
        # История. Воркер сюда только пишет: базой владеет Result Writer.
        self._history = ResultStream(self._redis, settings.results_stream, settings.results_group)
        self._structural = StructuralCache(self._redis, settings.verdict_ttl_s)
        self._av_cache = AvCache(self._redis, settings.av_cache_ttl_s)
        self._heartbeat = Heartbeat(self._redis, settings.heartbeat_ttl_s)
        self._journal = AttemptJournal(self._redis, settings.attempt_ttl_s)
        self._dlq = DeadLetterQueue(self._redis, settings.dlq_stream, settings.dlq_maxlen)
        self._concurrency = ConcurrencyLimiter(self._redis, settings.inflight_ttl_s)
        self._shadow = ShadowLedger(self._redis)
        self._allowlist = Allowlist(self._redis, settings.allowlist_ttl_days)
        self._rule_control = RulesControl(self._redis)
        self._canary = CanaryLedger(self._redis)
        # Стадия работает в пуле потоков, а журнал асинхронный. Поэтому
        # расхождения складываются в буфер и уезжают в Redis из цикла
        # перезагрузки: сетевой вызов из горячего пути обошёлся бы дороже
        # самой проверки, а `run_coroutine_threadsafe` завёл бы задачу на файл.
        self._canary_buffer: deque[tuple[str, frozenset[str], frozenset[str]]] = deque(
            maxlen=CANARY_BUFFER
        )
        self._reclaimer = StuckJobReclaimer(
            queue=self._queue,
            heartbeat=self._heartbeat,
            consumer=settings.consumer_name,
            min_idle_s=settings.reclaim_min_idle_s,
            max_deliveries=settings.max_deliveries,
            batch=settings.reclaim_batch,
        )
        self._store = build_store(settings)
        self._pipeline = Pipeline(self._store)
        # Доставку выполняет notifier: подпись идёт ключом тенанта, а держать
        # ключи в процессе, разбирающем враждебные файлы, нельзя.
        self._callbacks = CallbackQueue(
            self._redis, settings.callbacks_stream, settings.callbacks_group
        )
        # Отдельная очередь от коллбэков: выгрузка файла может упираться в
        # чужое хранилище минутами, коллбэк — это один HTTP-запрос. В общей
        # очереди недоступный приёмник задерживал бы уведомления всем.
        self._deliveries = DeliveryQueue(
            self._redis, settings.delivery_stream, settings.delivery_group
        )
        self._semaphore = asyncio.Semaphore(settings.concurrency)
        self._tasks: set[asyncio.Task[None]] = set()
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        await self._queue.ensure_group()
        if isinstance(self._store, S3Store):
            self._store.ensure_buckets(settings.raw_bucket, settings.clean_bucket)
            # Срок хранения выставляется правилом бакета, а не уборщиком в коде:
            # процесс, который «должен» подчищать, однажды не запустится.
            self._store.apply_retention(settings.raw_bucket, settings.raw_retention_days)
            self._store.apply_retention(settings.clean_bucket, settings.clean_retention_days)
        await asyncio.to_thread(self._pipeline.warmup)
        await self._publish_engine_version()

        if self._deep_mode:
            await self._deep_queue.ensure_group()

        # У воркера нет своей HTTP-ручки: он цикл-потребитель, а не сервис.
        # Поэтому эндпоинт метрик поднимается отдельно и слушает во внутренней
        # сети — скрейпить нужно каждую реплику, pushgateway тут не подходит.
        if settings.metrics_enabled:
            serve_metrics(settings.metrics_port)

        logger.info(
            "воркер запущен",
            extra={
                "mode": settings.worker_mode,
                "consumer": settings.consumer_name,
                "concurrency": settings.concurrency,
                "reclaim_min_idle_s": settings.reclaim_min_idle_s,
            },
        )
        # ДО первой задачи, а не в цикле перезагрузки. Цикл спит перед первым
        # тиком, и без этой строки перезапущенный воркер полминуты работал бы
        # с правилом, которое выключили из-за массовых ложных срабатываний, —
        # то есть откат отменялся бы рестартом.
        await self._apply_rule_control()
        self._pipeline.observe_canary_with(self._observe_canary)

        reclaim_task = asyncio.create_task(self._reclaim_loop())
        reload_task = asyncio.create_task(self._reload_loop())

        try:
            async for entry_id, job in self._queue.consume(settings.consumer_name):
                if self._stopping.is_set():
                    break
                await self._spawn(entry_id, job)
        finally:
            for task in (reclaim_task, reload_task):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _reclaim_loop(self) -> None:
        """Периодически разбирает pending-список группы."""
        while not self._stopping.is_set():
            await asyncio.sleep(settings.reclaim_interval_s)
            try:
                sweep = await self._reclaimer.sweep()
            except Exception:
                logger.exception("сбой при подхвате зависших задач")
                continue

            await self._observe_queues()

            # Подхват — это всегда чужая авария: воркер умер, не доработав
            # задачу. В логе она видна одной строкой `WARNING`, то есть
            # замечает её только тот, кто в этот момент читает логи. Всплеск
            # подхватов — самый ранний признак цикла «падаем на файле, задача
            # уходит следующему»; `vs_dlq_size` покажет это позже и только
            # после того, как лимит доставок исчерпан.
            if sweep.reclaimed:
                metrics().reclaimed_jobs.labels(outcome="reclaimed").inc(len(sweep.reclaimed))
            if sweep.abandoned:
                metrics().reclaimed_jobs.labels(outcome="abandoned").inc(len(sweep.abandoned))

            for claimed in sweep.reclaimed:
                await self._spawn(claimed.entry_id, claimed.job)
            for claimed in sweep.abandoned:
                await self._spawn(
                    claimed.entry_id, claimed.job, abandoned=True, delivered=claimed.delivered
                )

    async def _maybe_enqueue_deep(self, job: ScanJob, result: ScanResult) -> None:
        """Отправляет файл на углублённую проверку, если она чем-то поможет.

        Только из быстрой роли: углублённая проверка не порождает саму себя.
        """
        if self._deep_mode or job.deep or not settings.deep_enabled:
            return

        reason = deep_reason(result, job.policy, settings.deep_sample_rate)
        if not reason:
            return

        await self._deep_queue.publish(deep_job(job, reason))
        metrics().deep_scans.labels(reason=reason_code(reason)).inc()
        logger.info("файл отправлен на углублённую проверку", extra={"reason": reason})

    async def _check_allowlist(self, sha256: str, tenant: str | None, verdict: Verdict) -> bool:
        """Снята ли блокировка для этого файла.

        Проверяется, только когда вердикт действительно блокирующий: незачем
        ходить в Redis за каждым чистым документом.
        """
        if verdict is not Verdict.MALICIOUS:
            return False

        entry = await self._allowlist.get(sha256, tenant)
        if entry is None:
            return False

        logger.warning("блокировка снята записью в списке доверенных: %s", audit_line(entry))
        return True

    async def _reload_loop(self) -> None:
        """Подхватывает правки правил и весов без остановки воркера."""
        while not self._stopping.is_set():
            await asyncio.sleep(settings.reload_interval_s)
            try:
                changed = await asyncio.to_thread(self._pipeline.reload_config)
                changed |= await self._apply_rule_control()
                await asyncio.to_thread(self._pipeline.reload_candidate)
                await self._flush_canary()
            except Exception:
                logger.exception("сбой при перезагрузке конфигурации")
                continue

            # Публикуем на каждом тике: ключи с TTL в час иначе протухают, а
            # версия баз антивируса могла смениться после freshclam.
            await self._publish_engine_version()
            if changed:
                logger.info(
                    "конфигурация обновлена без рестарта",
                    extra={"rules_version": self._pipeline.rules_version},
                )

    def _observe_canary(
        self, sha256: str, active: frozenset[str], candidate: frozenset[str]
    ) -> None:
        """Вызывается из пула потоков. Только положить в очередь, ничего больше."""
        if len(self._canary_buffer) == self._canary_buffer.maxlen:
            # `deque` вытесняет молча, а молчаливая потеря наблюдений делает
            # кандидата чище, чем он есть, — то есть подталкивает выкатить.
            metrics().canary_runs.labels(outcome="dropped").inc()
        self._canary_buffer.append((sha256, active, candidate))

    async def _flush_canary(self) -> None:
        """Сбрасывает накопленные расхождения. Отказ Redis их теряет, и это
        приемлемо: канарейка — наблюдение, а не результат проверки."""
        while self._canary_buffer:
            sha256, active, candidate = self._canary_buffer.popleft()
            try:
                await self._canary.record(sha256, active, candidate)
            except Exception:
                logger.warning("не удалось записать расхождение канарейки", exc_info=True)
                return

    async def _apply_rule_control(self) -> bool:
        """Забирает список выключенных правил (M7.2).

        Недоступный Redis здесь не должен ослаблять проверку: прежний список
        остаётся в силе, а не сбрасывается в пустой. Сброс означал бы, что
        сетевой сбой сам собой включает обратно правило, которое выключили
        из-за массовых ложных срабатываний.
        """
        try:
            return self._pipeline.apply_rule_control(await self._rule_control.disabled())
        except Exception:
            logger.exception("не удалось прочитать список выключенных правил")
            return False

    async def _spawn(
        self, entry_id: str, job: ScanJob, abandoned: bool = False, delivered: int = 0
    ) -> None:
        await self._semaphore.acquire()
        coro = self._abandon(entry_id, job, delivered) if abandoned else self._handle(entry_id, job)
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        self._semaphore.release()
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            # Задача не подтверждена и вернётся через reclaimer. Без явного
            # снятия исключения оно осталось бы висеть безымянным warning'ом.
            logger.error(
                "обработка оборвалась исключением, задача остаётся в очереди",
                exc_info=error,
            )

    async def _enqueue_callback(self, job: ScanJob, result: ScanResult) -> None:
        """Ставит доставку в очередь. Сам воркер наружу не ходит.

        Тело формируется здесь и дальше не пересобирается: подпись считается
        именно по нему, и повторная сериализация на стороне доставки могла бы
        дать другой порядок полей — подпись не сошлась бы.
        """
        if not job.callback_url:
            return
        try:
            await self._callbacks.publish(
                CallbackTask(
                    scan_id=result.scan_id,
                    tenant=job.tenant,
                    key_id=job.key_id,
                    url=job.callback_url,
                    payload=result.model_dump_json(),
                    # Тот же приём, что и на входе в воркер: через очередь
                    # заголовков нет, контекст едет полем задачи.
                    traceparent=current_traceparent() or "",
                )
            )
        except Exception:
            # Очередь недоступна — вердикт всё равно посчитан и сохранён.
            logger.exception("не удалось поставить коллбэк в очередь доставки")

    async def _enqueue_delivery(self, job: ScanJob, result: ScanResult) -> None:
        """Ставит выгрузку копии в хранилище клиента (M14.1).

        Задание ставится и тогда, когда выгружать нечего: файл не прошёл
        проверку, но решение о нём обязано появиться в приёмнике манифестом.
        «Файла нет» иначе означает одновременно «заблокирован», «ещё в работе»
        и «сервис сломался», и различить их по содержимому ящика невозможно.

        Приёмник кладётся в задание целиком: решение принято политикой,
        действовавшей на момент проверки, и правка политики не должна
        переносить файл, который уже в пути.
        """
        policy = job.policy
        if policy.delivery_error:
            # Приёмник описан негодно. Молчать нельзя: тенанту его настроили,
            # значит файлы ждут, а они не придут.
            logger.error(
                "приёмник тенанта негоден, копия не выгружена",
                extra={"причина": policy.delivery_error},
            )
            return
        if policy.delivery is None:
            return

        try:
            await self._deliveries.publish(
                DeliveryTask(
                    scan_id=result.scan_id,
                    tenant=job.tenant,
                    destination=policy.delivery,
                    artifact=result.sanitized.ref if result.sanitized else None,
                    # Исходное имя файла не используется: оно часто содержит
                    # персональные данные, и мы его не храним. Сопоставить
                    # объект с обращением клиент может по `scan_id` из манифеста.
                    name=f"{result.scan_id}{job.filename_ext}",
                    payload=result.model_dump_json(),
                    traceparent=current_traceparent() or "",
                )
            )
        except Exception:
            # Очередь недоступна — вердикт всё равно посчитан и сохранён.
            logger.exception("не удалось поставить выгрузку копии в очередь")

    async def _record_history(self, job: ScanJob, result: ScanResult) -> None:
        """Отправляет запись в поток истории.

        Отказ здесь не прерывает обработку: вердикт клиенту важнее истории.
        Пишет в поток, а не в базу, — доступа к базе у воркера нет и быть не
        должно, это процесс, разбирающий враждебные файлы.
        """
        try:
            await self._history.publish(
                ScanRecord(
                    result=result,
                    tenant=job.tenant,
                    size=job.size,
                    detected_mime=result.facts.detected_mime if result.facts else None,
                    rules_version=self._pipeline.rules_version,
                    av_db_version=self._pipeline.engine_version,
                    traceparent=current_traceparent() or "",
                )
            )
        except Exception:
            logger.exception("не удалось записать результат в историю")

    async def _observe_queues(self) -> None:
        """Датчики глубины очередей.

        Снимаются в уже существующем периодическом цикле, а не отдельной
        задачей: лишний таймер здесь ничего не добавил бы, а поводов для гонок
        стало бы больше.
        """
        try:
            pending = await self._queue.pending(count=1000)
            metrics().queue_depth.labels(stream=settings.jobs_stream).set(len(pending))
            metrics().dlq_size.set(await self._dlq.size())
            metrics().inflight.set(len(self._tasks))
        except Exception:
            # Метрика не повод ронять цикл подхвата зависших задач.
            logger.debug("не удалось снять датчики очередей", exc_info=True)

    async def _handle(self, entry_id: str, job: ScanJob) -> None:
        with (
            log_context(scan_id=job.scan_id, sha=short(job.sha256), tenant=job.tenant),
            # Трейс продолжается с той стороны очереди: между gateway и воркером
            # Redis Stream, и без этого дерево спанов рвалось бы посередине.
            # Негодный контекст не принимается — начнётся новый корень.
            continue_trace(
                job.traceparent,
                "scan.deep" if job.deep else "scan.process",
                scan_id=job.scan_id,
                tenant=tenant_label(job.tenant),
                profile=job.profile.value,
                size=job.size,
                deep=job.deep,
            ),
        ):
            async with self._heartbeat.keep(entry_id, settings.consumer_name):
                completed = await self._results.load_status(job.scan_id)
                if completed is not None and completed.status in TERMINAL_STATUSES:
                    # Повторная доставка задачи с терминальным исходом: конвейер
                    # и CDR не повторяем, но результат добираем до получателей.
                    logger.info(
                        "задача уже завершена, повтор пропущен",
                        extra={"status": completed.status.value},
                    )
                    await self._results.publish(completed)
                    if job.callback_url:
                        await self._enqueue_callback(job, completed)
                        await self._enqueue_delivery(job, completed)
                    await self._queue.ack(entry_id)
                    return

                # Жизненный цикл скана — уровень INFO (см. CLAUDE.md). Gateway
                # пишет «принят», здесь — «взят в работу»: без этой записи между
                # приёмом и завершением зияет дыра, и по логам не понять, дошла
                # ли задача до воркера вообще.
                logger.info(
                    "задача взята в работу",
                    extra={
                        "размер": job.size,
                        "тип": job.filename_ext or "?",
                        "профиль": job.profile.value,
                        "режим": "углублённый" if job.deep else "быстрый",
                        "консьюмер": settings.consumer_name,
                        "из_кэша": job.cached is not None,
                    },
                )

                previous = await self._journal.load(job.scan_id)

                if previous is not None and crashed_on_content(
                    previous, settings.max_parser_crashes
                ):
                    # Прошлая попытка оборвалась не исключением, а вместе с
                    # процессом, внутри разбора этого файла. Повтор даст то же.
                    logger.error(
                        "разбор файла обрывает процесс, повтор не назначается",
                        extra={"crash_stage": previous.stage, "attempt": previous.attempt},
                    )
                    await self._journal.finish(job.scan_id)
                    await self._dead_letter(
                        job,
                        DeadLetterReason.PARSER_CRASH,
                        detail=f"процесс оборвался на стадии {previous.stage}",
                        stage=previous.stage,
                        delivered=previous.attempt,
                    )
                    await self._queue.ack(entry_id)
                    return

                attempt = previous.attempt + 1 if previous is not None else 1
                await self._journal.begin(job.scan_id, attempt)

                async def report(stage: str) -> None:
                    await self._journal.mark(job.scan_id, attempt, stage)

                try:
                    result = await self._pipeline.process(
                        job, on_stage=report, allowlist=self._check_allowlist
                    )
                except Exception as exc:
                    await self._journal.finish(job.scan_id)
                    if should_retry(exc):
                        # Транзиторный сбой: не подтверждаем задачу, её вернёт
                        # reclaimer. Лимит доставок ограничивает число попыток.
                        logger.warning(
                            "инфраструктурный сбой, задача остаётся в очереди",
                            extra={"exc": type(exc).__name__, "attempt": attempt},
                        )
                        return
                    logger.exception("ошибка вызвана самим файлом, повтор бесполезен")
                    await self._dead_letter(
                        job, DeadLetterReason.SCAN_FAILED, detail=type(exc).__name__
                    )
                    await self._queue.ack(entry_id)
                    return
                else:
                    await self._journal.finish(job.scan_id)

                await self._deliver(job, result)
            await self._queue.ack(entry_id)

    async def _abandon(self, entry_id: str, job: ScanJob, delivered: int) -> None:
        """Задача исчерпала лимит доставок — в dead-letter, не запуская обработку."""
        with log_context(scan_id=job.scan_id, sha=short(job.sha256), tenant=job.tenant):
            await self._journal.finish(job.scan_id)
            await self._dead_letter(
                job,
                DeadLetterReason.JOB_ABANDONED,
                detail="превышен лимит повторных доставок",
                delivered=delivered,
            )
            await self._queue.ack(entry_id)

    async def _dead_letter(
        self,
        job: ScanJob,
        reason: DeadLetterReason,
        detail: str,
        stage: str | None = None,
        delivered: int | None = None,
    ) -> None:
        """Файл проверить не удалось: фиксируем случай и передаём человеку."""
        result = self._failure_result(job, reason.value.upper(), detail)
        result.status = ScanStatus.MANUAL_REVIEW

        entry = DeadLetter(
            scan_id=job.scan_id,
            sha256=job.sha256,
            reason=reason,
            verdict=result.verdict,
            detail=detail,
            stage=stage,
            delivered=delivered,
            tenant=job.tenant,
            source=job.source,
        )
        await self._dlq.publish(entry)
        logger.error(
            "задача отправлена в dead-letter",
            extra={
                "reason": reason.value,
                "verdict": result.verdict.value,
                "stage": stage,
                "delivered": delivered,
            },
        )
        # Статус живёт долго: его будет смотреть человек, а не polling клиента.
        await self._deliver(job, result, status_ttl_s=settings.dlq_status_ttl_s)

    @staticmethod
    def _failure_result(job: ScanJob, code: str, detail: str) -> ScanResult:
        return ScanResult(
            scan_id=job.scan_id,
            sha256=job.sha256,
            status=ScanStatus.FAILED,
            verdict=verdict_on_failure(job.policy),
            findings=[Finding(stage="worker", code=code, severity=Severity.MEDIUM, detail=detail)],
        )

    @staticmethod
    def _observe_verdict(job: ScanJob, result: ScanResult) -> None:
        """Завершённый скан — здесь, а не в gateway.

        Gateway видит вердикт только тогда, когда тот успел в `wait_ms`. Всё,
        что не успело, уходит клиенту коллбэком, и в gateway такой скан
        существует лишь как `202` без вердикта. Пока счёт вёлся там,
        `vs_scans_total` описывал не поток, а полосу между кэшем и дедлайном:
        тяжёлые файлы уходят в `202` чаще лёгких, а вердикт у них чаще не
        `clean`. На этом счётчике стоит алерт на долю вредоносных — он делил
        одно смещённое число на другое.

        Углублённая проверка сюда не попадает: клиент получил один ответ на
        файл, и второй вердикт не должен удваивать поток. Для неё нужна своя
        метрика — иначе расхождение быстрой и углублённой проверок, ради
        которого она и заведена, нигде не видно.

        Время меряется от постановки в очередь, а не от начала конвейера:
        ожидание в очереди клиент ждёт наравне с разбором.
        """
        current = metrics()
        current.scans.labels(
            verdict=result.verdict.value,
            tenant=tenant_label(job.tenant),
            mode=job.mode.value,
        ).inc()
        current.verdict_seconds.labels(
            profile=job.profile.value,
            cached=CACHED_STRUCTURAL if job.cached is not None else CACHED_NONE,
        ).observe(max(0.0, time.time() - job.enqueued_at))

    async def _deliver(
        self, job: ScanJob, result: ScanResult, status_ttl_s: int | None = None
    ) -> None:
        # История пишется для любого исхода, включая углублённый: инцидент
        # разбирают по обоим вердиктам, а не по тому, который успел первым.
        await self._record_history(job, result)

        if job.deep:
            # Второй вердикт не подменяет первый: клиент уже получил ответ и
            # действовал по нему. Углублённый приходит отдельным коллбэком.
            await self._deliver_deep(job, result)
            return

        self._observe_verdict(job, result)

        # Порядок важен: сначала разбудить gateway, потом кэш и вебхук.
        if status_ttl_s is None:
            await self._results.publish(result)
        else:
            await self._results.publish(result, status_ttl_s=status_ttl_s)

        # Результат сбоя не кэшируем: следующая попытка должна пройти проверку заново.
        if result.status is ScanStatus.DONE:
            await self._store_cache(job, result)

        await self._maybe_enqueue_deep(job, result)

        if job.policy.shadow_mode:
            # Считаем ОТКАЗЫ, а не только вердикт `malicious`. Файл, который не
            # удалось пересобрать, пользователю тоже не отдадут — не учитывать
            # это значило бы занижать цену включения блокировок.
            refused = result.verdict is Verdict.MALICIOUS or (
                job.mode is not ScanMode.DETECT and result.sanitized is None
            )
            await self._shadow.record(
                tenant=job.policy.tenant,
                verdict=result.verdict.value,
                would_block=refused,
                codes=[f.code for f in result.findings if f.score > 0],
                sha256=result.sha256,
            )
            # То же число, но на графике рядом с вердиктами. В Redis его видит
            # только тот, кто спросит через админский API, — а решение включать
            # блокировки принимают, глядя на то, как доля вела себя неделю.
            metrics().shadow_records.labels(
                tenant=tenant_label(job.policy.tenant),
                would_block=str(refused).lower(),
            ).inc()
            if refused:
                logger.warning(
                    "теневой режим: пользователю отказали бы",
                    extra={"score": result.score, "verdict": result.verdict.value},
                )

        # Слот освобождается всегда, включая отказы: иначе тенант, чьи файлы
        # стабильно роняют разбор, сам себе закроет квоту.
        await self._concurrency.release(job.tenant or "default", job.scan_id)

        if job.callback_url:
            await self._enqueue_callback(job, result)
            await self._enqueue_delivery(job, result)

    async def _store_cache(self, job: ScanJob, result: ScanResult) -> None:
        """Раскладывает результат по двум уровням.

        Структурная часть переживает обновление баз антивируса — именно ради
        этого уровни и разделены.
        """
        facts = result.facts
        if facts is None:
            return

        av_findings = [f for f in facts.findings if f.stage == "clamav"]
        structural = CachedStructural(
            sha256=result.sha256,
            profile=job.profile,
            facts=ScanFacts(
                findings=[
                    f
                    for f in facts.findings
                    if f.stage != "clamav" and f.code not in REQUEST_DERIVED_CODES
                ],
                detected_mime=facts.detected_mime,
                encrypted=facts.encrypted,
                supported=facts.supported,
                failed_stages={s for s in facts.failed_stages if s != "clamav"},
            ),
            engines={k: v for k, v in result.engines.items() if k != "clamav"},
            sanitized=result.sanitized,
            rules_version=self._pipeline.rules_version,
            stages=[t for t in result.stages if t.stage != "clamav"],
        )
        await self._structural.put(structural, weights_key_for(job.policy))

        await self._av_cache.put(
            CachedAv(
                sha256=result.sha256,
                facts=ScanFacts(
                    findings=av_findings,
                    failed_stages={s for s in facts.failed_stages if s == "clamav"},
                ),
                engines={"clamav": result.engines.get("clamav", {})},
                av_db_version=self._pipeline.engine_version,
            )
        )

    @staticmethod
    def _verdict_change(fast: ScanResult | None, deep: ScanResult) -> str:
        """Чем углублённая проверка разошлась с быстрой.

        `stricter` — быстрая пропустила: это цена бюджета в сотни миллисекунд,
        и ради её измерения выборка чистых и берётся. `looser` — быстрая
        сработала ложно. `resolved` — быстрая не смогла разобрать файл, а
        углублённая довела его до вердикта.

        `unknown` — не с чем сравнивать: статус быстрой проверки живёт по TTL и
        мог истечь. Это отдельное значение, а не «совпало»: молча посчитать
        несравнимое совпадением значит занизить долю пропусков, то есть ровно
        то число, ради которого всё считается.
        """
        if fast is None:
            return "unknown"
        if fast.verdict is deep.verdict:
            return "agree"

        before = _VERDICT_RANK.get(fast.verdict)
        after = _VERDICT_RANK.get(deep.verdict)
        if before is None:
            return "resolved" if after is not None else "unknown"
        if after is None:
            return "unknown"
        return "stricter" if after > before else "looser"

    async def _observe_deep_change(self, job: ScanJob, result: ScanResult) -> None:
        """Сравнение двух вердиктов — единственное, ради чего есть выборка чистых.

        Читает статус родителя из Redis: лишний вызов, но углублённая проверка
        и так вне горячего пути, а без сравнения дорогая работа не отвечает ни
        на один вопрос.
        """
        fast = await self._results.load_status(job.parent_scan_id) if job.parent_scan_id else None
        change = self._verdict_change(fast, result)
        metrics().deep_changes.labels(change=change).inc()
        if change in ("stricter", "looser"):
            logger.warning(
                "углублённая проверка разошлась с быстрой",
                extra={
                    "change": change,
                    "быстрая": fast.verdict.value if fast else "?",
                    "углублённая": result.verdict.value,
                    "reason": job.deep_reason,
                },
            )

    async def _deliver_deep(self, job: ScanJob, result: ScanResult) -> None:
        try:
            await self._observe_deep_change(job, result)
        except Exception:
            # Наблюдение не имеет права стоить вердикта: недоступный Redis
            # здесь означает потерю одного измерения, а не потерю результата.
            logger.warning("не удалось сравнить вердикты быстрой и углублённой проверок")

        logger.info(
            "углублённая проверка завершена",
            extra={
                "verdict": result.verdict.value,
                "score": result.score,
                "reason": job.deep_reason,
                "parent": job.parent_scan_id,
            },
        )
        await self._results.store_status(result, ttl_s=settings.dlq_status_ttl_s)
        if job.callback_url:
            await self._enqueue_callback(job, result)
            await self._enqueue_delivery(job, result)
        await self._concurrency.release(job.tenant or "default", job.scan_id)

    async def _publish_engine_version(self) -> None:
        """gateway берёт версию баз отсюда для ключа кэша."""
        await self._redis.set("engine:clamav:version", self._pipeline.engine_version, ex=3600)
        await self._redis.set(
            "engine:libmagic", "on" if self._pipeline.libmagic_available else "off", ex=3600
        )
        await self._redis.set("engine:rules:version", self._pipeline.rules_version, ex=3600)

        # Определение типа по таблице сигнатур вместо libmagic — это работающий
        # сервис с худшим детектом. В логах об этом одна строка при старте.
        metrics().report_degraded("libmagic", not self._pipeline.libmagic_available)
        # Веса рядом и по той же причине: файл задан и не прочитан — балл
        # считается по встроенной таблице, то есть по чужим порогам, и наружу
        # это выглядит как обычная работа.
        metrics().report_degraded("weights", self._pipeline.weights_degraded)

        # Момент сборки базы, а не только её версия: по версии не понять,
        # остановилось ли обновление. Публикуем разобранное значение, чтобы
        # gateway не знал формата строки clamd.
        built_at = parse_clamav_built_at(self._pipeline.engine_version)
        if built_at is not None:
            await self._redis.set("engine:clamav:built_at", str(built_at), ex=3600)
            age = age_of(
                built_at,
                stale_after_s=settings.av_db_stale_after_h * HOUR,
                expired_after_s=settings.av_db_expired_after_h * HOUR,
            )
            metrics().rules_age.labels(kind="av_db").set(age.seconds or 0.0)
            if age.state is not Freshness.FRESH:
                logger.warning(
                    "базы антивируса устарели",
                    extra={"возраст_ч": age.hours, "состояние": age.state.value},
                )

    async def stop(self) -> None:
        logger.info("остановка воркера")
        self._stopping.set()
        await self._redis.aclose()


async def amain() -> None:
    setup_logging(settings.service_name, settings.log_level, settings.log_format)
    setup_metrics(known_tenants=_known_tenants())
    # Имя сервиса берётся из роли: fast и deep — один образ, но в трейсах их
    # надо различать, иначе углублённая проверка сольётся с горячим путём.
    setup_tracing(
        f"{settings.service_name}-{settings.worker_mode}",
        enabled=settings.otel_enabled,
        endpoint=settings.otel_endpoint,
        sample_ratio=settings.otel_sample_ratio,
    )
    worker = Worker()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))

    try:
        await worker.start()
    finally:
        await worker.stop()
        # Досылаем накопленные спаны: иначе последние секунды работы воркера
        # в Tempo не попадут, а это ровно то время, когда он падал.
        shutdown_tracing()


def _known_tenants() -> tuple[str, ...]:
    """Список для меток метрик. Незнакомый тенант схлопывается в `other`."""
    return tuple(t.strip() for t in settings.known_tenants.split(",") if t.strip())


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
