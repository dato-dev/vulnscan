"""Result Writer: история проверок в PostgreSQL.

Отдельный сервис, а не часть воркера, по одной причине: воркер разбирает
враждебные файлы, и сетевой доступ к базе из него — лишняя дверь. Результаты
доезжают сюда потоком Redis, база принадлежит только этому процессу.

Потеря истории не должна ломать проверку файлов, поэтому обратной связи нет:
воркер публикует и идёт дальше, а недоставленное копится в потоке.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time

from vscommon.logging import setup_logging
from vscommon.metrics import metrics, setup_metrics
from vscommon.metrics import serve as serve_metrics
from vscommon.models import ScanRecord
from vscommon.queue import ResultStream
from vscommon.redis_client import create_redis
from vscommon.telemetry import setup_tracing, shutdown_tracing

from .config import settings
from .db import Database

logger = logging.getLogger(__name__)

PRUNE_INTERVAL_S = 6 * 3600


class Writer:
    def __init__(self) -> None:
        self._redis = create_redis(settings.redis_url, blocking=True)
        self._stream = ResultStream(self._redis, settings.results_stream, settings.results_group)
        self._db = Database(settings.postgres_dsn)
        self._stopping = asyncio.Event()
        self._batch: list[tuple[str, ScanRecord]] = []
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        await self._db.connect()
        await self._db.migrate()
        await self._stream.ensure_group()

        if settings.metrics_enabled:
            serve_metrics(settings.metrics_port)

        logger.info("writer запущен", extra={"consumer": settings.consumer_name})
        prune_task = asyncio.create_task(self._prune_loop())
        flush_task = asyncio.create_task(self._flush_loop())

        try:
            async for entry_id, record in self._stream.consume(settings.consumer_name):
                if self._stopping.is_set():
                    break
                async with self._lock:
                    self._batch.append((entry_id, record))
                    full = len(self._batch) >= settings.batch_size
                if full:
                    await self._flush_pending()
        finally:
            # Незаписанное дописываем на выходе: иначе штатная остановка теряла
            # бы последнюю пачку.
            await self._flush_pending()
            for task in (prune_task, flush_task):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    async def _flush_loop(self) -> None:
        """Сброс по времени.

        Без него пачка ждала бы, пока наберётся целиком: при пяти сканах в час
        история оставалась бы невидимой до перезапуска — а ради неё writer и
        существует. Размер пачки экономит транзакции, но не должен превращаться
        в срок хранения в памяти.
        """
        while not self._stopping.is_set():
            await asyncio.sleep(settings.flush_interval_s)
            await self._flush_pending()

    async def _flush_pending(self) -> None:
        """Забирает накопленное под замком и пишет.

        Замок здесь обязателен: цикл чтения и цикл сброса работают
        одновременно, и без него пачку можно записать дважды или потерять.
        """
        async with self._lock:
            batch, self._batch = self._batch, []
        if batch:
            await self._flush(batch)

    async def _flush(self, batch: list[tuple[str, ScanRecord]]) -> None:
        """Записывает пачку и подтверждает её.

        Ack только после успешной записи: иначе сбой базы означал бы потерю
        истории без следа. Повторная доставка безопасна — запись идемпотентна
        по идентификатору скана.
        """
        records = [record for _entry_id, record in batch]
        try:
            written = await self._db.store(records)
        except Exception:
            # Записи не подтверждены в потоке, поэтому не потеряны: вернём их
            # в пачку и попробуем снова. Без возврата они ушли бы из памяти,
            # а из потока — только по истечении срока хранения.
            logger.exception("не удалось записать историю, повторим")
            metrics().stage_failures.labels(stage="writer", reason="db").inc()
            async with self._lock:
                self._batch = batch + self._batch
            return

        for entry_id, _record in batch:
            await self._stream.ack(entry_id)
        logger.info("история записана", extra={"записей": written})

        # Отставание меряется здесь, а не на приёме: до записи в базу история
        # существует только в памяти процесса. Именно так она однажды и жила —
        # сброс шёл раз в 64 записи, при слабом потоке база оставалась пустой,
        # и выглядело это как работающий сервис.
        now = time.time()
        for _entry_id, record in batch:
            metrics().history_lag.observe(max(0.0, now - record.result.created_at))

    async def _prune_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                await self._db.prune(settings.history_retention_days)
            except Exception:
                logger.exception("не удалось подчистить историю")
            await asyncio.sleep(PRUNE_INTERVAL_S)

    async def stop(self) -> None:
        self._stopping.set()
        await self._db.close()
        await self._redis.aclose()
        logger.info("остановка writer")


async def amain() -> None:
    setup_logging(settings.service_name, settings.log_level, settings.log_format)
    setup_metrics()
    setup_tracing(
        settings.service_name,
        enabled=settings.otel_enabled,
        endpoint=settings.otel_endpoint,
        sample_ratio=settings.otel_sample_ratio,
    )
    writer = Writer()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(writer.stop()))

    try:
        await writer.start()
    finally:
        await writer.stop()
        shutdown_tracing()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
