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

    async def start(self) -> None:
        await self._db.connect()
        await self._db.migrate()
        await self._stream.ensure_group()

        if settings.metrics_enabled:
            serve_metrics(settings.metrics_port)

        logger.info("writer запущен", extra={"consumer": settings.consumer_name})
        prune_task = asyncio.create_task(self._prune_loop())

        batch: list[tuple[str, ScanRecord]] = []
        try:
            async for entry_id, record in self._stream.consume(settings.consumer_name):
                if self._stopping.is_set():
                    break
                batch.append((entry_id, record))
                if len(batch) >= settings.batch_size:
                    await self._flush(batch)
                    batch = []
        finally:
            # Незаписанное дописываем на выходе: иначе штатная остановка теряла
            # бы последнюю пачку, хотя задачи уже подтверждены воркером.
            if batch:
                await self._flush(batch)
            prune_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await prune_task

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
            logger.exception("не удалось записать историю, пачка остаётся в потоке")
            metrics().stage_failures.labels(stage="writer", reason="db").inc()
            return

        for entry_id, _record in batch:
            await self._stream.ack(entry_id)
        logger.info("история записана", extra={"записей": written})

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
