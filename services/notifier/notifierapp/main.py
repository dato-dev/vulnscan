"""Notifier: доставка результатов клиентам.

Вынесен из воркера по двум причинам, и обе принципиальные.

**Секреты.** Коллбэк подписывается ключом тенанта. Держать ключи всех тенантов
в процессе, который разбирает враждебные файлы, значит менять одну дыру в
парсере на компрометацию всех клиентов сразу. Здесь недоверенный контент не
разбирается — только HTTP наружу.

**Время.** Три попытки за несколько секунд хватало соседнему контейнеру и не
хватало разрыву между площадками. Ретраи на десятки минут нельзя держать внутри
обработки задачи: воркер всё это время занят и не берёт новые файлы.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal

from vscommon.keys import KeyRegistry
from vscommon.logging import log_context, setup_logging
from vscommon.metrics import metrics, setup_metrics
from vscommon.metrics import serve as serve_metrics
from vscommon.models import CallbackTask, DeadLetter, DeadLetterReason
from vscommon.queue import CallbackQueue, DeadLetterQueue
from vscommon.redis_client import create_redis
from vscommon.telemetry import continue_trace, setup_tracing, shutdown_tracing

from .config import settings
from .sender import CallbackSender

logger = logging.getLogger(__name__)

KEYS_RELOAD_INTERVAL_S = 30.0


class Notifier:
    def __init__(self) -> None:
        self._redis = create_redis(settings.redis_url, blocking=True)
        self._queue = CallbackQueue(
            self._redis, settings.callbacks_stream, settings.callbacks_group
        )
        self._dlq = DeadLetterQueue(self._redis, settings.dlq_stream, settings.dlq_maxlen)
        self._keys = KeyRegistry.load(settings.keys_file)
        self._sender = CallbackSender(self._keys)
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        await self._queue.ensure_group()
        if settings.metrics_enabled:
            serve_metrics(settings.metrics_port)

        logger.info("notifier запущен", extra={"ключей": len(self._keys)})
        loops = [
            asyncio.create_task(self._retry_loop()),
            asyncio.create_task(self._keys_loop()),
        ]

        try:
            async for entry_id, task in self._queue.consume(settings.consumer_name):
                if self._stopping.is_set():
                    break
                await self._attempt(task)
                # Подтверждаем сразу: дальнейшая судьба задания живёт в
                # множестве повторов, а не в потоке. Иначе неудачная доставка
                # держала бы сообщение неподтверждённым часами.
                await self._queue.ack(entry_id)
        finally:
            for loop in loops:
                loop.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await loop

    async def _attempt(self, task: CallbackTask) -> None:
        with (
            log_context(scan_id=task.scan_id, tenant=task.tenant),
            continue_trace(
                task.traceparent,
                "callback.deliver",
                host=task.host,
                attempt=task.attempt,
            ),
        ):
            outcome = await self._sender.send(task)

            if outcome.delivered:
                metrics().callbacks.labels(outcome="delivered").inc()
                logger.info(
                    "коллбэк доставлен",
                    extra={"host": task.host, "попытка": task.attempt + 1},
                )
                return

            if not outcome.retryable:
                metrics().callbacks.labels(outcome="rejected").inc()
                logger.warning(
                    "коллбэк отклонён без повтора",
                    extra={"host": task.host, "причина": outcome.detail},
                )
                await self._give_up(task, outcome.detail)
                return

            await self._reschedule(task, outcome.detail)

    async def _reschedule(self, task: CallbackTask, detail: str) -> None:
        attempt = task.attempt + 1
        if attempt >= settings.max_attempts:
            metrics().callbacks.labels(outcome="lost").inc()
            logger.error(
                "коллбэк не доставлен после всех попыток",
                extra={"host": task.host, "попыток": attempt, "причина": detail},
            )
            await self._give_up(task, detail)
            return

        delay = min(settings.base_backoff_s * 2 ** (attempt - 1), settings.max_backoff_s)
        await self._queue.schedule_retry(task.model_copy(update={"attempt": attempt}), delay)
        metrics().callbacks.labels(outcome="retry").inc()
        logger.warning(
            "коллбэк не доставлен, повтор отложен",
            extra={
                "host": task.host,
                "попытка": attempt,
                "через_с": round(delay),
                "причина": detail,
            },
        )

    async def _give_up(self, task: CallbackTask, detail: str) -> None:
        """Недоставленное должно быть видно.

        Молча потерянный результат для клиента неотличим от того, что файл не
        проверяли, — поэтому он уходит в разбор человеком, а не в пустоту.
        """
        try:
            await self._dlq.publish(
                DeadLetter(
                    scan_id=task.scan_id,
                    sha256="",
                    reason=DeadLetterReason.CALLBACK_FAILED,
                    detail=f"{task.host}: {detail}",
                    tenant=task.tenant,
                )
            )
        except Exception:
            logger.exception("не удалось записать недоставленный коллбэк в dead-letter")

    async def _retry_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                for task in await self._queue.due_retries():
                    await self._attempt(task)
                metrics().queue_depth.labels(stream="callbacks:retry").set(
                    await self._queue.pending_retries()
                )
            except Exception:
                logger.exception("сбой в цикле повторов доставки")
            await asyncio.sleep(settings.retry_poll_interval_s)

    async def _keys_loop(self) -> None:
        """Перечитывает ключи: отозванный ключ не должен подписывать коллбэки."""
        while not self._stopping.is_set():
            await asyncio.sleep(KEYS_RELOAD_INTERVAL_S)
            try:
                keys = KeyRegistry.load(settings.keys_file)
                if keys.fingerprint() != self._keys.fingerprint():
                    self._keys = keys
                    self._sender.rebind(keys)
                    logger.info("реестр ключей перезагружен")
            except Exception:
                logger.exception("не удалось перечитать реестр ключей")

    async def stop(self) -> None:
        self._stopping.set()
        await self._sender.close()
        await self._redis.aclose()
        logger.info("остановка notifier")


async def amain() -> None:
    setup_logging(settings.service_name, settings.log_level, settings.log_format)
    setup_metrics()
    setup_tracing(
        settings.service_name,
        enabled=settings.otel_enabled,
        endpoint=settings.otel_endpoint,
        sample_ratio=settings.otel_sample_ratio,
    )
    notifier = Notifier()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(notifier.stop()))

    try:
        await notifier.start()
    finally:
        await notifier.stop()
        shutdown_tracing()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
