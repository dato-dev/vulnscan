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
import tempfile
from pathlib import Path

from vscommon.delivery import CredentialsRegistry, DeliveryCredentials
from vscommon.keys import KeyRegistry
from vscommon.logging import log_context, setup_logging
from vscommon.metrics import metrics, setup_metrics, tenant_label
from vscommon.metrics import serve as serve_metrics
from vscommon.models import CallbackTask, DeadLetter, DeadLetterReason, DeliveryTask
from vscommon.queue import CallbackQueue, DeadLetterQueue, DeliveryQueue
from vscommon.redis_client import create_redis
from vscommon.storage import build_store
from vscommon.telemetry import continue_trace, setup_tracing, shutdown_tracing

from .config import settings
from .dropoff import REBUILT_PREFIX, Dropoff, DropoffError, manifest_for
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
        self._deliveries = DeliveryQueue(
            self._redis, settings.delivery_stream, settings.delivery_group
        )
        self._credentials = CredentialsRegistry.load(settings.delivery_credentials_file)
        # Ноль выставляется всегда, а не только при поломке: ряд, появляющийся
        # лишь в аварии, неотличим от неработающего экспорта метрик. Файл
        # учёток задан и не прочитан — доставки не будет ни одной, а ящик
        # клиента выглядит так же, как при отсутствии файлов на проверку.
        metrics().report_degraded("delivery", self._credentials.degraded)
        self._store = build_store(settings)
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        await self._queue.ensure_group()
        if settings.metrics_enabled:
            serve_metrics(settings.metrics_port)

        await self._deliveries.ensure_group()

        logger.info(
            "notifier запущен",
            extra={"ключей": len(self._keys), "приёмников": len(self._credentials)},
        )
        loops = [
            asyncio.create_task(self._retry_loop()),
            asyncio.create_task(self._keys_loop()),
            # Отдельный цикл, а не общий с коллбэками: выгрузка файла упирается
            # в чужое хранилище и может тянуться минутами. В одном цикле она
            # задерживала бы уведомления всем остальным тенантам.
            asyncio.create_task(self._delivery_loop()),
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

    async def _delivery_loop(self) -> None:
        """Выгружает обезвреженные копии в хранилища клиентов (M14.1)."""
        try:
            async for entry_id, task in self._deliveries.consume(settings.consumer_name):
                if self._stopping.is_set():
                    break
                await self._deliver(task)
                await self._deliveries.ack(entry_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("цикл выгрузки копий остановлен")

    async def _deliver(self, task: DeliveryTask) -> None:
        with (
            log_context(scan_id=task.scan_id, tenant=task.tenant),
            continue_trace(task.traceparent, "delivery.put", tenant=tenant_label(task.tenant)),
        ):
            credentials = self._credentials.get(task.destination.credentials_id)
            if credentials is None:
                # Учётки нет — повторять бессмысленно: это конфигурация, а не
                # сетевая помеха. Но и молчать нельзя: тенанту приёмник
                # настроили, значит файлов ждут.
                await self._delivery_failed(
                    task, f"нет учётных данных «{task.destination.credentials_id}»"
                )
                return

            try:
                await asyncio.to_thread(self._put, task, credentials)
            except DropoffError as exc:
                await self._retry_delivery(task, str(exc))
                return
            except Exception as exc:
                logger.exception("непредвиденный сбой выгрузки копии")
                await self._retry_delivery(task, repr(exc))
                return

            # Разные исходы, а не один «успех»: отданный файл и один манифест
            # означают разное для того, кто смотрит в ящик. Доля
            # `manifest_only`, уехавшая вверх, — это выросшая блокировка, а не
            # поломка доставки, и путать их на графике нельзя.
            outcome = "delivered" if task.artifact is not None else "manifest_only"
            metrics().copies_delivered.labels(outcome=outcome).inc()
            logger.info(
                "копия выгружена в хранилище клиента",
                extra={
                    "bucket": task.destination.bucket,
                    "выгружен_файл": task.artifact is not None,
                },
            )

    def _put(self, task: DeliveryTask, credentials: DeliveryCredentials) -> None:
        """Синхронная часть: сеть и файлы. Идёт в пуле потоков.

        Порядок обязателен: сначала файл, потом манифест. Манифест утверждает,
        что файл рядом есть, и появившись первым, он утверждал бы это до того,
        как это стало правдой. Читатель ящика, доверяющий манифесту, забрал бы
        пустоту.
        """
        dropoff = Dropoff(task.destination, credentials)
        # Пересобранное из заблокированного — в свой каталог, вместе с
        # манифестом. Иначе оно легло бы рядом с обычными копиями и было бы
        # обработано как обычная.
        name = (REBUILT_PREFIX + task.name) if task.rebuilt_from_blocked else task.name

        if task.artifact is not None:
            with tempfile.TemporaryDirectory(prefix="vsdrop-") as tmp:
                local = self._store.get_to_path(task.artifact, Path(tmp) / "copy")
                dropoff.put_file(task.artifact, local, name)

        dropoff.put_manifest(
            name,
            manifest_for(
                task.payload,
                name,
                delivered=task.artifact is not None,
                rebuilt_from_blocked=task.rebuilt_from_blocked,
            ),
        )

    async def _retry_delivery(self, task: DeliveryTask, detail: str) -> None:
        attempt = task.attempt + 1
        if attempt >= settings.max_attempts:
            await self._delivery_failed(task, f"после {attempt} попыток: {detail}")
            return

        delay = min(settings.base_backoff_s * 2 ** (attempt - 1), settings.max_backoff_s)
        await self._deliveries.schedule_retry(task.model_copy(update={"attempt": attempt}), delay)
        metrics().copies_delivered.labels(outcome="retry").inc()
        logger.warning(
            "копия не выгружена, повтор отложен",
            extra={"bucket": task.destination.bucket, "попытка": attempt, "причина": detail},
        )

    async def _delivery_failed(self, task: DeliveryTask, detail: str) -> None:
        """Невыгруженное должно быть видно.

        Приёмник пуст и при исправной работе, и при отказе доставки. Не оставив
        следа, мы сделали бы эти два состояния неразличимыми для всех сразу: и
        для клиента, который смотрит в ящик, и для дежурного.
        """
        metrics().copies_delivered.labels(outcome="lost").inc()
        logger.error(
            "копия не выгружена в хранилище клиента",
            extra={"bucket": task.destination.bucket, "причина": detail},
        )
        try:
            await self._dlq.publish(
                DeadLetter(
                    scan_id=task.scan_id,
                    sha256="",
                    reason=DeadLetterReason.DELIVERY_FAILED,
                    detail=f"{task.destination.bucket}: {detail}",
                    tenant=task.tenant,
                )
            )
        except Exception:
            logger.exception("не удалось записать невыгруженную копию в dead-letter")

    async def _retry_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                for task in await self._queue.due_retries():
                    await self._attempt(task)
                metrics().queue_depth.labels(stream="callbacks:retry").set(
                    await self._queue.pending_retries()
                )
                # Отложенные выгрузки — там же, где отложенные коллбэки:
                # растущая очередь повторов означает недоступный приёмник, и
                # заметить это надо раньше, чем клиент спросит про файлы.
                for task in await self._deliveries.due_retries():
                    await self._deliver(task)
                metrics().queue_depth.labels(stream="delivery:retry").set(
                    await self._deliveries.pending_retries()
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
