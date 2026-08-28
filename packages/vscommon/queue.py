"""Очередь задач на Redis Streams и канал доставки результата в gateway."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from vscommon.models import CallbackTask, DeadLetter, ScanJob, ScanRecord, ScanResult

logger = logging.getLogger(__name__)

RESULT_TTL_S = 300


@dataclass(slots=True)
class PendingEntry:
    """Задача, взятая в работу и не подтверждённая."""

    entry_id: str
    consumer: str
    idle_ms: int
    delivered: int


class JobQueue:
    """XADD со стороны gateway, consumer group со стороны воркеров."""

    def __init__(self, redis: Redis, stream: str, group: str) -> None:
        self._redis = redis
        self._stream = stream
        self._group = group

    async def ensure_group(self) -> None:
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
            logger.info("создана consumer group", extra={"stream": self._stream})
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def publish(self, job: ScanJob) -> str:
        return await self._redis.xadd(self._stream, {"job": job.model_dump_json()})

    async def consume(
        self, consumer: str, block_ms: int = 5_000
    ) -> AsyncIterator[tuple[str, ScanJob]]:
        """Бесконечный поток задач. Ack выполняет вызывающий через `ack()`."""
        while True:
            try:
                batches = await self._redis.xreadgroup(
                    self._group, consumer, {self._stream: ">"}, count=1, block=block_ms
                )
            except RedisTimeoutError:
                # Истёк BLOCK — сообщений просто нет. Это не отказ.
                continue
            except ResponseError as exc:
                if "NOGROUP" not in str(exc):
                    raise
                # Redis перезапустили, и поток вместе с группой исчез. У нас
                # он живёт в памяти без сохранения на диск, так что это штатный
                # исход перезагрузки сервера, а не авария. Пересоздаём группу
                # и продолжаем: иначе воркеры остаются сломанными до рестарта.
                logger.warning(
                    "consumer group исчезла, создаю заново", extra={"stream": self._stream}
                )
                await self.ensure_group()
                continue
            if not batches:
                continue
            for _stream, entries in batches:
                for entry_id, fields in entries:
                    raw = fields.get("job") or fields.get(b"job")
                    try:
                        job = ScanJob.model_validate_json(raw)
                    except ValueError:
                        logger.exception("нераспознанное сообщение, ack и пропуск")
                        await self.ack(entry_id)
                        continue
                    yield entry_id, job

    async def ack(self, entry_id: str) -> None:
        await self._redis.xack(self._stream, self._group, entry_id)

    async def pending(self, count: int = 64) -> list[PendingEntry]:
        """Незакрытые задачи группы вместе с временем простоя и числом доставок.

        Фильтр по idle делаем на своей стороне, а не параметром XPENDING:
        реализации расходятся в трактовке `IDLE 0`.
        """
        rows = await self._redis.xpending_range(
            self._stream, self._group, min="-", max="+", count=count
        )
        return [
            PendingEntry(
                entry_id=row["message_id"],
                consumer=row["consumer"],
                idle_ms=int(row["time_since_delivered"]),
                delivered=int(row["times_delivered"]),
            )
            for row in rows
        ]

    async def claim(
        self, consumer: str, entry_ids: list[str], min_idle_ms: int
    ) -> list[tuple[str, ScanJob]]:
        """Переназначает задачи на себя.

        `min_idle_ms` здесь не только фильтр, но и защита от гонки: XCLAIM
        сбрасывает idle в ноль, поэтому второй reclaimer уже не заберёт то же
        сообщение.
        """
        if not entry_ids:
            return []

        entries = await self._redis.xclaim(
            self._stream, self._group, consumer, min_idle_time=min_idle_ms, message_ids=entry_ids
        )
        claimed: list[tuple[str, ScanJob]] = []
        for entry_id, fields in entries:
            raw = fields.get("job") or fields.get(b"job")
            try:
                job = ScanJob.model_validate_json(raw)
            except ValueError:
                logger.exception("нераспознанное сообщение при подхвате, ack и пропуск")
                await self.ack(entry_id)
                continue
            claimed.append((entry_id, job))
        return claimed


class Heartbeat:
    """Отметка «задача в работе у живого воркера».

    Основной признак смерти владельца — исчезнувший heartbeat, а не время
    простоя: иначе пришлось бы ждать дольше самой долгой легальной обработки.
    """

    def __init__(self, redis: Redis, ttl_s: int = 30) -> None:
        self._redis = redis
        self._ttl = ttl_s
        self._refresh_interval = max(ttl_s / 3, 1.0)

    @staticmethod
    def _key(entry_id: str) -> str:
        return f"inflight:{entry_id}"

    async def beat(self, entry_id: str, consumer: str) -> None:
        await self._redis.set(self._key(entry_id), consumer, ex=self._ttl)

    async def clear(self, entry_id: str) -> None:
        await self._redis.delete(self._key(entry_id))

    async def alive(self, entry_id: str) -> bool:
        return bool(await self._redis.exists(self._key(entry_id)))

    @asynccontextmanager
    async def keep(self, entry_id: str, consumer: str):
        """Держит отметку живой всё время обработки задачи."""

        async def refresher() -> None:
            while True:
                await asyncio.sleep(self._refresh_interval)
                await self.beat(entry_id, consumer)

        await self.beat(entry_id, consumer)
        task = asyncio.create_task(refresher())
        try:
            yield
        finally:
            task.cancel()
            await self.clear(entry_id)


class ResultChannel:
    """Канал ожидания результата.

    Уведомление идёт через pub/sub, а не через список: одного результата могут
    ждать несколько запросов — дедупликация присылает их на общий `scan_id`.
    `BLPOP` отдал бы значение только первому.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    @staticmethod
    def _channel(scan_id: str) -> str:
        return f"result:{scan_id}"

    async def wait(self, scan_id: str, timeout_ms: int) -> ScanResult | None:
        channel = self._channel(scan_id)
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(channel)
        try:
            # Дождаться подтверждения подписки обязательно: до него publish
            # нас не увидит, и сигнал будет потерян.
            await pubsub.get_message(timeout=1.0)

            # Проверка ПОСЛЕ подписки: результат мог прийти, пока подписывались.
            ready = await self.load_status(scan_id)
            if ready is not None:
                return ready
            if timeout_ms <= 0:
                return None

            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=max(timeout_ms / 1000, 0.001)
            )
            if message is None:
                return None
            return await self.load_status(scan_id)
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()

    async def publish(self, result: ScanResult, status_ttl_s: int = RESULT_TTL_S) -> None:
        """Сохраняет снимок и будит всех ожидающих.

        Порядок обязателен: сначала статус, потом сигнал. Иначе разбуженный
        клиент прочитает пустоту.
        """
        await self.store_status(result, ttl_s=status_ttl_s)
        await self._redis.publish(self._channel(result.scan_id), result.status.value)

    async def store_status(self, result: ScanResult, ttl_s: int = RESULT_TTL_S) -> None:
        """Снимок для polling через GET /v1/scan/{id}.

        Для задач, ушедших в dead-letter, TTL длиннее: их разбирает человек,
        и статус должен пережить пять минут.
        """
        await self._redis.set(f"status:{result.scan_id}", result.model_dump_json(), ex=ttl_s)

    async def load_status(self, scan_id: str) -> ScanResult | None:
        raw = await self._redis.get(f"status:{scan_id}")
        return ScanResult.model_validate_json(raw) if raw else None


class ResultStream:
    """Поток завершённых сканов для долговременного хранения.

    Отдельно от `ResultChannel`: тот отдаёт результат ждущему клиенту и живёт
    минутами, а этот — история, которую читает Result Writer. Смешивать нельзя,
    у них разные сроки жизни и разные потребители.

    Воркер сюда только пишет. В БД он не ходит: доступа к ней у него нет и быть
    не должно — это процесс, который разбирает враждебные файлы.
    """

    def __init__(self, redis: Redis, stream: str, group: str, maxlen: int = 100_000) -> None:
        self._redis = redis
        self._stream = stream
        self._group = group
        self._maxlen = maxlen

    async def ensure_group(self) -> None:
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
            logger.info("создана consumer group истории", extra={"stream": self._stream})
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def publish(self, record: ScanRecord) -> str:
        """Публикация не должна ронять обработку задачи.

        История ценна, но вердикт клиенту важнее: если поток недоступен,
        скан всё равно обязан завершиться.
        """
        entry_id: str = await self._redis.xadd(
            self._stream,
            {"record": record.model_dump_json()},
            maxlen=self._maxlen,
            approximate=True,
        )
        return entry_id

    async def consume(
        self, consumer: str, block_ms: int = 5_000, count: int = 32
    ) -> AsyncIterator[tuple[str, ScanRecord]]:
        while True:
            try:
                batches = await self._redis.xreadgroup(
                    self._group, consumer, {self._stream: ">"}, count=count, block=block_ms
                )
            except RedisTimeoutError:
                continue
            except ResponseError as exc:
                if "NOGROUP" not in str(exc):
                    raise
                logger.warning("группа истории исчезла, создаю заново")
                await self.ensure_group()
                continue
            if not batches:
                continue
            for _stream, entries in batches:
                for entry_id, fields in entries:
                    raw = fields.get("record") or fields.get(b"record")
                    try:
                        yield entry_id, ScanRecord.model_validate_json(raw)
                    except ValueError:
                        logger.exception("нераспознанный результат, ack и пропуск")
                        await self.ack(entry_id)

    async def ack(self, entry_id: str) -> None:
        await self._redis.xack(self._stream, self._group, entry_id)

    async def pending_count(self) -> int:
        """Сколько результатов ещё не записано в БД."""
        info = await self._redis.xpending(self._stream, self._group)
        return int(info.get("pending", 0)) if isinstance(info, dict) else 0


class CallbackQueue:
    """Очередь доставки результатов клиентам.

    Два хранилища на одну задачу: поток для новых заданий и упорядоченное
    множество для отложенных повторов. Держать повторы в самом потоке нельзя —
    он выдаёт сообщения сразу, а нам нужно «через четыре минуты».
    """

    def __init__(self, redis: Redis, stream: str, group: str, maxlen: int = 50_000) -> None:
        self._redis = redis
        self._stream = stream
        self._group = group
        self._maxlen = maxlen
        self._retry_key = f"{stream}:retry"

    async def ensure_group(self) -> None:
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
            logger.info("создана consumer group доставки", extra={"stream": self._stream})
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def publish(self, task: CallbackTask) -> str:
        entry_id: str = await self._redis.xadd(
            self._stream,
            {"task": task.model_dump_json()},
            maxlen=self._maxlen,
            approximate=True,
        )
        return entry_id

    async def consume(
        self, consumer: str, block_ms: int = 2_000
    ) -> AsyncIterator[tuple[str, CallbackTask]]:
        while True:
            try:
                batches = await self._redis.xreadgroup(
                    self._group, consumer, {self._stream: ">"}, count=16, block=block_ms
                )
            except RedisTimeoutError:
                continue
            except ResponseError as exc:
                if "NOGROUP" not in str(exc):
                    raise
                logger.warning("группа доставки исчезла, создаю заново")
                await self.ensure_group()
                continue
            if not batches:
                continue
            for _stream, entries in batches:
                for entry_id, fields in entries:
                    raw = fields.get("task") or fields.get(b"task")
                    try:
                        yield entry_id, CallbackTask.model_validate_json(raw)
                    except ValueError:
                        logger.exception("нераспознанное задание доставки, ack и пропуск")
                        await self.ack(entry_id)

    async def ack(self, entry_id: str) -> None:
        await self._redis.xack(self._stream, self._group, entry_id)

    async def schedule_retry(self, task: CallbackTask, delay_s: float) -> None:
        """Откладывает повтор. Задание хранится целиком в множестве."""
        await self._redis.zadd(self._retry_key, {task.model_dump_json(): time.time() + delay_s})

    async def due_retries(self, limit: int = 32) -> list[CallbackTask]:
        """Забирает задания, которым пора. Забранное сразу удаляется.

        Удаление до попытки, а не после: иначе два экземпляра notifier взяли бы
        одно задание и клиент получил бы результат дважды.
        """
        now = time.time()
        raw = await self._redis.zrangebyscore(self._retry_key, "-inf", now, start=0, num=limit)
        if not raw:
            return []
        await self._redis.zrem(self._retry_key, *raw)

        tasks: list[CallbackTask] = []
        for item in raw:
            try:
                tasks.append(CallbackTask.model_validate_json(item))
            except ValueError:
                logger.exception("нераспознанное отложенное задание, пропуск")
        return tasks

    async def pending_retries(self) -> int:
        return int(await self._redis.zcard(self._retry_key))


class DeadLetterQueue:
    """Задачи, которые не удалось проверить. Разбираются человеком.

    Отдельный поток, а не общий с задачами: сюда не должны попадать воркеры,
    а размер ограничен, чтобы всплеск отказов не съел память Redis.
    """

    def __init__(self, redis: Redis, stream: str, maxlen: int = 10_000) -> None:
        self._redis = redis
        self._stream = stream
        self._maxlen = maxlen

    async def publish(self, entry: DeadLetter) -> str:
        entry_id: str = await self._redis.xadd(
            self._stream,
            {"entry": entry.model_dump_json()},
            maxlen=self._maxlen,
            approximate=True,
        )
        return entry_id

    async def recent(self, count: int = 50) -> list[DeadLetter]:
        """Последние записи, новые первыми."""
        rows = await self._redis.xrevrange(self._stream, count=count)
        entries: list[DeadLetter] = []
        for _entry_id, fields in rows:
            raw = fields.get("entry") or fields.get(b"entry")
            try:
                entries.append(DeadLetter.model_validate_json(raw))
            except ValueError:
                logger.warning("битая запись в dead-letter, пропускаю")
        return entries

    async def size(self) -> int:
        return int(await self._redis.xlen(self._stream))
