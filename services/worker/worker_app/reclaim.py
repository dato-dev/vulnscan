"""Подхват задач, зависших после падения воркера (ROADMAP M1.2).

Redis Streams даёт at-least-once только при условии, что кто-то разбирает
pending-список упавшего потребителя. Без этого задача остаётся в PEL навсегда,
и требование «потеря результатов 0» не выполняется.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from vscommon.models import ScanJob
from vscommon.queue import Heartbeat, JobQueue, PendingEntry

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ClaimedJob:
    entry_id: str
    job: ScanJob
    delivered: int
    """Сколько раз задача уже выдавалась — нужно для dead-letter."""


@dataclass(slots=True)
class SweepResult:
    reclaimed: list[ClaimedJob] = field(default_factory=list)
    """Задачи мёртвого воркера, взятые на себя для обычной обработки."""

    abandoned: list[ClaimedJob] = field(default_factory=list)
    """Исчерпали лимит доставок: перевыдавать дальше нельзя, отправляем в dead-letter."""

    def __bool__(self) -> bool:
        return bool(self.reclaimed or self.abandoned)


class StuckJobReclaimer:
    def __init__(
        self,
        queue: JobQueue,
        heartbeat: Heartbeat,
        consumer: str,
        min_idle_s: float,
        max_deliveries: int,
        batch: int = 64,
    ) -> None:
        self._queue = queue
        self._heartbeat = heartbeat
        self._consumer = consumer
        self._min_idle_ms = int(min_idle_s * 1000)
        self._max_deliveries = max_deliveries
        self._batch = batch

    async def _is_orphaned(self, entry: PendingEntry) -> bool:
        """Задача осталась без живого владельца."""
        if entry.idle_ms < self._min_idle_ms:
            # Выдана только что — первый heartbeat мог не успеть проставиться.
            return False
        # Основной признак: heartbeat владельца исчез. Ждать таймаута самой
        # долгой легальной обработки (профиль strict — минуты) не приходится.
        return not await self._heartbeat.alive(entry.entry_id)

    async def sweep(self) -> SweepResult:
        """Один проход по pending-списку группы.

        Забираем не больше `batch` записей за проход; при очень большом
        pending-списке живых задач стоит поднять batch выше суммарной
        конкурентности всех воркеров.
        """
        entries = await self._queue.pending(count=self._batch)
        if not entries:
            return SweepResult()

        # Забрать нужно и «брошенные» задачи тоже: без полезной нагрузки не
        # построить результат — нужны scan_id, политика и адрес коллбэка.
        # Поэтому классификация и claim разведены на два шага.
        to_claim: list[str] = []
        abandoned_ids: set[str] = set()
        delivered_by_id: dict[str, int] = {}

        for entry in entries:
            if not await self._is_orphaned(entry):
                continue
            to_claim.append(entry.entry_id)
            delivered_by_id[entry.entry_id] = entry.delivered
            if entry.delivered > self._max_deliveries:
                abandoned_ids.add(entry.entry_id)
                logger.error(
                    "задача исчерпала лимит доставок",
                    extra={
                        "entry": entry.entry_id,
                        "delivered": entry.delivered,
                        "prev_consumer": entry.consumer,
                    },
                )

        if not to_claim:
            return SweepResult()

        claimed = await self._queue.claim(self._consumer, to_claim, self._min_idle_ms)

        result = SweepResult()
        for entry_id, job in claimed:
            target = result.abandoned if entry_id in abandoned_ids else result.reclaimed
            target.append(
                ClaimedJob(entry_id=entry_id, job=job, delivered=delivered_by_id[entry_id])
            )

        if result.reclaimed:
            logger.warning(
                "подхвачены задачи мёртвого воркера",
                extra={"count": len(result.reclaimed), "consumer": self._consumer},
            )
        return result
