"""M1.2: задача упавшего воркера не теряется, но и не перевыдаётся бесконечно."""

from __future__ import annotations

import asyncio

import pytest
from fakeredis import aioredis

from vscommon.models import ObjectRef, ScanJob
from vscommon.queue import Heartbeat, JobQueue
from worker_app.reclaim import StuckJobReclaimer

STREAM = "scan.jobs"
GROUP = "scanners"


@pytest.fixture()
async def redis():
    client = aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture()
async def queue(redis) -> JobQueue:
    q = JobQueue(redis, STREAM, GROUP)
    await q.ensure_group()
    return q


def _job(scan_id: str = "job-1") -> ScanJob:
    return ScanJob(
        scan_id=scan_id,
        sha256="a" * 64,
        source=ObjectRef(bucket="raw", key="a/aaa"),
        size=1024,
    )


async def _deliver_to(queue: JobQueue, consumer: str) -> str:
    """Имитирует «воркер взял задачу и не подтвердил её»."""
    batches = await queue._redis.xreadgroup(GROUP, consumer, {STREAM: ">"}, count=1)
    return batches[0][1][0][0]


def _reclaimer(queue, heartbeat, *, min_idle_s=0.0, max_deliveries=3) -> StuckJobReclaimer:
    return StuckJobReclaimer(
        queue=queue,
        heartbeat=heartbeat,
        consumer="worker-2",
        min_idle_s=min_idle_s,
        max_deliveries=max_deliveries,
    )


async def test_pending_exposes_idle_and_delivery_count(queue) -> None:
    await queue.publish(_job())
    await _deliver_to(queue, "worker-1")

    pending = await queue.pending()

    assert len(pending) == 1
    assert pending[0].consumer == "worker-1"
    assert pending[0].delivered == 1


async def test_reclaims_job_of_dead_worker(queue, redis) -> None:
    """Воркер взял задачу и умер: heartbeat пропал, задачу подхватывает другой."""
    await queue.publish(_job("upload-42"))
    await _deliver_to(queue, "worker-1")
    # heartbeat не ставим — это и есть «воркер мёртв»

    sweep = await _reclaimer(queue, Heartbeat(redis)).sweep()

    assert len(sweep.reclaimed) == 1
    assert sweep.reclaimed[0].job.scan_id == "upload-42"
    assert sweep.abandoned == []


async def test_does_not_steal_from_live_worker(queue, redis) -> None:
    """Пока heartbeat жив, задачу отбирать нельзя — иначе двойная обработка."""
    heartbeat = Heartbeat(redis)
    await queue.publish(_job())
    entry_id = await _deliver_to(queue, "worker-1")
    await heartbeat.beat(entry_id, "worker-1")

    sweep = await _reclaimer(queue, heartbeat).sweep()

    assert not sweep


async def test_ignores_recently_delivered(queue, redis) -> None:
    """Только что выданная задача пропускается: первый heartbeat мог не успеть."""
    await queue.publish(_job())
    await _deliver_to(queue, "worker-1")

    sweep = await _reclaimer(queue, Heartbeat(redis), min_idle_s=60).sweep()

    assert not sweep


async def test_abandons_after_max_deliveries(queue, redis) -> None:
    """Задача, пережившая лимит доставок, закрывается, а не перевыдаётся вечно."""
    heartbeat = Heartbeat(redis)
    await queue.publish(_job("poison"))
    await _deliver_to(queue, "worker-1")
    reclaimer = _reclaimer(queue, heartbeat, max_deliveries=1)

    first = await reclaimer.sweep()  # delivered 1 -> подхват, delivered станет 2
    second = await reclaimer.sweep()  # delivered 2 > 1 -> брошена

    assert len(first.reclaimed) == 1
    assert len(second.abandoned) == 1
    assert second.abandoned[0].job.scan_id == "poison"
    assert second.reclaimed == []


async def test_abandoned_job_still_carries_payload(queue, redis) -> None:
    """Без полезной нагрузки нельзя построить запись dead-letter и коллбэк."""
    job = _job("with-callback")
    job.callback_url = "https://bot.example/hook"
    await queue.publish(job)
    await _deliver_to(queue, "worker-1")
    reclaimer = _reclaimer(queue, Heartbeat(redis), max_deliveries=0)

    sweep = await reclaimer.sweep()

    assert len(sweep.abandoned) == 1
    assert sweep.abandoned[0].job.callback_url == "https://bot.example/hook"
    assert sweep.abandoned[0].delivered >= 1  # число доставок нужно для dead-letter


async def test_claim_is_race_safe_between_reclaimers(queue, redis) -> None:
    """XCLAIM сбрасывает idle, поэтому второй reclaimer не заберёт то же сообщение."""
    await queue.publish(_job())
    entry_id = await _deliver_to(queue, "worker-1")
    await asyncio.sleep(0.05)

    first = await queue.claim("worker-2", [entry_id], min_idle_ms=20)
    second = await queue.claim("worker-3", [entry_id], min_idle_ms=20)

    assert len(first) == 1
    assert second == []


async def test_unparseable_message_is_acked_not_retried(queue, redis) -> None:
    """Битое сообщение не должно крутиться в pending вечно."""
    await queue._redis.xadd(STREAM, {"job": "{не json"})
    entry_id = await _deliver_to(queue, "worker-1")

    claimed = await queue.claim("worker-2", [entry_id], min_idle_ms=0)

    assert claimed == []
    assert await queue.pending() == []


async def test_heartbeat_keep_clears_after_completion(redis) -> None:
    heartbeat = Heartbeat(redis, ttl_s=30)

    async with heartbeat.keep("entry-1", "worker-1"):
        assert await heartbeat.alive("entry-1")

    assert not await heartbeat.alive("entry-1")


async def test_consumer_group_is_recreated_after_loss(queue, redis) -> None:
    """Redis у нас без сохранения на диск: его перезапуск сносит поток.

    Без восстановления группы воркеры остаются сломанными до рестарта —
    на сервере это означало бы тихую остановку обработки после перезагрузки.
    """
    await queue.publish(_job())
    await redis.flushdb()

    consumer = queue.consume("worker-1", block_ms=10)
    await queue.publish(_job("после-сброса"))
    entry_id, job = await anext(consumer)

    assert job.scan_id == "после-сброса"
    assert entry_id
