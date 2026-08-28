"""M1.4: непроверенный файл не исчезает бесследно, а ждёт человека."""

from __future__ import annotations

import pytest
from fakeredis import aioredis

from vscommon.models import (
    DeadLetter,
    DeadLetterReason,
    ObjectRef,
    ScanResult,
    ScanStatus,
    Verdict,
)
from vscommon.queue import DeadLetterQueue, ResultChannel

STREAM = "scan.dlq"


@pytest.fixture()
async def redis():
    client = aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture()
async def dlq(redis) -> DeadLetterQueue:
    return DeadLetterQueue(redis, STREAM, maxlen=100)


def _entry(scan_id: str = "scan-1", reason=DeadLetterReason.PARSER_CRASH) -> DeadLetter:
    return DeadLetter(
        scan_id=scan_id,
        sha256="b" * 64,
        reason=reason,
        verdict=Verdict.SUSPICIOUS,
        detail="процесс оборвался на стадии structure",
        stage="structure",
        delivered=1,
        tenant="team-a",
        source=ObjectRef(bucket="quarantine", key="b/bbb"),
    )


async def test_entry_carries_everything_needed_for_review(dlq) -> None:
    """Критерий приёмки: в записи есть scan_id, причина и sha256."""
    await dlq.publish(_entry("upload-77"))

    (found,) = await dlq.recent()

    assert found.scan_id == "upload-77"
    assert found.sha256 == "b" * 64
    assert found.reason is DeadLetterReason.PARSER_CRASH
    assert found.stage == "structure"
    assert found.source.key == "b/bbb"


async def test_no_file_content_in_entry(dlq) -> None:
    """В dead-letter только ссылка на карантин — содержимого там быть не должно."""
    await dlq.publish(_entry())

    (found,) = await dlq.recent()

    assert not hasattr(found, "content")
    assert set(found.model_dump()) == {
        "scan_id",
        "sha256",
        "reason",
        "verdict",
        "detail",
        "stage",
        "delivered",
        "tenant",
        "source",
        "created_at",
    }


async def test_newest_first(dlq) -> None:
    for i in range(3):
        await dlq.publish(_entry(f"scan-{i}"))

    entries = await dlq.recent()

    assert [e.scan_id for e in entries] == ["scan-2", "scan-1", "scan-0"]


async def test_stream_is_bounded(redis) -> None:
    """Всплеск отказов не должен съесть память Redis."""
    small = DeadLetterQueue(redis, "bounded.dlq", maxlen=5)

    for i in range(50):
        await small.publish(_entry(f"scan-{i}"))

    assert await small.size() <= 20  # XADD MAXLEN ~ приблизительный


async def test_corrupted_row_does_not_break_listing(dlq, redis) -> None:
    await dlq.publish(_entry("ok"))
    await redis.xadd(STREAM, {"entry": "{не json"})

    entries = await dlq.recent()

    assert [e.scan_id for e in entries] == ["ok"]


async def test_all_reasons_are_representable(dlq) -> None:
    for reason in DeadLetterReason:
        await dlq.publish(_entry(f"scan-{reason.value}", reason=reason))

    assert len(await dlq.recent()) == len(DeadLetterReason)


# --- статус для клиента ---


async def test_manual_review_status_outlives_normal_ttl(redis) -> None:
    """Голый 404 неотличим от «всё хорошо», поэтому статус живёт неделю."""
    channel = ResultChannel(redis)
    result = ScanResult(
        scan_id="scan-1",
        sha256="c" * 64,
        status=ScanStatus.MANUAL_REVIEW,
        verdict=Verdict.SUSPICIOUS,
    )

    await channel.store_status(result, ttl_s=7 * 24 * 3600)

    ttl = await redis.ttl("status:scan-1")
    assert ttl > 24 * 3600
    loaded = await channel.load_status("scan-1")
    assert loaded is not None
    assert loaded.status is ScanStatus.MANUAL_REVIEW


def test_manual_review_is_never_clean() -> None:
    """Задача из dead-letter не проверена — вердикт clean для неё невозможен."""
    result = ScanResult(
        scan_id="s",
        sha256="c" * 64,
        status=ScanStatus.MANUAL_REVIEW,
        verdict=Verdict.SUSPICIOUS,
    )

    assert result.status is not ScanStatus.DONE
    assert result.verdict is not Verdict.CLEAN
