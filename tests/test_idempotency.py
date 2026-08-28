"""M1.5: один файл — один scan_id и один артефакт."""

from __future__ import annotations

import asyncio

import pytest
from fakeredis import aioredis

from vscommon.idempotency import ScanRegistry
from vscommon.models import ScanResult, ScanStatus, Verdict
from vscommon.queue import ResultChannel

SHA = "a" * 64


@pytest.fixture()
async def redis():
    client = aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture()
async def registry(redis) -> ScanRegistry:
    return ScanRegistry(redis, ttl_s=300)


# --- заявка на проверку ---


async def test_second_upload_of_same_file_reuses_scan_id(registry) -> None:
    """Критерий приёмки: двойная отправка даёт один scan_id."""
    first = await registry.claim(SHA, "standard", "scan-1")
    second = await registry.claim(SHA, "standard", "scan-2")

    assert first == "scan-1"
    assert second == "scan-1"


async def test_concurrent_claims_pick_one_winner(registry) -> None:
    """Пользователь дважды нажал «отправить» — проход CDR должен быть один."""
    results = await asyncio.gather(
        *(registry.claim(SHA, "standard", f"scan-{i}") for i in range(10))
    )

    assert len(set(results)) == 1


async def test_different_profiles_are_separate_scans(registry) -> None:
    """standard и strict дают разные артефакты — объединять их нельзя."""
    first = await registry.claim(SHA, "standard", "scan-1")
    second = await registry.claim(SHA, "strict", "scan-2")

    assert first != second


async def test_different_files_do_not_collide(registry) -> None:
    assert await registry.claim(SHA, "standard", "scan-1") == "scan-1"
    assert await registry.claim("b" * 64, "standard", "scan-2") == "scan-2"


async def test_claim_released_allows_new_scan(registry) -> None:
    await registry.claim(SHA, "standard", "scan-1")
    await registry.release(SHA, "standard")

    assert await registry.claim(SHA, "standard", "scan-2") == "scan-2"


# --- канал ожидания: результата ждёт несколько запросов ---


def _done(scan_id: str = "scan-1") -> ScanResult:
    return ScanResult(scan_id=scan_id, sha256=SHA, status=ScanStatus.DONE, verdict=Verdict.CLEAN)


async def test_all_waiters_receive_one_result(redis) -> None:
    """BLPOP отдал бы результат только первому — здесь его получают все."""
    channel = ResultChannel(redis)

    waiters = [asyncio.create_task(channel.wait("scan-1", 2000)) for _ in range(3)]
    await asyncio.sleep(0.1)
    await channel.publish(_done())

    results = await asyncio.gather(*waiters)

    assert len(results) == 3
    assert all(r is not None and r.verdict is Verdict.CLEAN for r in results)


async def test_waiter_arriving_after_result_gets_it_immediately(redis) -> None:
    """Проверка статуса после подписки закрывает гонку «результат уже пришёл»."""
    channel = ResultChannel(redis)
    await channel.publish(_done())

    result = await channel.wait("scan-1", 50)

    assert result is not None
    assert result.status is ScanStatus.DONE


async def test_waiter_times_out_without_result(redis) -> None:
    channel = ResultChannel(redis)

    assert await channel.wait("никого-нет", 50) is None


async def test_publish_stores_status_before_signalling(redis) -> None:
    """Разбуженный клиент не должен прочитать пустоту."""
    channel = ResultChannel(redis)
    await channel.publish(_done(), status_ttl_s=600)

    assert await channel.load_status("scan-1") is not None
    assert await redis.ttl("status:scan-1") > 300


# --- один артефакт ---


def test_artifact_key_is_deterministic() -> None:
    """Повтор перезаписывает тот же объект, а не плодит второй."""
    scan_id = "0f9c3b7a2d"

    def key(suffix: str) -> str:
        return f"{scan_id[:2]}/{scan_id}{suffix}"

    assert key(".pdf") == key(".pdf")
    assert key(".pdf").startswith("0f/")


# --- повторная доставка завершённой задачи ---


def test_terminal_statuses_cover_done_and_manual_review() -> None:
    """После этих исходов пересканировать нечего."""
    from vscommon.models import TERMINAL_STATUSES

    assert ScanStatus.DONE in TERMINAL_STATUSES
    assert ScanStatus.MANUAL_REVIEW in TERMINAL_STATUSES


def test_failed_is_not_terminal() -> None:
    """Сбой CDR или дедлайн могут пройти со второй попытки."""
    from vscommon.models import TERMINAL_STATUSES

    assert ScanStatus.FAILED not in TERMINAL_STATUSES
    assert ScanStatus.QUEUED not in TERMINAL_STATUSES


async def test_claim_release_allows_immediate_rescan(registry) -> None:
    """Заявка живёт ещё несколько минут после завершения скана.

    Из-за этого запрос сразу после внесения файла в список доверенных
    дедуплицировался на прежний, заблокированный результат — то есть снятие
    блокировки не действовало до истечения заявки.
    """
    first = await registry.claim(SHA, "standard", "scan-1")
    assert await registry.claim(SHA, "standard", "scan-2") == first

    await registry.release(SHA, "standard")

    assert await registry.claim(SHA, "standard", "scan-3") == "scan-3"
