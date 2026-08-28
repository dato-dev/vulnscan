"""M2.6: превышение даёт 429, а не деградацию латентности для остальных."""

from __future__ import annotations

import asyncio
import time

import pytest
from fakeredis import aioredis

from vscommon import ratelimit as ratelimit_module
from vscommon.limits import MAX_UPLOAD_BYTES
from vscommon.models import TenantPolicy
from vscommon.policy import upload_limit_for
from vscommon.ratelimit import WINDOW_S, ConcurrencyLimiter, RateLimiter


@pytest.fixture()
async def redis():
    client = aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


# --- частота запросов ---


async def test_requests_under_limit_pass(redis) -> None:
    limiter = RateLimiter(redis)

    for _ in range(10):
        assert (await limiter.check("team-a", 10)).allowed


async def test_excess_is_rejected(redis) -> None:
    limiter = RateLimiter(redis)
    for _ in range(5):
        await limiter.check("team-a", 5)

    decision = await limiter.check("team-a", 5)

    assert not decision.allowed
    assert decision.retry_after_s > 0


async def test_tenants_do_not_share_budget(redis) -> None:
    """Флудящий тенант не должен закрывать доступ соседям."""
    limiter = RateLimiter(redis)
    for _ in range(20):
        await limiter.check("шумный", 3)

    assert not (await limiter.check("шумный", 3)).allowed
    assert (await limiter.check("тихий", 3)).allowed


async def test_zero_means_unlimited(redis) -> None:
    limiter = RateLimiter(redis)

    for _ in range(200):
        assert (await limiter.check("team-a", 0)).allowed


async def test_rejected_request_still_consumes_budget(redis) -> None:
    """Иначе клиент, долбящийся в стену, обходил бы лимит повторами."""
    limiter = RateLimiter(redis)
    for _ in range(3):
        await limiter.check("team-a", 2)

    decision = await limiter.check("team-a", 2)

    assert not decision.allowed
    assert decision.observed > 2


async def test_retry_after_within_window(redis) -> None:
    limiter = RateLimiter(redis)
    for _ in range(3):
        await limiter.check("team-a", 1)

    decision = await limiter.check("team-a", 1)

    assert 1 <= decision.retry_after_s <= WINDOW_S


@pytest.mark.parametrize(
    ("elapsed_fraction", "expected_allowed"),
    [(0.0, False), (0.5, False), (0.99, True)],
)
async def test_previous_window_decays(
    redis, monkeypatch: pytest.MonkeyPatch, elapsed_fraction: float, expected_allowed: bool
) -> None:
    """Предыдущее окно учитывается тем меньше, чем дальше мы от него ушли.

    Это и отличает скользящее окно от фиксированного: на стыке не возникает
    двойного лимита, но и старая нагрузка не давит вечно.
    """
    frozen = 1_000_000 * WINDOW_S + elapsed_fraction * WINDOW_S
    monkeypatch.setattr(ratelimit_module.time, "time", lambda: frozen)
    bucket = int(frozen // WINDOW_S)
    await redis.set(RateLimiter._key("team-a", bucket - 1), 100)

    decision = await RateLimiter(redis).check("team-a", 50)

    assert decision.allowed is expected_allowed


# --- параллелизм: он и защищает соседей ---


async def test_slots_are_limited(redis) -> None:
    limiter = ConcurrencyLimiter(redis)

    granted = [await limiter.acquire("team-a", f"scan-{i}", 3) for i in range(5)]

    assert granted == [True, True, True, False, False]
    assert await limiter.current("team-a") == 3


async def test_release_frees_slot(redis) -> None:
    limiter = ConcurrencyLimiter(redis)
    for i in range(3):
        await limiter.acquire("team-a", f"scan-{i}", 3)
    assert not await limiter.acquire("team-a", "scan-x", 3)

    await limiter.release("team-a", "scan-0")

    assert await limiter.acquire("team-a", "scan-x", 3)


async def test_concurrent_acquire_does_not_overshoot(redis) -> None:
    """Без Lua: ранг после вставки задаёт полный порядок даже при гонке."""
    limiter = ConcurrencyLimiter(redis)

    granted = await asyncio.gather(*(limiter.acquire("team-a", f"scan-{i}", 4) for i in range(20)))

    assert sum(granted) == 4
    assert await limiter.current("team-a") == 4


async def test_one_tenant_cannot_squeeze_out_another(redis) -> None:
    """Главный смысл лимита: доля очереди одного клиента ограничена."""
    limiter = ConcurrencyLimiter(redis)
    for i in range(50):
        await limiter.acquire("шумный", f"scan-{i}", 2)

    assert await limiter.current("шумный") == 2
    assert await limiter.acquire("тихий", "scan-a", 2)


async def test_stale_slot_expires(redis) -> None:
    """Воркер умер, не сняв задачу — слот не должен протечь навсегда."""
    limiter = ConcurrencyLimiter(redis, stale_after_s=1)
    await limiter.acquire("team-a", "zombie", 1)
    await redis.zadd(ConcurrencyLimiter._key("team-a"), {"zombie": time.time() - 3600})

    assert await limiter.acquire("team-a", "fresh", 1)


async def test_zero_concurrency_means_unlimited(redis) -> None:
    limiter = ConcurrencyLimiter(redis)

    for i in range(100):
        assert await limiter.acquire("team-a", f"scan-{i}", 0)


# --- политика ---


def test_defaults_are_generous_but_bounded() -> None:
    """Ненастроенный тенант не должен иметь возможности залить очередь."""
    policy = TenantPolicy()

    assert policy.rate_limit_per_min > 0
    assert policy.max_concurrent_scans > 0


def test_tenant_size_limit_cannot_exceed_global() -> None:
    huge = TenantPolicy(max_upload_bytes=MAX_UPLOAD_BYTES * 10)
    small = TenantPolicy(max_upload_bytes=1024)

    assert upload_limit_for(huge) == MAX_UPLOAD_BYTES
    assert upload_limit_for(small) == 1024
    assert upload_limit_for(TenantPolicy()) == MAX_UPLOAD_BYTES
