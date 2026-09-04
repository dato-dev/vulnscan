"""M12.5: суточная квота на публичный ключ.

Ограничение частоты и квота защищают разное, и это главное, что здесь
проверяется. Частота отвечает на вопрос «сколько запросов в секунду мы
выдержим», квота — «сколько это будет стоить владельцу ключа за сутки».

Поток внутри лимита частоты выглядит совершенно штатным: шестьдесят запросов в
минуту — это восемьдесят шесть тысяч файлов в день. Публичный ключ видит
каждый, кто открыл исходный код страницы.
"""

from __future__ import annotations

import pytest
from fakeredis import aioredis

from vscommon.quota import DailyQuota


@pytest.fixture()
def quota() -> DailyQuota:
    return DailyQuota(aioredis.FakeRedis())


@pytest.mark.asyncio
async def test_spending_within_limit_is_allowed(quota: DailyQuota) -> None:
    """Пока не исчерпано — пропускаем."""
    for _ in range(5):
        assert await quota.spend("acme-public", limit=5) is True


@pytest.mark.asyncio
async def test_limit_is_enforced(quota: DailyQuota) -> None:
    """Превышение отклоняется, и дальше тоже."""
    for _ in range(3):
        await quota.spend("acme-public", limit=3)

    assert await quota.spend("acme-public", limit=3) is False
    assert await quota.spend("acme-public", limit=3) is False


@pytest.mark.asyncio
async def test_refused_attempt_still_counts(quota: DailyQuota) -> None:
    """Отказанная попытка тоже расходует счёт, и это осознанно.

    Откат означал бы «прочитать, сравнить, записать» — то есть гонку, в
    которой два параллельных запроса пробивают лимит. Отказ обходится нам
    почти так же, как успех, поэтому дешевле считать его, чем открывать окно
    для обхода.
    """
    await quota.spend("acme-public", limit=1)
    assert await quota.spend("acme-public", limit=1) is False

    assert await quota.spent("acme-public") == 2


@pytest.mark.asyncio
async def test_subjects_are_counted_separately(quota: DailyQuota) -> None:
    """Ключи считаются по отдельности.

    Иначе один сайт исчерпывал бы квоту другого, и владелец ключа отвечал бы
    за чужой трафик.
    """
    await quota.spend("acme-public", limit=1)

    assert await quota.spend("другой-ключ", limit=1) is True


@pytest.mark.asyncio
async def test_zero_means_unlimited(quota: DailyQuota) -> None:
    """Ноль — «без счёта», как и у остальных лимитов тенанта.

    Единообразие важнее выразительности: если бы ноль здесь означал «ничего
    нельзя», настройка вела бы себя противоположно соседним полям, и однажды
    кто-то выключил бы квоту, а выключил бы сервис.
    """
    for _ in range(100):
        assert await quota.spend("acme-public", limit=0) is True


@pytest.mark.asyncio
async def test_counter_is_per_day() -> None:
    """Счётчик привязан к календарным суткам UTC.

    Новые сутки начинаются с чистого счётчика сами собой — обнулять нечего.
    Проверяется через ключ, а не переводом часов: подменять время ради этого
    значит проверять подмену, а не поведение.
    """
    redis = aioredis.FakeRedis()
    quota = DailyQuota(redis)

    await quota.spend("acme-public", limit=10)
    keys = [k.decode() if isinstance(k, bytes) else k for k in await redis.keys("quota:*")]

    assert len(keys) == 1
    # quota:ГГГГ-ММ-ДД:ключ
    prefix, day, subject = keys[0].split(":")
    assert prefix == "quota"
    assert len(day) == len("2026-01-01")
    assert subject == "acme-public"


@pytest.mark.asyncio
async def test_ttl_is_set_once() -> None:
    """Срок жизни ставится при первом расходе, а не при каждом.

    Продлевать его на каждом запросе — значит никогда не дождаться истечения:
    у активного ключа записи копились бы вечно.
    """
    redis = aioredis.FakeRedis()
    quota = DailyQuota(redis)

    await quota.spend("acme-public", limit=10)
    key = (await redis.keys("quota:*"))[0]
    first = await redis.ttl(key)

    await redis.expire(key, 100)  # как будто время прошло
    await quota.spend("acme-public", limit=10)

    assert first > 0
    assert await redis.ttl(key) <= 100, "TTL продлился на втором расходе"


@pytest.mark.asyncio
async def test_broken_redis_does_not_block_scanning() -> None:
    """Недоступный счётчик не отказывает в проверке файла.

    Квота — вспомогательный механизм. Превратив её в единственную точку
    отказа, мы бы поменяли «перерасход у одного тенанта» на «сервис не
    принимает файлы» — обмен явно не в нашу пользу.
    """

    class _Broken:
        async def incrby(self, key: str, amount: int) -> int:
            raise ConnectionError("redis недоступен")

    assert await DailyQuota(_Broken()).spend("acme-public", limit=1) is True
