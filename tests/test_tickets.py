"""M12.1: одноразовый талон на загрузку.

Талон существует затем, чтобы браузер мог загрузить файл, не имея секрета
тенанта. Всё, что здесь проверяется, — про одно: талон не должен превратиться в
ключ. Одна загрузка, короткий срок, заявленный размер, свой тенант, и ничего
сверх этого.
"""

from __future__ import annotations

import asyncio

import pytest
from fakeredis import aioredis

from vscommon.tickets import MAX_TTL_S, TicketStore


@pytest.fixture()
def redis() -> aioredis.FakeRedis:
    return aioredis.FakeRedis()


@pytest.mark.asyncio
async def test_issued_ticket_is_redeemable(redis: aioredis.FakeRedis) -> None:
    """Выданный талон гасится и отдаёт то, что в него положили."""
    store = TicketStore(redis)

    ticket, ttl = await store.issue("acme", "acme-site", max_bytes=1024, origin="https://acme.tld")

    assert ttl > 0
    redeemed = await store.redeem(ticket.token)

    assert redeemed is not None
    assert redeemed.tenant == "acme"
    assert redeemed.key_id == "acme-site"
    assert redeemed.max_bytes == 1024
    assert redeemed.origin == "https://acme.tld"


@pytest.mark.asyncio
async def test_ticket_is_single_use(redis: aioredis.FakeRedis) -> None:
    """Второе гашение не проходит.

    Иначе талон, подсмотренный в браузере, становится ключом на срок своей
    жизни: грузить по нему можно сколько угодно.
    """
    store = TicketStore(redis)
    ticket, _ = await store.issue("acme", "acme-site", max_bytes=1024)

    assert await store.redeem(ticket.token) is not None
    assert await store.redeem(ticket.token) is None


class _InterleavingRedis:
    """Redis, который гарантированно даёт другим корутинам вклиниться.

    `fakeredis` этого не даёт: его операции завершаются без реальной уступки
    управления, и гонка на нём не воспроизводится. Первая версия теста ниже
    проходила и с наивной реализацией «прочитать, потом удалить» — то есть
    проверяла ровно ничего.

    Здесь `get` и `delete` уступают управление явно, а `getdel` — нет: он
    атомарен, как и настоящий. На таком двойнике наивная реализация падает, а
    правильная проходит.
    """

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.data[key] = value

    async def get(self, key: str) -> str | None:
        await asyncio.sleep(0)  # окно, в которое влезает второй запрос
        return self.data.get(key)

    async def delete(self, key: str) -> None:
        await asyncio.sleep(0)
        self.data.pop(key, None)

    async def getdel(self, key: str) -> str | None:
        # Без единой точки ожидания: в этом весь смысл операции.
        return self.data.pop(key, None)


@pytest.mark.asyncio
async def test_concurrent_redeem_gives_exactly_one_winner() -> None:
    """Две параллельные загрузки одним талоном дают одну успешную.

    Проверка не теоретическая: пара «прочитать, потом удалить» пропускает оба
    запроса, если второй успел встать между чтением и удалением. Поэтому
    гашение сделано через `GETDEL`.

    Двойник вместо `fakeredis` — намеренно, см. `_InterleavingRedis`.
    """
    store = TicketStore(_InterleavingRedis())
    ticket, _ = await store.issue("acme", "acme-site", max_bytes=1024)

    results = await asyncio.gather(*(store.redeem(ticket.token) for _ in range(8)))
    winners = [r for r in results if r is not None]

    assert len(winners) == 1, f"талон погасился {len(winners)} раз вместо одного"


@pytest.mark.asyncio
async def test_expired_ticket_is_rejected(redis: aioredis.FakeRedis) -> None:
    """Истёкший талон недействителен.

    Срок жизни короткий намеренно: талон уезжает в браузер, а всё, что уехало в
    браузер, следует считать известным посторонним.
    """
    store = TicketStore(redis, ttl_s=1)
    ticket, _ = await store.issue("acme", "acme-site", max_bytes=1024)

    await redis.delete(f"ticket:{ticket.token}")  # то же, что сделал бы TTL

    assert await store.redeem(ticket.token) is None


@pytest.mark.asyncio
async def test_unknown_and_empty_tokens_are_rejected(redis: aioredis.FakeRedis) -> None:
    """Выдуманный талон не проходит, пустая строка тоже.

    Пустой токен отдельно: `""` в качестве ключа Redis — валидный ключ, и без
    явной проверки нашлась бы запись, если её кто-то создал.
    """
    store = TicketStore(redis)

    assert await store.redeem("") is None
    assert await store.redeem("нет-такого") is None


@pytest.mark.asyncio
async def test_corrupted_record_is_rejected(redis: aioredis.FakeRedis) -> None:
    """Испорченная запись — отказ, а не загрузка без ограничений.

    Разбор чужих данных обязан заканчиваться отказом в непонятной ситуации:
    «не смогли прочитать» не может означать «разрешено».
    """
    store = TicketStore(redis)
    await redis.set("ticket:битый", "acme\nтолько-два-поля")

    assert await store.redeem("битый") is None

    await redis.set("ticket:нечисло", "acme\nkey\nне-число\n")
    assert await store.redeem("нечисло") is None


@pytest.mark.asyncio
async def test_ttl_is_capped(redis: aioredis.FakeRedis) -> None:
    """Запрошенный срок больше предельного урезается, а не отклоняется.

    Интегратор не должен получать отказ за то, что попросил слишком много: он
    получит меньше, и это ровно то поведение, которое ему нужно объяснить один
    раз в документации.
    """
    store = TicketStore(redis, ttl_s=MAX_TTL_S * 10)

    _, ttl = await store.issue("acme", "acme-site", max_bytes=1024)

    assert ttl == MAX_TTL_S


@pytest.mark.asyncio
async def test_tokens_are_unpredictable(redis: aioredis.FakeRedis) -> None:
    """Талоны не повторяются и не выводятся один из другого."""
    store = TicketStore(redis)

    tokens = {(await store.issue("acme", "acme-site", max_bytes=1))[0].token for _ in range(64)}

    assert len(tokens) == 64
    assert all(len(token) >= 32 for token in tokens)


# --- талон наблюдения (M12.7) --------------------------------------------


@pytest.mark.asyncio
async def test_status_ticket_is_reusable(redis: aioredis.FakeRedis) -> None:
    """Талон наблюдения предъявляется многократно — в этом его смысл.

    Опрос состоит из нескольких запросов подряд; одноразовость сделала бы его
    невозможным. Ограничивает не счётчик, а срок жизни.
    """
    from vscommon.tickets import StatusTicketStore

    store = StatusTicketStore(redis)
    token, ttl = await store.issue("скан-1", "acme")

    assert ttl > 0
    for _ in range(5):
        assert await store.resolve(token) == ("скан-1", "acme")


@pytest.mark.asyncio
async def test_status_ticket_is_bound_to_one_scan(redis: aioredis.FakeRedis) -> None:
    """Талон привязан к одному скану и другого не открывает.

    Иначе он стал бы ключом на чтение вердиктов: предъявитель узнавал бы, что
    присылали другие посетители того же сайта.
    """
    from vscommon.tickets import StatusTicketStore

    store = StatusTicketStore(redis)
    first, _ = await store.issue("скан-1", "acme")
    second, _ = await store.issue("скан-2", "acme")

    assert await store.resolve(first) == ("скан-1", "acme")
    assert await store.resolve(second) == ("скан-2", "acme")


@pytest.mark.asyncio
async def test_unknown_status_ticket_is_rejected(redis: aioredis.FakeRedis) -> None:
    """Выдуманный и пустой талон не проходят."""
    from vscommon.tickets import StatusTicketStore

    store = StatusTicketStore(redis)

    assert await store.resolve("") is None
    assert await store.resolve("нет-такого") is None


@pytest.mark.asyncio
async def test_corrupted_status_record_is_rejected(redis: aioredis.FakeRedis) -> None:
    """Испорченная запись — отказ, а не наблюдение за неизвестно чем."""
    from vscommon.tickets import StatusTicketStore

    store = StatusTicketStore(redis)
    await redis.set("status-ticket:битый", "только-одно-поле")

    assert await store.resolve("битый") is None


@pytest.mark.asyncio
async def test_status_ticket_outlives_the_upload_ticket(redis: aioredis.FakeRedis) -> None:
    """Живёт дольше талона на загрузку, и это намеренно.

    Тот ждёт, пока посетитель выберет файл; этот — пока закончится проверка,
    включая углублённую.
    """
    from vscommon.tickets import DEFAULT_TTL_S, StatusTicketStore

    _token, ttl = await StatusTicketStore(redis).issue("скан-1", "acme")

    assert ttl > DEFAULT_TTL_S
