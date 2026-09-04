"""M12.6: вердикт становится доказательством только на бэкенде сайта.

Браузер посетителя целиком под его контролем. Он отправит форму с любым
`scan_id` и любым «чисто», и никакая проверка на нашей стороне этого не
изменит — мы не знаем, что именно страница сказала своему серверу.

Единственное место, где вердикт превращается в доказательство, — запрос от
бэкенда сайта его секретным ключом. Здесь проверяется, что этот запрос
действительно возможен и что он ограничен так, как заявлено: свой тенант видит
свой скан, чужой не видит ничего, а публичный ключ не читает результаты вовсе.
"""

from __future__ import annotations

import pytest
from fakeredis import aioredis

from vscommon.keys import AccessKey, KeyRegistry
from vscommon.ownership import Ownership
from vscommon.signing import sign
from vscommon.tickets import TicketStore

SCAN_ID = "2f6a1b7c9d0e4f5a8b3c2d1e0f9a8b7c"


def _keys() -> KeyRegistry:
    """Три ключа: сайта, его бэкенда и совсем чужой."""
    return KeyRegistry(
        {
            "acme-public": AccessKey(
                key_id="acme-public",
                tenant="acme",
                secret="p" * 32,
                public=True,
                origins=("https://acme.tld",),
            ),
            "acme-backend": AccessKey(key_id="acme-backend", tenant="acme", secret="s" * 32),
            "other-backend": AccessKey(key_id="other-backend", tenant="other", secret="o" * 32),
        }
    )


@pytest.fixture()
def redis() -> aioredis.FakeRedis:
    """Как в проде: `create_redis` создаёт клиент с `decode_responses=True`.

    Без этого `Ownership.owner` получил бы байты и сравнил бы `"b'acme'"` с
    `"acme"` — первая версия теста падала именно так. Двойник, настроенный
    иначе, чем боевой клиент, проверяет не то поведение, которое поедет.
    """
    return aioredis.FakeRedis(decode_responses=True)


async def _scan_uploaded_by_widget(redis: aioredis.FakeRedis) -> Ownership:
    """Воспроизводит то, что делает приём файла по талону.

    Тенант берётся из ключа, которым выдан талон, и им же помечается владелец
    скана. Дальше вся проверка доступа опирается только на это.
    """
    tickets = TicketStore(redis)
    ticket, _ = await tickets.issue("acme", "acme-public", max_bytes=4096)
    redeemed = await tickets.redeem(ticket.token)
    assert redeemed is not None

    ownership = Ownership(redis, ttl_s=3600)
    await ownership.claim(SCAN_ID, redeemed.tenant)
    return ownership


@pytest.mark.asyncio
async def test_site_backend_can_verify_widget_upload(redis: aioredis.FakeRedis) -> None:
    """Бэкенд сайта видит скан, загруженный через его виджет.

    Это опора всей схемы: без неё обязательная проверка была бы невыполнима, и
    сайту осталось бы верить браузеру.
    """
    ownership = await _scan_uploaded_by_widget(redis)

    assert await ownership.allows(SCAN_ID, "acme") is True


@pytest.mark.asyncio
async def test_foreign_tenant_sees_nothing(redis: aioredis.FakeRedis) -> None:
    """Чужой тенант не видит скан — и не отличит его от несуществующего.

    Ответ `404`, а не `403`: `403` подтвердил бы, что такой скан есть, и
    превратил бы ручку в способ проверять чужие идентификаторы.
    """
    ownership = await _scan_uploaded_by_widget(redis)

    assert await ownership.allows(SCAN_ID, "other") is False


@pytest.mark.asyncio
async def test_public_key_cannot_read_results(redis: aioredis.FakeRedis) -> None:
    """Публичным ключом результат не прочитать.

    Чтение требует подписи, а подписать публичным ключом нельзя: его секрет
    знает каждый посетитель. Если бы это работало, посетитель читал бы вердикты
    по чужим идентификаторам — то есть узнавал бы, что присылали другие.

    Проверяется на ПРАВИЛЬНО посчитанной подписи: отказ должен наступать
    из-за типа ключа, а не из-за неверных байтов.
    """
    from vscommon.signing import canonical_request

    registry = _keys()
    payload = canonical_request("GET", f"/v1/scan/{SCAN_ID}", "acme-public")
    timestamp, signature = sign("p" * 32, payload)

    key, _check = registry.check("acme-public", payload, timestamp, signature)

    assert key is None


@pytest.mark.asyncio
async def test_backend_key_signature_works(redis: aioredis.FakeRedis) -> None:
    """А секретным ключом того же тенанта — работает.

    Без этой половины предыдущий тест доказывал бы только то, что подпись
    вообще не проходит.
    """
    from vscommon.signing import canonical_request

    registry = _keys()
    payload = canonical_request("GET", f"/v1/scan/{SCAN_ID}", "acme-backend")
    timestamp, signature = sign("s" * 32, payload)

    key, _check = registry.check("acme-backend", payload, timestamp, signature)

    assert key is not None
    assert key.tenant == "acme"


@pytest.mark.asyncio
async def test_unknown_owner_is_refused(redis: aioredis.FakeRedis) -> None:
    """Скан без записи о владельце не отдаётся никому.

    Записи истекают вместе с результатом. Если владелец потерялся раньше
    результата, отдавать документ наугад нельзя — «не знаем чей» не может
    означать «отдать спросившему».
    """
    ownership = Ownership(redis, ttl_s=3600)

    assert await ownership.allows("нет-такого-скана", "acme") is False


def test_scan_routes_check_ownership() -> None:
    """Владение проверяется везде, где отдаются данные конкретного скана.

    Таких ручек две: результат и обезвреженная копия. Пропуск на любой из них
    — это доступ к чужому файлу, и по поведению он не виден: свои сканы
    продолжают работать как ни в чём не бывало.

    `/lookup/{sha256}` сюда не входит и не должен: он принимает хэш, а не
    идентификатор скана, и отдаёт не чужой результат, а признаки из кэша,
    пересчитанные под политику спрашивающего. Кэш у нас общий намеренно —
    хранятся факты, вердикт считается на чтении.
    """
    from pathlib import Path

    source = (
        Path(__file__).parent.parent / "services/gateway/gateway_app/routes/scan.py"
    ).read_text()

    # Определение плюс два вызова.
    assert source.count("_require_owner(") == 3, (
        "проверка владения пропала с одной из ручек или появилась лишняя"
    )


def test_ticket_flow_never_exposes_the_secret() -> None:
    """Секретный ключ не участвует в браузерной части потока.

    Талон выдаётся публичным ключом, загрузка идёт талоном. Секрет нужен
    только бэкенду сайта — на шаге проверки. Если бы он требовался раньше,
    его пришлось бы отдать в браузер, и вся схема потеряла бы смысл.
    """

    from gateway_app.cors import CORS_PATHS

    # Из браузера доступны ровно две ручки, и обе не требуют секрета.
    # Сравниваем со списком в коде, а не ищем строки в файле: первая версия
    # искала «/v1/scan/» в тексте и находила его в комментарии — то есть
    # проверяла прозу.
    assert {"/v1/tickets", "/v1/scan"} == CORS_PATHS


@pytest.mark.asyncio
async def test_same_file_from_two_visitors_shares_the_scan(redis: aioredis.FakeRedis) -> None:
    """Один и тот же файл от разных посетителей — одна проверка.

    Следствие идемпотентности по sha256, и его надо знать бэкенду сайта:
    `scan_id` не является идентификатором отправки формы. Двое приложили один
    документ — получат один идентификатор.

    Практический вывод для интегратора: связывать `scan_id` с конкретной
    отправкой нужно у себя, а не полагаться на его уникальность.
    """
    ownership = Ownership(redis, ttl_s=3600)
    await ownership.claim(SCAN_ID, "acme")
    await ownership.claim(SCAN_ID, "acme")

    assert await ownership.allows(SCAN_ID, "acme") is True
