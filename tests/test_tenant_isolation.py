"""M7.7: аудит на общие данные между тенантами.

Про то, что тенант выводится из ключа, есть `test_multitenancy.py`. Здесь
другой вопрос: **чьи данные лежат под ключом Redis, к которому этот тенант
получил доступ**. Ответ «наши, а разграничение проверяется на чтении»
оказался недостаточным дважды.

Критерий из ROADMAP: на каждый разделяемый ключ либо обоснование общности,
либо тенант в составе ключа. Проверяется не по списку литералов в исходниках,
а по ключам, которые компоненты **создают** в настоящем Redis: разделяемый
ключ, собранный из константы и f-строки, обзор литералов пропустил бы — и
пропустил бы ровно те два модуля, из-за которых эта задача и появилась.
"""

from __future__ import annotations

import inspect
import json
import pathlib
from types import SimpleNamespace

import pytest
from fakeredis import aioredis
from fastapi import HTTPException

from vscommon.allowlist import Allowlist, AllowlistEntry
from vscommon.cache import AvCache, StructuralCache
from vscommon.canary import CanaryLedger
from vscommon.idempotency import ScanRegistry
from vscommon.journal import AttemptJournal
from vscommon.keys import AccessKey
from vscommon.models import (
    CachedAv,
    CachedStructural,
    CallbackTask,
    CdrProfile,
    DeadLetter,
    DeadLetterReason,
    ObjectRef,
    ScanFacts,
    ScanResult,
    ScanStatus,
    Verdict,
)
from vscommon.ownership import Ownership
from vscommon.provisioning import TenantStore
from vscommon.queue import (
    CallbackQueue,
    DeadLetterQueue,
    Heartbeat,
    JobQueue,
    ResultChannel,
    ResultStream,
)
from vscommon.quota import DailyQuota
from vscommon.ratelimit import ConcurrencyLimiter, RateLimiter
from vscommon.rules_control import DisabledRule, RulesControl
from vscommon.shadow import ShadowLedger
from vscommon.tickets import StatusTicketStore, TicketStore

TENANT = "команда-а"
OTHER = "команда-б"
SCAN_ID = "scan-0000000000000001"
SHA = "a" * 64

VSCOMMON = pathlib.Path(__file__).parent.parent / "packages/vscommon"


# --- инвентарь: что общее и почему ---------------------------------------

TENANT_IN_KEY = {
    "allowlist": "разрешение ослабляет проверку и действует на одного клиента",
    "rl": "частота считается по тенанту",
    "inflight:tenant": "параллелизм ограничивается по тенанту",
    "shadow": "учёт теневого режима читается целиком, режим включают по одному",
    "quota": "суточная квота ключа сайта",
}
"""Ключи, в составе которых обязан быть тенант. Значение — зачем он там."""

PER_SCAN = {
    "owner": "владелец скана — сам этот механизм разграничения",
    "attempt": "журнал попыток одного скана",
    "status": "результат одного скана, доступ проверяется через owner",
    "inflight:scan": "идемпотентность по содержимому файла",
}
"""Ключи, привязанные к идентификатору скана или к содержимому файла.

Тенанта в ключе нет намеренно: `scan_id` не угадывается, а доступ к нему
проверяется через `owner:` — то есть через отдельный механизм, у которого есть
свои тесты. Идемпотентность привязана к sha256 по замыслу: повтор того же
файла не должен создавать второй скан.

Имён каналов pub/sub здесь нет: `result:<scan_id>`, по которому gateway ждёт
ответа, ключом не является и в Redis не хранится. Подписка на него ничего не
читает — она ждёт публикации.
"""

SHARED = {
    "scan:struct": (
        "факты о байтах файла, а не вердикт. Вердикт пересчитывается на "
        "чтении под политику тенанта, поэтому общая запись не отдаёт чужой"
    ),
    "scan:av": "вердикт антивируса о байтах файла от тенанта не зависит",
    "ticket": "токен случайный, тенант лежит внутри значения",
    "status-ticket": "то же: токен случайный, привязан к одному scan_id",
    "provision": "административный реестр: ключи и политики всех тенантов",
    "engine": "версии движков — свойство установки, не клиента",
    "callbacks": "внутренняя очередь повторов, наружу не отдаётся",
    "scan.jobs": "поток задач: воркеры разбирают его целиком",
    "scan.dlq": "поток разбора; отбор по тенанту делает ручка, не ключ",
    "results": "поток результатов для писателя истории",
    "inflight": "heartbeat записи потока, живёт по entry_id",
    "canary": (
        "наблюдение за набором-кандидатом: чей это набор, решает установка, "
        "а не клиент. Отчёт по нему административный"
    ),
    "rules": (
        "набор правил — свойство установки, а не клиента. Тенанту нельзя "
        "выключать детект: платит за это не он, а поток соседей"
    ),
}
"""Осознанно общие ключи. Значение — обоснование, а не описание."""


def _classify(key: str) -> tuple[str, str]:
    """Ключ → (раздел инвентаря, пространство имён).

    Порядок перебора от длинного к короткому: `inflight:scan` и
    `inflight:tenant` попадают в разные разделы, и общий префикс `inflight`
    не должен их проглотить.
    """
    for section, table in (("tenant", TENANT_IN_KEY), ("scan", PER_SCAN), ("shared", SHARED)):
        for prefix in sorted(table, key=len, reverse=True):
            if key == prefix or key.startswith(f"{prefix}:"):
                return section, prefix
    return "неизвестно", key.split(":")[0]


# --- что именно создаёт ключи --------------------------------------------


async def _write_everything(redis, tenant: str) -> None:
    """Прогоняет записывающий путь каждого компонента, работающего с Redis.

    Список руками, и это не лень: автоматически найти «все, кто пишет в
    Redis» нельзя, а забытый компонент ловится проверкой ниже — она сверяет
    этот список с модулями, которые Redis импортируют.
    """
    await Allowlist(redis).add(
        AllowlistEntry(sha256=SHA, reason="разобрано вручную", author="дежурный", tenant=tenant)
    )
    await ShadowLedger(redis).record(tenant, "malicious", True, ["PDF_LAUNCH"], SHA)
    await RateLimiter(redis).check(tenant, limit_per_min=10)
    await ConcurrencyLimiter(redis).acquire(tenant, SCAN_ID, limit=4)
    await DailyQuota(redis).spend(f"public:{tenant}", limit=10)
    await Ownership(redis, ttl_s=60).claim(SCAN_ID, tenant)
    await AttemptJournal(redis).begin(SCAN_ID, attempt=1)
    await ScanRegistry(redis).claim(SHA, CdrProfile.STANDARD.value, SCAN_ID)
    await TicketStore(redis).issue(tenant, key_id="k1", max_bytes=1024)
    await StatusTicketStore(redis).issue(SCAN_ID, tenant)
    await TenantStore(redis).put_policy(tenant, {"block_threshold": 50})
    await Heartbeat(redis).beat("1-1", consumer="w1")
    await CanaryLedger(redis).record(SHA, frozenset({"a"}), frozenset({"b"}))
    await RulesControl(redis).disable(
        DisabledRule(rule="pdf_launch_action", reason="массовые ложные", author="дежурный")
    )

    # Версии движков сервисы пишут прямо, без компонента в `vscommon`. Именно
    # поэтому строка здесь: ключ, которого не касается ни один класс, из
    # аудита выпал бы целиком.
    await redis.set("engine:clamav:version", "1")

    result = ScanResult(
        scan_id=SCAN_ID,
        sha256=SHA,
        status=ScanStatus.DONE,
        verdict=Verdict.CLEAN,
    )
    facts = ScanFacts()
    await StructuralCache(redis, ttl_s=60).put(
        CachedStructural(sha256=SHA, profile=CdrProfile.STANDARD, facts=facts, rules_version="r1"),
        weights_key="w1",
    )
    await AvCache(redis, ttl_s=60).put(
        CachedAv(sha256=SHA, av_db_version="1", facts=facts, engines={})
    )

    await ResultChannel(redis).publish(result)
    await DeadLetterQueue(redis, stream="scan.dlq").publish(
        DeadLetter(
            scan_id=SCAN_ID,
            sha256=SHA,
            reason=DeadLetterReason.SCAN_FAILED,
            verdict=Verdict.ERROR,
            tenant=tenant,
            source=ObjectRef(bucket="quarantine", key="a/aaa"),
        )
    )
    await JobQueue(redis, stream="scan.jobs", group="workers").ensure_group()
    await ResultStream(redis, stream="results", group="writer").publish(result)
    await CallbackQueue(redis, stream="callbacks", group="notifier").publish(
        CallbackTask(
            scan_id=SCAN_ID,
            url="https://example.test/hook",
            tenant=tenant,
            payload=result.model_dump_json(),
        )
    )


@pytest.fixture()
async def keys():
    """Ключи, созданные полным проходом записи под одним тенантом."""
    redis = aioredis.FakeRedis(decode_responses=True)
    await _write_everything(redis, TENANT)
    found = [key async for key in redis.scan_iter(count=1000)]
    await redis.aclose()
    return sorted(found)


# --- сам аудит -----------------------------------------------------------


def test_every_key_is_classified(keys) -> None:
    """Ни одного ключа вне инвентаря.

    Новый компонент, пишущий в Redis, обязан ответить на вопрос «чьи это
    данные» здесь — а не в момент, когда клиент увидит в ответе чужой
    `scan_id`.
    """
    unknown = [key for key in keys if _classify(key)[0] == "неизвестно"]

    assert not unknown, f"ключи без обоснования общности: {unknown}"


def test_tenant_scoped_keys_carry_the_tenant(keys) -> None:
    """Обещали тенанта в ключе — он там есть.

    Именно это обещание и было нарушено: `allowlist:<sha256>` разграничивал
    доступ проверкой на чтении, а ключ был один — и запись одного клиента
    затирала запись другого по тому же файлу.
    """
    for key in keys:
        section, prefix = _classify(key)
        if section != "tenant":
            continue
        assert TENANT in key, f"{prefix}: обещан тенант в ключе, а его нет: {key}"


def test_per_scan_keys_are_addressed_by_unguessable_id(keys) -> None:
    """Ключи без тенанта адресуются `scan_id` или sha256, а не именем."""
    for key in keys:
        section, prefix = _classify(key)
        if section != "scan":
            continue
        assert SCAN_ID in key or SHA in key, f"{prefix}: непонятно, чей это ключ: {key}"


def test_shared_keys_have_a_written_justification(keys) -> None:
    """У каждого общего ключа есть обоснование, и оно не заглушка."""
    for key in keys:
        section, prefix = _classify(key)
        if section != "shared":
            continue
        assert len(SHARED[prefix]) > 20, f"{prefix}: обоснование общности не написано"


def test_inventory_has_no_stale_entries(keys) -> None:
    """В инвентаре нет строк про ключи, которых больше нет.

    Устаревшая строка хуже отсутствующей: по ней читают, что данные
    разграничены, хотя компонент давно переписан.
    """
    used = {_classify(key)[1] for key in keys}
    listed = set(TENANT_IN_KEY) | set(PER_SCAN) | set(SHARED)

    assert not listed - used, f"инвентарь описывает ключи, которых нет: {sorted(listed - used)}"


def test_every_redis_module_is_exercised() -> None:
    """Список компонентов в этом файле не отстаёт от кода.

    Аудит по фактически созданным ключам сильнее обзора литералов, но у него
    своя слабость: компонент, который забыли завести в `_write_everything`,
    ключей не создаст и проверку пройдёт. Поэтому модули, работающие с Redis,
    сверяются со списком отдельно.
    """
    source = inspect.getsource(_write_everything) + "".join(
        line for line in pathlib.Path(__file__).read_text().splitlines() if "import" in line
    )
    missing = []
    for path in sorted(VSCOMMON.glob("*.py")):
        text = path.read_text()
        if "from redis" not in text and "import redis" not in text:
            # Упоминание Redis в комментарии — не работа с ним. Признак
            # именно импорт: без него модуль ключей не создаёт.
            continue
        if path.stem in {"redis_client", "config"}:
            # Первый создаёт соединение и своих ключей не имеет, второй лишь
            # хранит адрес.
            continue
        if f"vscommon.{path.stem}" not in source:
            missing.append(path.stem)

    assert not missing, f"модуль работает с Redis, но в аудите не участвует: {missing}"


# --- поведение: чужого не видно ------------------------------------------


@pytest.fixture()
async def redis():
    client = aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


async def test_allowlist_entry_is_not_overwritten_by_a_neighbour(redis) -> None:
    """Два клиента разрешили один файл — обе записи живы.

    Раньше ключ был один на sha256, и вторая запись затирала первую. Пропажа
    разрешения возвращает блокировку документа, который вручную разобрали, —
    и выглядит это как новое ложное срабатывание, а не как потеря настройки.
    """
    allowlist = Allowlist(redis)
    await allowlist.add(
        AllowlistEntry(sha256=SHA, reason="разобрано у нас", author="дежурный-а", tenant=TENANT)
    )
    await allowlist.add(
        AllowlistEntry(sha256=SHA, reason="разобрано у нас", author="дежурный-б", tenant=OTHER)
    )

    ours = await allowlist.get(SHA, TENANT)
    theirs = await allowlist.get(SHA, OTHER)

    assert ours is not None and ours.author == "дежурный-а"
    assert theirs is not None and theirs.author == "дежурный-б"


async def test_own_entry_wins_over_the_global_one(redis) -> None:
    """Своя запись перекрывает общую: она заведена под этого клиента."""
    allowlist = Allowlist(redis)
    await allowlist.add(AllowlistEntry(sha256=SHA, reason="общее разрешение", author="админ"))
    await allowlist.add(
        AllowlistEntry(sha256=SHA, reason="разобрано у нас", author="дежурный-а", tenant=TENANT)
    )

    entry = await allowlist.get(SHA, TENANT)

    assert entry is not None and entry.author == "дежурный-а"


async def test_listing_shows_own_and_global_but_not_a_neighbour(redis) -> None:
    """В записи есть автор и причина — рассказ о чужом потоке документов."""
    allowlist = Allowlist(redis)
    await allowlist.add(AllowlistEntry(sha256="c" * 64, reason="общее разрешение", author="админ"))
    await allowlist.add(
        AllowlistEntry(sha256=SHA, reason="разобрано у нас", author="дежурный-а", tenant=TENANT)
    )
    await allowlist.add(
        AllowlistEntry(sha256="b" * 64, reason="их разбор", author="дежурный-б", tenant=OTHER)
    )

    authors = {entry.author for entry in await allowlist.entries(tenant=TENANT)}

    assert authors == {"дежурный-а", "админ"}


async def test_admin_sees_every_tenant(redis) -> None:
    """Администратору список нужен целиком — иначе пересматривать нечего."""
    allowlist = Allowlist(redis)
    await allowlist.add(
        AllowlistEntry(sha256=SHA, reason="разобрано у нас", author="дежурный-а", tenant=TENANT)
    )
    await allowlist.add(
        AllowlistEntry(sha256="b" * 64, reason="их разбор", author="дежурный-б", tenant=OTHER)
    )

    authors = {entry.author for entry in await allowlist.entries(tenant=None)}

    assert authors == {"дежурный-а", "дежурный-б"}


async def test_removing_does_not_touch_a_neighbours_permission(redis) -> None:
    """Удаление своей записи не снимает разрешение у соседа."""
    allowlist = Allowlist(redis)
    for tenant in (TENANT, OTHER):
        await allowlist.add(
            AllowlistEntry(sha256=SHA, reason="разобрано вручную", author="дежурный", tenant=tenant)
        )

    assert await allowlist.remove(SHA, "дежурный", TENANT)

    assert await allowlist.get(SHA, TENANT) is None
    assert await allowlist.get(SHA, OTHER) is not None


async def test_shadow_report_counts_only_its_own_tenant(redis) -> None:
    """Доля «заблокировали бы» на общем счётчике не имела смысла.

    Теневой режим включают по одному тенанту (`TenantPolicy.shadow_mode`),
    значит общая доля описывала поток тех, у кого он включён, а выдавалась за
    долю спрашивающего.
    """
    ledger = ShadowLedger(redis)
    await ledger.record(TENANT, "clean", False, [], SHA)
    for _ in range(3):
        await ledger.record(OTHER, "malicious", True, ["PDF_LAUNCH"], "b" * 64)

    ours = await ledger.report(TENANT)

    assert ours.total == 1
    assert ours.would_block == 0
    assert ours.recent_blocks == [], "чужие хэши не должны попадать в наш отчёт"


async def test_shadow_reset_does_not_wipe_a_neighbour(redis) -> None:
    """Сброс счётчиков — операция одного тенанта.

    Общий `reset` уничтожал наблюдение соседа, который как раз считал свою
    долю ложных срабатываний, и восстановить его было нечем.
    """
    ledger = ShadowLedger(redis)
    await ledger.record(TENANT, "clean", False, [], SHA)
    await ledger.record(OTHER, "clean", False, [], "b" * 64)

    await ledger.reset(TENANT)

    assert (await ledger.report(TENANT)).total == 0
    assert (await ledger.report(OTHER)).total == 1


async def test_admin_aggregate_sums_tenants(redis) -> None:
    """Сводка администратору складывается, а не ведётся вторым счётчиком.

    Второй счётчик того же события пришлось бы держать согласованным, а
    расходятся такие пары молча.
    """
    from vscommon.shadow import ALL_TENANTS

    ledger = ShadowLedger(redis)
    await ledger.record(TENANT, "clean", False, [], SHA)
    await ledger.record(OTHER, "malicious", True, ["PDF_LAUNCH"], "b" * 64)

    total = await ledger.report(ALL_TENANTS)

    assert total.total == 2
    assert total.would_block == 1
    assert dict(total.top_codes) == {"PDF_LAUNCH": 1}


async def test_dead_letter_listing_is_filtered_by_tenant(redis) -> None:
    """В записи разбора лежит ключ объекта в карантине — по нему читается файл."""
    dlq = DeadLetterQueue(redis, stream="scan.dlq")
    for index, tenant in enumerate([OTHER] * 5 + [TENANT]):
        await dlq.publish(
            DeadLetter(
                scan_id=f"scan-{index}",
                sha256=SHA,
                reason=DeadLetterReason.SCAN_FAILED,
                verdict=Verdict.ERROR,
                tenant=tenant,
                source=ObjectRef(bucket="quarantine", key=f"a/{index}"),
            )
        )

    ours = await dlq.recent(count=50, tenant=TENANT)

    assert [entry.tenant for entry in ours] == [TENANT]


async def test_dead_letter_filtering_looks_past_the_first_page(redis) -> None:
    """Отбор идёт страницами, иначе редкие отказы не находятся.

    Записи тенантов в потоке перемешаны: без страниц клиент видел бы пустой
    разбор при непустой очереди — то есть отказ, выглядящий как порядок.
    """
    dlq = DeadLetterQueue(redis, stream="scan.dlq")
    dlq.PAGE = 3  # чтобы не заводить в тест сотни записей

    await dlq.publish(
        DeadLetter(
            scan_id="scan-наш",
            sha256=SHA,
            reason=DeadLetterReason.SCAN_FAILED,
            verdict=Verdict.ERROR,
            tenant=TENANT,
            source=ObjectRef(bucket="quarantine", key="a/1"),
        )
    )
    for index in range(10):
        await dlq.publish(
            DeadLetter(
                scan_id=f"scan-{index}",
                sha256=SHA,
                reason=DeadLetterReason.SCAN_FAILED,
                verdict=Verdict.ERROR,
                tenant=OTHER,
                source=ObjectRef(bucket="quarantine", key=f"b/{index}"),
            )
        )

    ours = await dlq.recent(count=5, tenant=TENANT)

    assert [entry.scan_id for entry in ours] == ["scan-наш"]


# --- права на служебные ручки --------------------------------------------


def _request(state, key: AccessKey | None) -> SimpleNamespace:
    """То немногое из `Request`, чем пользуются служебные ручки.

    Стенда для маршрутов gateway в проекте нет, и заводить его ради этого
    незачем: решение «чьи данные показать» целиком принимает `ops_scope`.
    """
    request = SimpleNamespace()
    request.app = SimpleNamespace(state=SimpleNamespace(vs=state))
    request.state = SimpleNamespace()
    if key is not None:
        request.state.access_key = key
    request.url = SimpleNamespace(path="/v1/ops/allowlist")
    return request


def _key(admin: bool = False) -> AccessKey:
    return AccessKey(key_id="k1", tenant=TENANT, secret="s" * 32, admin=admin)


async def test_ops_scope_is_the_tenant_for_a_plain_key() -> None:
    """Обычный ключ видит только себя.

    Раньше служебным ручкам хватало любой подписи, а отдают они разбор
    карантина, список доверенных и учёт теневого режима.
    """
    from gateway_app.auth import ops_scope

    assert await ops_scope(_request(None, _key())) == TENANT


async def test_ops_scope_is_everyone_for_an_admin_key() -> None:
    from gateway_app.auth import ops_scope

    assert await ops_scope(_request(None, _key(admin=True))) is None


async def test_ops_scope_refuses_when_the_key_is_missing() -> None:
    """Без проверенного ключа сузить видимость некуда, кроме «ничего».

    Сюда попадают только после `require_signed_ops`; отсутствие ключа значит,
    что порядок зависимостей сломали, и молча отдать всё — худший из исходов.
    """
    from gateway_app.auth import ops_scope

    with pytest.raises(HTTPException) as exc:
        await ops_scope(_request(None, None))

    assert exc.value.status_code == 401


def test_every_ops_handler_asks_who_is_calling() -> None:
    """Новая служебная ручка обязана объявить `scope`.

    Проверяется объявление, а не поведение: ручку, забывшую про тенанта,
    поведенческий тест не поймает — его для неё просто не напишут.
    """
    from gateway_app.auth import ops_scope
    from gateway_app.routes import ops

    unscoped = []
    for route in ops.router.routes:
        parameters = inspect.signature(route.endpoint).parameters
        scope = parameters.get("scope")
        if scope is None or getattr(scope.default, "dependency", None) is not ops_scope:
            unscoped.append(route.endpoint.__name__)

    assert not unscoped, f"служебная ручка не ограничена тенантом: {unscoped}"


async def test_plain_key_cannot_allow_a_file_for_everyone(redis) -> None:
    """`tenant: "*"` — право администратора.

    Иначе любой клиент снимал бы блокировку файла соседям, причём в списке это
    выглядело бы законной записью с автором и причиной.
    """
    from gateway_app.routes.ops import add_to_allowlist

    state = SimpleNamespace(allowlist=Allowlist(redis))
    body = json.dumps(
        {"sha256": SHA, "reason": "разобрано вручную", "author": "дежурный", "tenant": "*"}
    ).encode()

    with pytest.raises(HTTPException) as exc:
        await add_to_allowlist(_request(state, None), body=body, ttl_days=None, scope=TENANT)

    assert exc.value.status_code == 403


async def test_plain_key_writes_the_entry_to_its_own_tenant(redis) -> None:
    """Тенант не назван — берётся из ключа, а не из умолчания модели.

    Умолчание `AllowlistEntry.tenant` — это `*`. Принять его как желание
    клиента значило бы отдать «для всех» тому, кто просто не заполнил поле.
    """
    from gateway_app.routes.ops import add_to_allowlist

    state = SimpleNamespace(allowlist=Allowlist(redis))
    body = json.dumps({"sha256": SHA, "reason": "разобрано вручную", "author": "дежурный"}).encode()

    stored = await add_to_allowlist(_request(state, None), body=body, ttl_days=None, scope=TENANT)

    assert stored.tenant == TENANT
    assert await Allowlist(redis).get(SHA, OTHER) is None


async def test_admin_keeps_the_global_default(redis) -> None:
    """Администратор по-прежнему пишет «для всех», не называя тенанта."""
    from gateway_app.routes.ops import add_to_allowlist

    state = SimpleNamespace(allowlist=Allowlist(redis))
    body = json.dumps({"sha256": SHA, "reason": "разобрано вручную", "author": "админ"}).encode()

    stored = await add_to_allowlist(_request(state, None), body=body, ttl_days=None, scope=None)

    assert stored.tenant == "*"


async def test_queue_size_is_not_shown_to_a_tenant(redis) -> None:
    """Размер очереди разбора — величина общая: это поток отказов у соседей."""
    from gateway_app.routes.ops import dead_letter_size

    state = SimpleNamespace(dlq=DeadLetterQueue(redis, stream="scan.dlq"))

    with pytest.raises(HTTPException) as exc:
        await dead_letter_size(_request(state, None), scope=TENANT)

    assert exc.value.status_code == 404, "404, а не 403: подтверждать существование ручки незачем"
