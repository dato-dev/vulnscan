"""Мультитенантность: ключи, владение сканом, адреса коллбэков.

До M8 тенант был самозаявленным заголовком при одном общем секрете. Тесты здесь
закрепляют главное: тенант выводится из ключа и ниоткуда больше.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vscommon.callbacks import CallbackRejectedError, validate_callback
from vscommon.keys import MIN_SECRET_LEN, AccessKey, KeyRegistry
from vscommon.signing import sign

SECRET_A = "a" * MIN_SECRET_LEN
SECRET_B = "b" * MIN_SECRET_LEN


def _registry(tmp_path: Path, payload: dict[str, object]) -> KeyRegistry:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(payload))
    return KeyRegistry.load(str(path))


# --- реестр ключей -------------------------------------------------------


def test_tenant_comes_from_the_key(tmp_path: Path) -> None:
    """Главный инвариант всего M8."""
    registry = _registry(tmp_path, {"k1": {"tenant": "команда-а", "secret": SECRET_A}})
    body = b'{"mode":"both"}'
    ts, signature = sign(SECRET_A, body)

    key = registry.resolve("k1", body, ts, signature)

    assert key is not None and key.tenant == "команда-а"


def test_foreign_key_cannot_impersonate(tmp_path: Path) -> None:
    """Ключ команды Б не даёт назваться командой А.

    Раньше для этого хватало заголовка: чужая политика вместе с её порогами и
    режимом отказа доставалась любому, кто её назвал.
    """
    registry = _registry(
        tmp_path,
        {
            "k1": {"tenant": "команда-а", "secret": SECRET_A},
            "k2": {"tenant": "команда-б", "secret": SECRET_B},
        },
    )
    body = b"{}"
    ts, signature = sign(SECRET_B, body)

    # Подпись ключом Б, а идентификатор назван чужой.
    assert registry.resolve("k1", body, ts, signature) is None
    assert registry.resolve("k2", body, ts, signature).tenant == "команда-б"  # type: ignore[union-attr]


def test_disabled_key_is_refused(tmp_path: Path) -> None:
    """Отзыв обязан работать без рестарта."""
    registry = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A, "disabled": True}})
    body = b"{}"
    ts, signature = sign(SECRET_A, body)

    assert registry.resolve("k1", body, ts, signature) is None


def test_short_secret_is_not_loaded(tmp_path: Path) -> None:
    """Короткий секрет перебирается — это условие приёма, а не рекомендация."""
    registry = _registry(tmp_path, {"k1": {"tenant": "а", "secret": "коротко"}})

    assert len(registry) == 0


def test_one_broken_entry_does_not_close_access_for_others(tmp_path: Path) -> None:
    """Опечатка в файле не должна отрезать остальных тенантов."""
    registry = _registry(
        tmp_path,
        {"плохой": {"tenant": "а"}, "хороший": {"tenant": "б", "secret": SECRET_B}},
    )

    assert len(registry) == 1
    assert registry.get("хороший") is not None


def test_missing_file_refuses_everyone(tmp_path: Path) -> None:
    """Умолчание в аутентификации — это дыра.

    Тот же случай уже ронял gateway: непримонтированный файл Docker молча
    подменяет каталогом. Здесь это означает «никого не пускаем», а не
    «работаем на значениях по умолчанию».
    """
    registry = KeyRegistry.load(str(tmp_path / "нет-такого.json"))

    assert registry.degraded
    assert len(registry) == 0


def test_fingerprint_does_not_contain_secrets(tmp_path: Path) -> None:
    registry = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})

    assert SECRET_A not in registry.fingerprint()


def test_wrong_signature_is_refused(tmp_path: Path) -> None:
    registry = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})
    ts, _ = sign(SECRET_A, b"{}")

    assert registry.resolve("k1", b"{}", ts, "sha256=подделка") is None


def test_body_substitution_is_detected(tmp_path: Path) -> None:
    registry = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})
    ts, signature = sign(SECRET_A, b'{"profile":"strict"}')

    assert registry.resolve("k1", b'{"profile":"light"}', ts, signature) is None


# --- адреса коллбэков (M8.9) --------------------------------------------


def test_allowed_host_passes() -> None:
    assert validate_callback("https://client.example/hook", ("client.example",))


def test_empty_allowlist_forbids_everything() -> None:
    """Пустой список — «запрещено», а не «разрешено всё»."""
    with pytest.raises(CallbackRejectedError):
        validate_callback("https://client.example/hook", ())


def test_foreign_host_is_refused() -> None:
    with pytest.raises(CallbackRejectedError):
        validate_callback("https://зло.example/hook", ("client.example",))


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.170.2/v2/credentials",
    ],
)
def test_cloud_metadata_is_never_allowed(url: str) -> None:
    """Запрещено даже если вписали в список.

    Легитимного повода слать туда результат не существует, а цена ошибки в
    конфигурации — выдача ключей от всей инфраструктуры.
    """
    host = url.split("/")[2]
    with pytest.raises(CallbackRejectedError):
        validate_callback(url, (host,))


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://client.example/",
        "ftp://client.example/",
    ],
)
def test_only_http_schemes_are_allowed(url: str) -> None:
    with pytest.raises(CallbackRejectedError):
        validate_callback(url, ("client.example",))


def test_credentials_in_url_are_refused() -> None:
    """Они утекут в логи доставки и в историю."""
    with pytest.raises(CallbackRejectedError):
        validate_callback("https://ключ:пароль@client.example/hook", ("client.example",))


def test_internal_service_is_refused_when_not_listed() -> None:
    """Сканер не должен становиться посредником для обращений внутрь сети."""
    for target in ("http://redis:6379/", "http://minio:9000/", "http://gateway:8080/"):
        with pytest.raises(CallbackRejectedError):
            validate_callback(target, ("client.example",))


# --- владение сканом (M8.3) ---------------------------------------------


@pytest.mark.asyncio
async def test_foreign_tenant_cannot_read_scan() -> None:
    """`scan_id` не секрет: он попадает в логи, переписку и тикеты."""
    from fakeredis.aioredis import FakeRedis

    from vscommon.ownership import Ownership

    ownership = Ownership(FakeRedis(decode_responses=True), ttl_s=300)
    await ownership.claim("скан-1", "команда-а")

    assert await ownership.allows("скан-1", "команда-а")
    assert not await ownership.allows("скан-1", "команда-б")


@pytest.mark.asyncio
async def test_unknown_owner_is_refusal_not_permission() -> None:
    """Записи истекают; отдавать документ наугад нельзя."""
    from fakeredis.aioredis import FakeRedis

    from vscommon.ownership import Ownership

    ownership = Ownership(FakeRedis(decode_responses=True), ttl_s=300)

    assert not await ownership.allows("никогда-не-было", "команда-а")


def test_access_key_defaults_forbid_callbacks() -> None:
    """Разрешать по умолчанию нельзя: адрес приходит из запроса."""
    assert AccessKey(key_id="k", tenant="а", secret=SECRET_A).callback_hosts == ()


# --- совместимость бота с проверкой gateway -----------------------------
#
# Именно это разошлось на боевом стенде: сервис перешёл на ключи, а бот
# продолжал слать `X-Vulnscan-Tenant` без подписи и получал `401` на каждый файл.


def test_bot_signature_is_accepted_by_gateway(tmp_path: Path) -> None:
    """Клиент и сервис обязаны строить подпись загрузки одинаково.

    Проверяется сквозным путём: бот считает заголовки, реестр их принимает.
    Копия формата на одной из сторон разошлась бы молча, а выглядело бы это
    как неверный ключ.
    """
    from vscommon.signing import canonical_request

    registry = _registry(
        tmp_path, {"telegram-bot-1": {"tenant": "telegram-bot", "secret": SECRET_A}}
    )

    payload = canonical_request("POST", "/v1/scan", "telegram-bot-1")
    timestamp, signature = sign(SECRET_A, payload)

    key = registry.resolve("telegram-bot-1", payload, timestamp, signature)
    assert key is not None and key.tenant == "telegram-bot"


def test_signature_from_another_path_is_refused(tmp_path: Path) -> None:
    """Подпись, снятая с одной ручки, не должна годиться для другой."""
    from vscommon.signing import canonical_request

    registry = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})
    timestamp, signature = sign(SECRET_A, canonical_request("GET", "/v1/scan/чужой", "k1"))

    assert (
        registry.resolve("k1", canonical_request("POST", "/v1/scan", "k1"), timestamp, signature)
        is None
    )


def test_comment_entries_do_not_produce_errors(tmp_path: Path) -> None:
    """JSON не имеет комментариев, их кладут отдельным полем.

    Ругаться на штатную запись нельзя: `ERROR` при каждом старте обесценивает
    сам уровень, и настоящую ошибку перестают замечать.
    """
    registry = _registry(
        tmp_path,
        {
            "_комментарий": ["как заполнять этот файл"],
            "k1": {"tenant": "а", "secret": SECRET_A},
        },
    )

    assert len(registry) == 1
    assert registry.get("k1") is not None


@pytest.mark.asyncio
async def test_owner_is_recorded_for_every_scan_id() -> None:
    """Владелец записывается везде, где наружу уходит новый `scan_id`.

    Ответ из кэша получает свежий идентификатор и раньше уходил клиенту без
    записи владельца — тот не мог забрать собственный результат, проверка
    владения честно отвечала `404`. Ошибка проявлялась только на повторе
    того же файла, то есть ровно тогда, когда всё «должно работать быстрее».
    """
    from fakeredis.aioredis import FakeRedis

    from vscommon.ownership import Ownership

    ownership = Ownership(FakeRedis(decode_responses=True), ttl_s=300)

    # Путь полной проверки и путь кэша дают разные scan_id — оба обязаны
    # получить владельца.
    for scan_id in ("из-очереди", "из-кэша"):
        await ownership.claim(scan_id, "telegram-bot")
        assert await ownership.allows(scan_id, "telegram-bot"), scan_id


def test_every_ingest_path_claims_ownership() -> None:
    """Структурная проверка: сколько мест выдают scan_id, столько и записей.

    Тест на исходник намеренно. Логику владения легко починить в одном месте
    и забыть про второе — именно так и вышло: `claim` стоял только на пути
    полной проверки, а ответ из кэша уходил без владельца.
    """
    source = (Path(__file__).parent.parent / "services/gateway/gateway_app/ingest.py").read_text()

    claims = source.count("ownership.claim(")
    statuses = source.count("results.store_status(")

    assert claims >= statuses, (
        f"мест, выдающих scan_id: {statuses}, записей владельца: {claims} — "
        "какой-то путь отдаёт скан без владельца"
    )


# --- квота считается по ключу, а не по заголовку -------------------------


def test_rate_limit_bucket_cannot_be_switched_by_header(tmp_path: Path) -> None:
    """Заголовок с именем тенанта клиент выставляет сам.

    Пока ведро выбиралось по нему, достаточно было прислать другое имя, чтобы
    получить свежий счётчик и обойти собственную квоту. M8 перевёл на ключи
    вердикт и политику, а квота осталась на заголовке — дыра дожила до
    проверки документации.
    """
    from types import SimpleNamespace

    from gateway_app.throttle import _bucket_of

    registry = _registry(tmp_path, {"k1": {"tenant": "команда-а", "secret": SECRET_A}})
    state = SimpleNamespace(
        keys=registry,
        policies=SimpleNamespace(for_tenant=lambda t: SimpleNamespace(rate_limit_per_min=10)),
    )

    # Заголовок врёт, ключ настоящий — ведро определяется ключом.
    request = SimpleNamespace(
        headers={"X-Vulnscan-Key": "k1", "X-Vulnscan-Tenant": "чужая-команда"}
    )
    bucket, _policy = _bucket_of(request, state)
    assert bucket == "команда-а"


def test_unknown_key_shares_one_strict_bucket(tmp_path: Path) -> None:
    """Перебор идентификаторов не должен давать счётчик на каждую попытку."""
    from types import SimpleNamespace

    from gateway_app.throttle import UNKNOWN_BUCKET, _bucket_of

    registry = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})
    state = SimpleNamespace(
        keys=registry,
        policies=SimpleNamespace(for_tenant=lambda t: SimpleNamespace(rate_limit_per_min=10)),
    )

    for attempt in ("выдумка-1", "выдумка-2", ""):
        request = SimpleNamespace(headers={"X-Vulnscan-Key": attempt})
        assert _bucket_of(request, state)[0] == UNKNOWN_BUCKET
