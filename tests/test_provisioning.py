"""Заведение тенантов и ключей без правки файлов (M8.7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fakeredis.aioredis import FakeRedis

from vscommon.keys import MIN_SECRET_LEN, KeyRegistry
from vscommon.provisioning import TenantStore, generate_secret

SECRET = "f" * MIN_SECRET_LEN


def _store() -> TenantStore:
    return TenantStore(FakeRedis(decode_responses=True))


def test_generated_secret_is_long_enough() -> None:
    """Секрет генерируется сервером: присланный клиентом мог бы оказаться
    коротким, повторно использованным или подсмотренным."""
    assert len(generate_secret()) >= MIN_SECRET_LEN


def test_generated_secrets_differ() -> None:
    assert generate_secret() != generate_secret()


@pytest.mark.asyncio
async def test_key_is_issued_and_readable() -> None:
    store = _store()
    await store.put_key("k1", "команда-а", SECRET, callback_hosts=("hooks.example",))

    keys = await store.all_keys()
    assert keys["k1"].tenant == "команда-а"
    assert keys["k1"].callback_hosts == ("hooks.example",)


@pytest.mark.asyncio
async def test_short_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="короче"):
        await _store().put_key("k1", "а", "коротко")


@pytest.mark.asyncio
async def test_revocation_removes_the_secret() -> None:
    """Удаляем, а не помечаем: отозванный ключ не должен лежать в хранилище
    вместе с рабочим секретом."""
    store = _store()
    await store.put_key("k1", "а", SECRET)

    assert await store.revoke_key("k1") is True
    assert await store.all_keys() == {}
    assert await store.revoke_key("k1") is False


@pytest.mark.asyncio
async def test_store_overrides_file(tmp_path: Path) -> None:
    """Отозвать ключ через API должно получаться и тогда, когда он в файле."""
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"k1": {"tenant": "из-файла", "secret": SECRET}}))
    from_file = KeyRegistry.load(str(path))

    store = _store()
    await store.put_key("k1", "из-хранилища", SECRET)
    merged = from_file.merged_with(await store.all_keys())

    key = merged.get("k1")
    assert key is not None and key.tenant == "из-хранилища"


@pytest.mark.asyncio
async def test_file_keys_survive_alongside_store(tmp_path: Path) -> None:
    """Файл — начальная загрузка: потеря Redis не должна отрезать админа."""
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"админ": {"tenant": "ops", "secret": SECRET, "admin": True}}))
    from_file = KeyRegistry.load(str(path))

    store = _store()
    await store.put_key("k1", "команда-а", SECRET)
    merged = from_file.merged_with(await store.all_keys())

    assert merged.get("админ") is not None
    assert merged.get("k1") is not None


@pytest.mark.asyncio
async def test_admin_flag_is_preserved(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"a": {"tenant": "ops", "secret": SECRET, "admin": True}}))

    key = KeyRegistry.load(str(path)).get("a")
    assert key is not None and key.admin


@pytest.mark.asyncio
async def test_ordinary_key_is_not_admin(tmp_path: Path) -> None:
    """Умолчание — не администратор.

    Иначе клиент выписывал бы себе ключи и менял себе политику: тот же
    `fail-open` полем в запросе, только окольным путём.
    """
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"a": {"tenant": "команда-а", "secret": SECRET}}))

    key = KeyRegistry.load(str(path)).get("a")
    assert key is not None and not key.admin


@pytest.mark.asyncio
async def test_policy_from_store_overrides_file() -> None:
    from vscommon.config import CommonSettings
    from vscommon.policy import PolicyRegistry

    settings = CommonSettings(default_block_threshold=80)
    registry = PolicyRegistry.load(settings, {"команда-а": {"block_threshold": 55}})

    assert registry.for_tenant("команда-а").block_threshold == 55
    assert registry.for_tenant("другая").block_threshold == 80


@pytest.mark.asyncio
async def test_broken_managed_policy_does_not_break_others() -> None:
    from vscommon.config import CommonSettings
    from vscommon.policy import PolicyRegistry

    settings = CommonSettings(default_block_threshold=80)
    registry = PolicyRegistry.load(
        settings,
        {"плохая": {"block_threshold": "не число"}, "хорошая": {"block_threshold": 60}},
    )

    assert registry.for_tenant("хорошая").block_threshold == 60
    assert registry.for_tenant("плохая").block_threshold == 80


@pytest.mark.asyncio
async def test_tenants_are_derived_from_keys() -> None:
    """Список тенантов для меток метрик берётся отсюда, а не из отдельной
    переменной: два списка неизбежно разъезжаются."""
    store = _store()
    await store.put_key("k1", "команда-а", SECRET)
    await store.put_key("k2", "команда-б", SECRET)
    await store.put_key("k3", "команда-а", SECRET)

    assert await store.tenants() == ("команда-а", "команда-б")
