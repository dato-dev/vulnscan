"""M3.4: снятие блокировки с конкретного файла без релиза."""

from __future__ import annotations

import time

import pytest
from fakeredis import aioredis
from pydantic import ValidationError

from vscommon.allowlist import ANY_TENANT, Allowlist, AllowlistEntry, entry_from_request

SHA = "a" * 64


@pytest.fixture()
async def allowlist():
    redis = aioredis.FakeRedis(decode_responses=True)
    yield Allowlist(redis, default_ttl_days=30)
    await redis.aclose()


def _entry(**kwargs) -> AllowlistEntry:
    defaults = {
        "sha256": SHA,
        "reason": "разобрано вручную, ложное срабатывание",
        "author": "дежурный",
    }
    return AllowlistEntry(**{**defaults, **kwargs})


# --- обязательные поля ---


def test_reason_is_required() -> None:
    """«Потом разберёмся» не должно проходить: через полгода никто не вспомнит."""
    with pytest.raises(ValidationError):
        AllowlistEntry(sha256=SHA, reason="ок", author="дежурный")


def test_author_is_required() -> None:
    with pytest.raises(ValidationError):
        AllowlistEntry(sha256=SHA, reason="ложное срабатывание на скане", author="")


def test_extra_fields_are_dropped() -> None:
    """Клиент не должен уметь дописать себе поля вроде срока жизни."""
    entry = entry_from_request(
        {
            "sha256": SHA,
            "reason": "разобрано вручную",
            "author": "дежурный",
            "expires_at": 9e12,
            "verdict": "clean",
        }
    )

    assert entry.sha256 == SHA
    assert entry.expires_at != 9e12


# --- срок жизни ---


async def test_entry_expires(allowlist) -> None:
    """Вечная запись превращается в дыру, о которой все забыли."""
    stored = await allowlist.add(_entry(), ttl_days=7)

    assert stored.days_left == 7, "назначили семь дней — должно показывать семь"
    assert stored.expires_at > time.time()


async def test_expired_entry_is_not_returned(allowlist) -> None:
    await allowlist.add(_entry(), ttl_days=1)
    await allowlist._redis.delete(Allowlist._key(SHA))  # имитация истечения

    assert await allowlist.get(SHA, None) is None


async def test_index_cleaned_after_expiry(allowlist) -> None:
    await allowlist.add(_entry(), ttl_days=1)
    await allowlist._redis.delete(Allowlist._key(SHA))

    assert await allowlist.entries() == []


# --- область действия ---


async def test_global_entry_applies_to_any_tenant(allowlist) -> None:
    await allowlist.add(_entry())

    assert await allowlist.get(SHA, "team-a") is not None
    assert await allowlist.get(SHA, "team-b") is not None


async def test_tenant_entry_does_not_leak(allowlist) -> None:
    """Доверие одного клиента не должно распространяться на остальных."""
    await allowlist.add(_entry(tenant="team-a"))

    assert await allowlist.get(SHA, "team-a") is not None
    assert await allowlist.get(SHA, "team-b") is None


def test_scope_check() -> None:
    assert _entry(tenant=ANY_TENANT).applies_to("кто угодно")
    assert _entry(tenant="team-a").applies_to("team-a")
    assert not _entry(tenant="team-a").applies_to(None)


# --- жизненный цикл ---


async def test_add_get_remove(allowlist) -> None:
    await allowlist.add(_entry())
    assert await allowlist.get(SHA, None) is not None

    assert await allowlist.remove(SHA, "дежурный")
    assert await allowlist.get(SHA, None) is None


async def test_remove_missing_reports_false(allowlist) -> None:
    assert not await allowlist.remove("b" * 64, "дежурный")


async def test_entries_sorted_by_expiry(allowlist) -> None:
    """Ближайшие к истечению — первыми: их и надо пересматривать."""
    await allowlist.add(_entry(sha256="a" * 64), ttl_days=30)
    await allowlist.add(_entry(sha256="b" * 64), ttl_days=3)

    entries = await allowlist.entries()

    assert [e.sha256[0] for e in entries] == ["b", "a"]


async def test_corrupted_entry_ignored(allowlist) -> None:
    await allowlist._redis.set(Allowlist._key(SHA), "{не json")

    assert await allowlist.get(SHA, None) is None


# --- взаимодействие с кэшем ---


async def test_removed_entry_restores_blocking(allowlist) -> None:
    """Отзыв записи возвращает блокировку: это не односторонняя дверь."""
    await allowlist.add(_entry())
    assert await allowlist.get(SHA, None) is not None

    await allowlist.remove(SHA, "дежурный")

    assert await allowlist.get(SHA, None) is None


def test_days_left_is_visible_in_response() -> None:
    """Срок должен быть виден в ответе — иначе записи никто не пересматривает."""
    entry = _entry()
    entry.expires_at = time.time() + 5 * 86400

    assert entry.model_dump()["days_left"] == 5


def test_entry_never_carries_file_content() -> None:
    """В аудите только хэш: содержимое доверенного документа хранить незачем."""
    fields = set(AllowlistEntry.model_fields)

    assert fields == {"sha256", "reason", "author", "tenant", "created_at", "expires_at"}
