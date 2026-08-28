"""Сроки хранения в объектном хранилище.

Здесь лежат сканы паспортов и договоров. Хранилище, которое ничего не удаляет,
со временем превращается в архив чужих документов.
"""

from __future__ import annotations

from typing import Any

from vscommon.storage import S3Store


class FakeS3:
    def __init__(self, fail: bool = False) -> None:
        self.applied: list[dict[str, Any]] = []
        self._fail = fail

    def put_bucket_lifecycle_configuration(self, **kwargs: Any) -> None:
        if self._fail:
            raise RuntimeError("реализация не поддерживает lifecycle")
        self.applied.append(kwargs)


def _store(client: object) -> S3Store:
    store = S3Store.__new__(S3Store)
    store._client = client  # type: ignore[attr-defined]
    return store


def test_retention_is_applied_to_bucket() -> None:
    client = FakeS3()

    assert _store(client).apply_retention("vulnscan-raw", 1) is True

    rule = client.applied[0]["LifecycleConfiguration"]["Rules"][0]
    assert client.applied[0]["Bucket"] == "vulnscan-raw"
    assert rule["Status"] == "Enabled"
    assert rule["Expiration"]["Days"] == 1


def test_zero_days_does_not_disable_cleanup_silently() -> None:
    """Ноль — это «не задано», и об этом надо сказать вслух.

    Молча накапливать чужие документы хуже, чем громко отказаться настроить
    уборку: во втором случае это хотя бы заметят.
    """
    client = FakeS3()

    assert _store(client).apply_retention("vulnscan-raw", 0) is False
    assert client.applied == []


def test_unsupported_storage_does_not_break_startup() -> None:
    """Не все реализации S3 умеют lifecycle.

    Это повод сообщить, а не падать: сервис должен работать, но администратор
    обязан узнать, что уборка не настроена.
    """
    assert _store(FakeS3(fail=True)).apply_retention("vulnscan-raw", 1) is False
