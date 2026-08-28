"""Версия баз антивируса и её влияние на кэш.

Версия входит в ключ AV-кэша: пока она не менялась, кэш считает прежние
результаты действительными. Значит обновление баз обязано её менять, иначе
новые сигнатуры не применяются к уже виденным файлам.
"""

from __future__ import annotations

import pytest

from worker_app.stages.clamav import ClamavStage


class VersionedClamd:
    """Клиент, у которого версия баз меняется под нами — как в жизни."""

    def __init__(self, version: str) -> None:
        self.version_string = version
        self.calls = 0

    def version(self) -> str:
        self.calls += 1
        return self.version_string

    def instream(self, buff: object) -> dict[str, tuple[str, None]]:
        return {"stream": ("OK", None)}


class BrokenClamd:
    def version(self) -> str:
        raise ConnectionError("clamd недоступен")

    def instream(self, buff: object) -> dict[str, tuple[str, None]]:
        raise ConnectionError("clamd недоступен")


def test_version_is_picked_up_on_first_connect() -> None:
    client = VersionedClamd("ClamAV 1.4.6/28101")
    stage = ClamavStage(factory=lambda: client)
    stage.warmup()

    assert stage.engine_version == "ClamAV 1.4.6/28101"


def test_database_update_changes_version() -> None:
    """Главное: freshclam обновил базы — ключ кэша обязан поменяться.

    Раньше версия защёлкивалась на первом подключении и жила до перезапуска
    процесса. Базы обновлялись, clamd их подхватывал, а воркер ещё сутки
    отдавал вердикты, снятые старыми сигнатурами.
    """
    client = VersionedClamd("ClamAV 1.4.6/28101")
    stage = ClamavStage(factory=lambda: client)
    stage.warmup()

    client.version_string = "ClamAV 1.4.6/28108"

    assert stage.refresh_version() is True
    assert stage.engine_version == "ClamAV 1.4.6/28108"


def test_unchanged_version_reports_no_change() -> None:
    """Иначе каждые 30 секунд обесценивался бы весь AV-кэш."""
    client = VersionedClamd("ClamAV 1.4.6/28101")
    stage = ClamavStage(factory=lambda: client)
    stage.warmup()

    assert stage.refresh_version() is False


def test_unavailable_clamd_keeps_previous_version() -> None:
    """Недоступность clamd не должна выглядеть как обновление баз.

    Смена версии обесценивает кэш; делать это из-за сетевого сбоя — значит
    перепроверять всё подряд ровно тогда, когда антивирус и так не отвечает.
    """
    stage = ClamavStage(factory=BrokenClamd)

    assert stage.refresh_version() is False
    assert stage.engine_version == "unavailable"


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_version_is_ignored(blank: str) -> None:
    """Пустой ответ clamd — не повод считать базы обновившимися."""
    client = VersionedClamd("ClamAV 1.4.6/28101")
    stage = ClamavStage(factory=lambda: client)
    stage.warmup()

    client.version_string = blank
    assert stage.refresh_version() is False
    assert stage.engine_version == "ClamAV 1.4.6/28101"
