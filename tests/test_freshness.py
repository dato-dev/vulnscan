"""Возраст сигнатур: остановившееся обновление должно быть видно снаружи.

Это тот же принцип, которым чинили молча недоступный clamd: проблема не в весе
признака, а в том, что проверку нельзя считать состоявшейся.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vscommon.freshness import DAY, HOUR, Freshness, age_of, parse_clamav_built_at


def _at(day: int, hour: int = 12) -> float:
    return datetime(2026, 8, day, hour, tzinfo=UTC).timestamp()


def test_parses_real_clamd_version() -> None:
    """Строка снята с боевого clamd."""
    built = parse_clamav_built_at("ClamAV 1.4.6/28101/Sun Aug 23 06:26:53 2026")

    assert built is not None
    assert datetime.fromtimestamp(built, UTC).date() == datetime(2026, 8, 23, tzinfo=UTC).date()


@pytest.mark.parametrize(
    "version",
    ["", "мусор", "ClamAV 1.4.6", "ClamAV 1.4.6/28101", "ClamAV 1.4.6/28101/не дата"],
)
def test_unparsable_version_is_unknown(version: str) -> None:
    """Формат чужой и может измениться.

    Смена формата у вендора не должна ронять готовность сервиса — она делает
    возраст неизвестным, а это отдельное состояние.
    """
    assert parse_clamav_built_at(version) is None


def test_fresh_database() -> None:
    age = age_of(_at(28, 6), now=_at(28, 12))

    assert age.state is Freshness.FRESH
    assert age.usable


def test_day_old_database_is_stale() -> None:
    """Сутки — предупреждение: проверять можно, но пора разбираться."""
    age = age_of(_at(27), now=_at(28))

    assert age.state is Freshness.STALE
    assert age.usable, "предупреждение не должно останавливать проверку файлов"


def test_week_old_database_is_expired() -> None:
    """Неделя — отказ. `clean` по таким сигнатурам ничего не значит."""
    age = age_of(_at(21), now=_at(28))

    assert age.state is Freshness.EXPIRED
    assert not age.usable


def test_unknown_age_is_not_usable() -> None:
    """Молчание — не «свежо».

    Отсутствие значения означает, что воркер мог не запуститься вовсе, то есть
    проверять файлы некому. Считать это исправностью — ровно та ошибка, из-за
    которой недоступный clamd когда-то выдавал `clean` на всё подряд.
    """
    age = age_of(None)

    assert age.state is Freshness.UNKNOWN
    assert not age.usable


def test_clock_skew_does_not_break_service() -> None:
    """База «из будущего» — это расхождение часов, а не повод остановиться."""
    age = age_of(_at(29), now=_at(28))

    assert age.seconds == 0.0
    assert age.state is Freshness.FRESH


def test_thresholds_are_configurable() -> None:
    age = age_of(_at(27), now=_at(28), stale_after_s=48 * HOUR, expired_after_s=14 * DAY)

    assert age.state is Freshness.FRESH


def test_age_is_reported_in_hours() -> None:
    """В /readyz уходят часы: секунды там читать неудобно."""
    assert age_of(_at(27), now=_at(28)).hours == 24.0
