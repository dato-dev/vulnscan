"""Возраст сигнатур и правил.

Остановившееся обновление выглядит ровно как работающее: clamd доволен базой,
которую нашёл при старте, и о её возрасте не сообщает. Вердикт `clean` при этом
выдаётся по сигнатурам недельной давности — и снаружи это неотличимо от честной
проверки.

Тот же приём, которым чинили молча недоступный clamd: проблема не в весе
признака, а в том, что проверку нельзя считать состоявшейся.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

logger = logging.getLogger(__name__)

_CLAMAV_VERSION_RE: Final = re.compile(r"^ClamAV\s+(?P<engine>[^/]+)/(?P<db>\d+)/(?P<built>.+)$")
"""`ClamAV 1.4.6/28101/Sun Aug 23 06:26:53 2026` — дата базы лежит третьим полем.

Разбор строки, а не отдельный запрос: clamd и так отдаёт дату в версии, а
лишний способ узнать то же самое — лишний способ разойтись.
"""

_BUILT_FORMAT: Final = "%a %b %d %H:%M:%S %Y"

HOUR: Final = 3600.0
DAY: Final = 24 * HOUR


class Freshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    """Обновление отстаёт. Проверять можно, но пора разбираться."""
    EXPIRED = "expired"
    """Отстаёт настолько, что проверке верить нельзя."""
    UNKNOWN = "unknown"
    """Возраст неизвестен — считаем это отказом, а не мелочью."""


@dataclass(frozen=True, slots=True)
class Age:
    seconds: float | None
    state: Freshness

    @property
    def hours(self) -> float | None:
        return None if self.seconds is None else round(self.seconds / HOUR, 1)

    @property
    def usable(self) -> bool:
        """Можно ли считать проверку состоявшейся."""
        return self.state in (Freshness.FRESH, Freshness.STALE)


def parse_clamav_built_at(version: str) -> float | None:
    """Момент сборки базы из строки версии clamd. `None` — разобрать не вышло.

    Формат чужой и может измениться; неразобранная строка это `unknown`, а не
    исключение — иначе смена формата у вендора роняла бы готовность сервиса.
    """
    match = _CLAMAV_VERSION_RE.match(version.strip())
    if match is None:
        return None
    try:
        built = datetime.strptime(match.group("built").strip(), _BUILT_FORMAT)
    except ValueError:
        return None
    return built.replace(tzinfo=UTC).timestamp()


def age_of(
    built_at: float | None,
    *,
    stale_after_s: float = DAY,
    expired_after_s: float = 7 * DAY,
    now: float | None = None,
) -> Age:
    """Возраст и что о нём думать.

    Отрицательный возраст (часы разошлись, база «из будущего») считается
    свежестью: расхождение часов — не повод останавливать проверку файлов.
    """
    if built_at is None:
        return Age(seconds=None, state=Freshness.UNKNOWN)

    seconds = max((now if now is not None else time.time()) - built_at, 0.0)
    if seconds >= expired_after_s:
        state = Freshness.EXPIRED
    elif seconds >= stale_after_s:
        state = Freshness.STALE
    else:
        state = Freshness.FRESH
    return Age(seconds=seconds, state=state)
