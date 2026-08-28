"""Решение о повторе: ретраить задачу или закрывать её сразу (ROADMAP M1.3)."""

from __future__ import annotations

import logging

from vscommon.errors import ErrorKind, classify
from vscommon.journal import Attempt

logger = logging.getLogger(__name__)

RISKY_STAGES = frozenset({"structure", "yara", "cdr"})
"""Стадии, где недоверенный файл попадает в C-код.

pikepdf, Pillow и yara-python могут уронить процесс целиком — не исключением,
а segfault'ом. Если предыдущая попытка оборвалась на одной из этих стадий,
причина в самом файле. Стадия `clamav` сюда не входит: разбор идёт в чужом
процессе, упасть вместе с нами он не может.
"""


def crashed_on_content(previous: Attempt, max_crashes: int) -> bool:
    """Предыдущая попытка умерла жёстко внутри разбора этого файла.

    `max_crashes` — сколько таких обрывов терпим, прежде чем признать файл
    неперевариваемым. Единица означает «закрываем после первого». Больше
    единицы имеет смысл там, где воркеров регулярно вытесняет планировщик:
    OOM-kill по вине соседа выглядит так же, как краш парсера.
    """
    if previous.stage not in RISKY_STAGES:
        # Оборвались до разбора — виновата инфраструктура, а не файл.
        return False
    return previous.attempt >= max_crashes


def should_retry(exc: BaseException) -> bool:
    """Питоновское исключение: повторять попытку или закрывать задачу."""
    kind = classify(exc)
    logger.debug(
        "классификация ошибки",
        extra={"kind": kind.value, "exc": type(exc).__name__},
    )
    return kind is ErrorKind.INFRA
