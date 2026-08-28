"""Настройка стандартного logging для сервисов.

Единственное место, где трогается конфигурация logging. Библиотечные модули
только берут `logging.getLogger(__name__)` и ничего не настраивают.
"""

from __future__ import annotations

import contextvars
import json
import logging
import logging.config
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from types import MappingProxyType
from typing import Any, Final

from vscommon.telemetry import current_ids

_EMPTY: Final[Mapping[str, Any]] = MappingProxyType({})

_context: contextvars.ContextVar[Mapping[str, Any]] = contextvars.ContextVar(
    "log_context", default=_EMPTY
)

# Поля LogRecord, которые не являются пользовательскими extra-полями.
_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


class ContextFilter(logging.Filter):
    """Добавляет в запись поля из contextvars (scan_id, tenant и т.п.).

    Сюда же попадают идентификаторы текущего спана: без них из трейса в Tempo
    не перейти в логи этого же скана в Loki и обратно.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _context.get().items():
            if not hasattr(record, key):
                setattr(record, key, value)
        ids = current_ids()
        if ids is not None:
            record.trace_id, record.span_id = ids
        return True


class JsonFormatter(logging.Formatter):
    """JSON-строка на запись — формат для прода."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "service": self._service,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class ConsoleFormatter(logging.Formatter):
    """Читаемый формат для локальной разработки."""

    _FMT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        base = logging.Formatter(self._FMT, "%H:%M:%S").format(record)
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED and not key.startswith("_")
        }
        if extras:
            tail = " ".join(f"{k}={v}" for k, v in extras.items())
            base = f"{base}  [{tail}]"
        return base


def setup_logging(service: str, level: str = "INFO", fmt: str = "console") -> None:
    """Конфигурирует root-логгер. Вызывается один раз на старте процесса."""
    formatter: logging.Formatter = JsonFormatter(service) if fmt == "json" else ConsoleFormatter()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(ContextFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Чужие библиотеки не должны шуметь в горячем пути.
    for noisy in ("botocore", "boto3", "urllib3", "s3transfer", "httpx", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True


@contextmanager
def log_context(**fields: Any) -> Iterator[None]:
    """Протаскивает поля во все записи внутри блока.

    Значения должны быть уже безопасными: sha256 усекается вызывающим кодом,
    имена файлов и содержимое сюда не попадают (см. CLAUDE.md).
    """
    token = _context.set(MappingProxyType({**_context.get(), **fields}))
    try:
        yield
    finally:
        _context.reset(token)
