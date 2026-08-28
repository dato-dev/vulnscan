"""Контракт санитайзера.

Правило из CLAUDE.md: санитайзер всегда собирает НОВЫЙ файл, а результат
обязан пройти verify_sanitized().
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from pathlib import Path

from vscommon.models import CdrProfile

logger = logging.getLogger(__name__)


class SanitizeError(RuntimeError):
    """CDR не смог собрать безопасный файл. Отдавать исходник нельзя."""


@dataclass(slots=True)
class SanitizeOutcome:
    path: Path
    content_type: str
    transforms: list[str] = field(default_factory=list)


class Sanitizer(abc.ABC):
    """Один санитайзер на семейство форматов."""

    name: str
    mimes: frozenset[str]

    @abc.abstractmethod
    def sanitize(self, src: Path, dst_dir: Path, profile: CdrProfile) -> SanitizeOutcome:
        """Блокирующая работа. Вызывается через asyncio.to_thread."""

    @abc.abstractmethod
    def verify(self, path: Path) -> list[str]:
        """Возвращает список активных элементов, оставшихся в выходном файле."""
