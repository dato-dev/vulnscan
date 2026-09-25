"""Выбор санитайзера по типу и запуск с обязательной верификацией."""

from __future__ import annotations

import logging
from pathlib import Path

from vscommon.models import CdrProfile

from .archive import ZipSanitizer
from .base import SanitizeError, SanitizeOutcome, Sanitizer
from .docx import DocxSanitizer
from .image import ImageSanitizer
from .pdf import PdfSanitizer

logger = logging.getLogger(__name__)

_SANITIZERS: tuple[Sanitizer, ...] = (
    PdfSanitizer(),
    ImageSanitizer(),
    DocxSanitizer(),
    ZipSanitizer(),
)


def find_sanitizer(mime: str | None) -> Sanitizer | None:
    if mime is None:
        return None
    return next((s for s in _SANITIZERS if mime in s.mimes), None)


def sanitize(src: Path, dst_dir: Path, mime: str | None, profile: CdrProfile) -> SanitizeOutcome:
    """Санитизирует и верифицирует. Неподдержанный формат — SanitizeError."""
    sanitizer = find_sanitizer(mime)
    if sanitizer is None:
        raise SanitizeError(f"нет санитайзера для {mime}")

    try:
        outcome = sanitizer.sanitize(src, dst_dir, profile)
    except SanitizeError:
        raise
    except Exception as exc:
        # Парсеры кидают что угодно (UnidentifiedImageError, PdfError, MemoryError).
        # Наружу контракт один: SanitizeError. Иначе конвейер получит verdict=error
        # вместо аккуратного CDR_FAILED.
        logger.warning(
            "санитайзер упал с неожиданной ошибкой",
            extra={"sanitizer": sanitizer.name, "reason": type(exc).__name__},
        )
        raise SanitizeError(f"{sanitizer.name}: {type(exc).__name__}") from exc

    try:
        leftovers = sanitizer.verify(outcome.path)
    except Exception as exc:
        # Не смогли проверить — считаем непроверенным, файл не отдаём.
        outcome.path.unlink(missing_ok=True)
        raise SanitizeError(f"верификация невозможна: {type(exc).__name__}") from exc

    if leftovers:
        # Тихо отдавать такой файл нельзя — это дыра в основной гарантии сервиса.
        logger.error(
            "в санитизированном файле остались активные элементы",
            extra={"sanitizer": sanitizer.name, "profile": profile.value, "left": leftovers},
        )
        outcome.path.unlink(missing_ok=True)
        raise SanitizeError(f"верификация не пройдена: {leftovers}")

    logger.debug(
        "CDR завершён",
        extra={
            "sanitizer": sanitizer.name,
            "profile": profile.value,
            "transforms": len(outcome.transforms),
        },
    )
    return outcome
