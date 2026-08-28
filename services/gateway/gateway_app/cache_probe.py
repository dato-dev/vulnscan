"""Исход просмотра двухуровневого кэша перед постановкой задачи.

Три варианта: результат готов целиком, готова только структурная часть
(воркеру останется антивирус), не готово ничего.
"""

from __future__ import annotations

from dataclasses import dataclass

from vscommon.models import CachedStructural, ScanResult


@dataclass(slots=True)
class CacheProbe:
    result: ScanResult | None = None
    """Полный хит: отвечаем сразу."""

    structural: CachedStructural | None = None
    """Частичный хит: задачу ставим, но воркер прогонит только антивирус."""

    @property
    def hit(self) -> bool:
        return self.result is not None
