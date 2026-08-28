"""Лимиты защиты от бомб и переполнения. Единственный источник правды."""

from __future__ import annotations

from typing import Final

MAX_UPLOAD_BYTES: Final[int] = 64 * 1024 * 1024
"""Больше этого не принимаем на вход вовсе."""

MAX_SANITIZED_BYTES: Final[int] = 128 * 1024 * 1024
"""Выход CDR не может быть больше — защита от декомпресс-бомбы на выходе."""

MAX_IMAGE_PIXELS: Final[int] = 80_000_000
"""~80 Мпикс. Дальше Pillow должен отказать, а не аллоцировать гигабайты."""

MAX_PDF_PAGES: Final[int] = 500
MAX_PDF_OBJECTS: Final[int] = 200_000
MAX_PDF_NESTING_DEPTH: Final[int] = 128
"""Порог признака, а не защита.

Защита — итеративный обход с лимитом шагов, ему глубина не вредит. Порог
подобран по реальным документам: медиана 2, p99 = 49. Прежние 32 задевали
обычные многостраничные PDF со вложенными формами.
"""

STAGE_TIMEOUT_S: Final[dict[str, float]] = {
    "filetype": 2.0,
    "structure": 10.0,
    "clamav": 20.0,
    "yara": 10.0,
}

CDR_TIMEOUT_S: Final[dict[str, float]] = {
    "light": 15.0,
    "standard": 60.0,
    "strict": 180.0,
}
