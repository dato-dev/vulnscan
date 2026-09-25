"""Что видит YARA: файл целиком и, у документа Word, каждую его часть.

Документ Word — это ZIP, и его XML-части сжаты. Правило по сырым байтам
документа видит сжатый поток и не находит ничего: ни строки из шаблона, ни
атрибута объекта. Поэтому части отдаются правилам распакованными, по одной,
с именем в внешней переменной `part` — правило может спросить, в какой части
оно сработало.

Архив так не разворачивается: его записи — отдельные файлы, и каждая
проходит все стадии сама (`Pipeline._expand`), YARA в том числе.

Модуль общий для стадии и для шлюза выкатки (`rules/check.py`): правило,
проверенное шлюзом, должно видеть ровно то же, что увидит в работе.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from vscommon.limits import MAX_OOXML_PART_BYTES, MAX_UNPACKED_BYTES

from .archive import ArchiveError, open_archive, read_limited
from .stages.filetype_detect import DOCX_MIMES

logger = logging.getLogger(__name__)

EXTERNALS: dict[str, str] = {"part": ""}
"""Внешние переменные правил и их значения по умолчанию.

Объявляются при компиляции всего набора: правило, которое спрашивает `part`,
без объявления не компилируется. У файла целиком `part` пустая.
"""


def views(path: Path, mime: str | None) -> Iterator[tuple[str, bytes | None]]:
    """(имя части, байты). Первым — сам файл: `("", None)`, читать по пути.

    Часть больше предела пропускается молча не потому, что это нормально: её
    уже отметил разбор структуры (`ARCHIVE_INCOMPLETE`), и вердикт от этого
    не `clean`. Бомбу этот обход тоже не распакует: заявленные размеры
    суммируются до чтения, а настоящие режет `read_limited`.
    """
    yield "", None
    if mime not in DOCX_MIMES:
        return
    try:
        zf = open_archive(path)
    except ArchiveError:
        return
    with zf:
        total = 0
        for info in zf.infolist():
            if info.is_dir() or info.file_size > MAX_OOXML_PART_BYTES:
                continue
            total += info.file_size
            if total > MAX_UNPACKED_BYTES:
                return
            try:
                data = read_limited(zf, info.filename, MAX_OOXML_PART_BYTES)
            except ArchiveError:
                continue
            yield info.filename, data
