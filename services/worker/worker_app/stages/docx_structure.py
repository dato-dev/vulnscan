"""Разбор документа Word для стадии `structure` (M6.3).

Что ищется и почему именно это — механизмы, которыми документ Word
исполняет код или тянет его по сети при открытии:

* макросы VBA и элементы ActiveX;
* встроенные OLE-объекты — через них шли эксплойты редактора формул;
* поля DDE — выполнение команды без всяких макросов;
* шаблон и объекты по сети — документ чист, а код приезжает при открытии
  (CVE-2017-0199, Follina);
* `altChunk` — вставка RTF или HTML, внутри которых свой набор уязвимостей;
* DTD в XML-частях — в Word его не бывает, это атака на разборщик.

Документ — тоже ZIP, поэтому бюджет распаковки и опись записей у него те же,
что у архива. Но его части — не файлы для проверки: вложениями они не
становятся.
"""

from __future__ import annotations

import logging
import zipfile

from vscommon.limits import MAX_OOXML_PART_BYTES

from .. import ooxml
from ..archive import ArchiveError, BudgetExceededError, inspect, open_archive, read_limited
from .archive_structure import budget_for, mark_incomplete, report
from .base import ScanContext

logger = logging.getLogger(__name__)

REMOTE_PREFIXES = ("http://", "https://", "ftp://", "\\\\", "//", "mhtml:", "ms-")


def is_remote(target: str) -> bool:
    """Цель по сети, а не на диске автора.

    `file:///C:/…` — шаблон с машины автора: Word на другой машине его не
    найдёт, и ничего не загрузит. `file://host/…` и UNC — уже сеть: при
    открытии Windows сама отдаст на такой адрес хэш пароля пользователя.
    """
    lowered = target.strip().lower()
    if lowered.startswith("file://"):
        return not lowered.startswith("file:///")
    return lowered.startswith(REMOTE_PREFIXES)


def where(target: str) -> str:
    """Куда ведёт внешняя связь — без самого адреса.

    Адрес — часть содержимого файла, а подробность признака уходит в ответ и
    в историю проверок.
    """
    lowered = target.strip().lower()
    if lowered.startswith(("\\\\", "//")) or lowered.startswith("file://"):
        return "сетевой путь"
    scheme, sep, _ = lowered.partition(":")
    return f"схема {scheme}" if sep and scheme.isalpha() else "адрес"


def analyse(ctx: ScanContext, stage: str) -> None:
    budget = budget_for(ctx)
    try:
        zf = open_archive(ctx.path)
    except BudgetExceededError as exc:
        mark_incomplete(ctx, stage, str(exc))
        return
    except ArchiveError as exc:
        ctx.supported = False
        ctx.add(stage, "DOCX_MALFORMED", str(exc))
        return

    with zf:
        inventory = inspect(zf, budget, ctx.depth, collect=False)
        report(ctx, stage, inventory)
        if inventory.bomb or inventory.encrypted:
            return
        _analyse_package(ctx, stage, zf)


def _analyse_package(ctx: ScanContext, stage: str, zf: zipfile.ZipFile) -> None:
    names = [info.filename for info in zf.infolist() if not info.is_dir()]
    lowered = [name.lower() for name in names]

    types = _read(ctx, stage, zf, "[Content_Types].xml")
    if types is None:
        return
    content_types = ooxml.content_types(types)

    if any(name.endswith("vbaproject.bin") for name in lowered) or any(
        "vbaproject" in value.lower() for value in content_types.overrides.values()
    ):
        ctx.add(stage, "DOCX_VBA", "проект VBA")
    if any(name.startswith("word/activex/") for name in lowered):
        ctx.add(stage, "DOCX_ACTIVEX", "элементы ActiveX")
    for name in names:
        if not name.lower().startswith("word/embeddings/"):
            continue
        kind = content_types.of(name).lower()
        if name.lower().endswith(".bin") or "oleobject" in kind:
            ctx.add(stage, "DOCX_OLE_OBJECT", "встроенный OLE-объект")
        else:
            ctx.add(stage, "DOCX_EMBEDDED", "встроенный документ")

    for name in names:
        low = name.lower()
        if low.endswith(".rels"):
            part = _read(ctx, stage, zf, name)
            if part is not None:
                for rel in ooxml.relationships(part):
                    _check_relationship(ctx, stage, rel)
        elif low.endswith(".xml") and name != "[Content_Types].xml":
            _check_fields(ctx, stage, zf, name, fields=low.startswith("word/"))


def _read(ctx: ScanContext, stage: str, zf: zipfile.ZipFile, name: str) -> ooxml.Part | None:
    try:
        return ooxml.parse(read_limited(zf, name, MAX_OOXML_PART_BYTES))
    except BudgetExceededError as exc:
        mark_incomplete(ctx, stage, f"часть документа: {exc}")
    except ooxml.DtdError:
        ctx.add(stage, "DOCX_DTD", "DTD в части документа")
    except (ArchiveError, ooxml.XmlError, KeyError) as exc:
        ctx.supported = False
        ctx.add(stage, "DOCX_MALFORMED", type(exc).__name__)
    return None


def _check_relationship(ctx: ScanContext, stage: str, rel: ooxml.Relationship) -> None:
    kind = rel.kind.lower()
    if kind == "vbaproject":
        ctx.add(stage, "DOCX_VBA", "связь с проектом VBA")
    elif kind in ("control", "activexcontrolbinary"):
        ctx.add(stage, "DOCX_ACTIVEX", "связь с элементом ActiveX")
    elif kind == "afchunk":
        ctx.add(stage, "DOCX_ALTCHUNK", "вставка внешнего формата")
    elif not rel.external:
        if kind == "oleobject":
            ctx.add(stage, "DOCX_OLE_OBJECT", "связь с OLE-объектом")
        elif kind == "package":
            ctx.add(stage, "DOCX_EMBEDDED", "встроенный документ")
    elif kind == "hyperlink":
        # Ссылка срабатывает щелчком, а не при открытии, — поэтому обычная
        # веб-ссылка не признак. Но схема решает, что запустит щелчок.
        if not ooxml.safe_hyperlink(rel.target):
            ctx.add(stage, "DOCX_EXTERNAL_LINK", f"гиперссылка, {where(rel.target)}")
    elif kind == "attachedtemplate":
        if is_remote(rel.target):
            ctx.add(stage, "DOCX_EXTERNAL_TEMPLATE", where(rel.target))
    elif kind in ("oleobject", "frame", "subdocument"):
        ctx.add(stage, "DOCX_EXTERNAL_OBJECT", f"{rel.kind}, {where(rel.target)}")
    else:
        ctx.add(stage, "DOCX_EXTERNAL_LINK", f"{rel.kind}, {where(rel.target)}")


def _check_fields(
    ctx: ScanContext, stage: str, zf: zipfile.ZipFile, name: str, *, fields: bool
) -> None:
    """Поля и DTD. Поля ищутся только в частях Word, DTD — во всех."""
    try:
        kinds = set(ooxml.scan_fields(read_limited(zf, name, MAX_OOXML_PART_BYTES)))
    except BudgetExceededError as exc:
        mark_incomplete(ctx, stage, f"часть документа: {exc}")
        return
    except ooxml.DtdError:
        ctx.add(stage, "DOCX_DTD", "DTD в части документа")
        return
    except (ArchiveError, ooxml.XmlError) as exc:
        ctx.supported = False
        ctx.add(stage, "DOCX_MALFORMED", type(exc).__name__)
        return

    if not fields:
        return
    if "dde" in kinds:
        ctx.add(stage, "DOCX_DDE", "поле DDE")
    if "obfuscated" in kinds:
        ctx.add(stage, "DOCX_FIELD_OBFUSCATED", "имя поля вычисляется другим полем")
    if "include" in kinds:
        ctx.add(stage, "DOCX_FIELD_INCLUDE", "поле подгружает внешний файл")
    if "altchunk" in kinds:
        ctx.add(stage, "DOCX_ALTCHUNK", "вставка внешнего формата")
    if "ole" in kinds:
        ctx.add(stage, "DOCX_OLE_OBJECT", "OLE-объект в разметке")
    if "control" in kinds:
        ctx.add(stage, "DOCX_ACTIVEX", "элемент управления в разметке")
