"""CDR для документов Word (M6.4).

Два разных подхода, как и у PDF.

**`light` и `standard`** — пересборка пакета по списку разрешённых частей.
Не «удалили макросы», а «взяли только то, что знаем»: текст, стили,
колонтитулы, сноски, картинки, диаграммы. Всё прочее — проект VBA, ActiveX,
встроенные объекты, шрифты, стандартные блоки — в выход не попадает, потому
что не попадает в список, а не потому, что мы его опознали. Каждая XML-часть
разбирается и записывается заново; связи с выброшенными частями и внешние
связи (кроме гиперссылок) удаляются вместе с разметкой, которая на них
ссылается; коды полей вне разрешённого списка заменяются результатом.

**`strict`** — безопасен by construction. Документ собирается с нуля из
текста, простых признаков оформления и перекодированных пикселей картинок.
Ни одной части, ни одного элемента исходника в выходе нет, поэтому
утверждение «активного содержимого нет» не зависит от того, что было во
входе. Это аналог растеризации PDF: без движка отрисовки Word честная
растеризация невозможна, а собранный из текста документ даёт ту же
гарантию. Цена — оформление: остаются абзацы, таблицы, картинки,
полужирный, курсив, подчёркивание и выравнивание.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

from vscommon.limits import MAX_IMAGE_PIXELS, MAX_OOXML_PART_BYTES, MAX_SANITIZED_BYTES
from vscommon.models import CdrProfile

from .. import ooxml
from ..archive import ArchiveError, UnpackBudget, inspect, open_archive, read_limited
from ..stages.filetype_detect import DOCM_MIME, DOCX_MIME, DOCX_MIMES
from .base import SanitizeError, SanitizeOutcome, Sanitizer

logger = logging.getLogger(__name__)

W = ooxml.W
R = ooxml.R
WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC = "http://schemas.openxmlformats.org/drawingml/2006/picture"
C = "http://schemas.openxmlformats.org/drawingml/2006/chart"
w = ooxml.w

REL_OFFICE_DOCUMENT = ooxml.REL + "officeDocument"
REL_IMAGE = ooxml.REL + "image"
RELS_TYPE = "application/vnd.openxmlformats-package.relationships+xml"

_PARTS = (
    r"word/(document|styles|stylesWithEffects|settings|webSettings|fontTable|numbering"
    r"|footnotes|endnotes|comments|commentsExtended|commentsIds|commentsExtensible|people)\.xml",
    r"word/(header|footer)\d+\.xml",
    r"word/theme/theme\d+\.xml",
    r"word/charts/(chart|style|colors)\d+\.xml",
    r"word/media/[^/]+\.(png|jpe?g|gif|bmp|emf|wmf|tiff?)",
)
_METADATA_PARTS = (
    r"docProps/(core|app|custom)\.xml",
    r"customXml/(item|itemProps)\d+\.xml",
)

KEPT = [re.compile(pattern, re.IGNORECASE) for pattern in _PARTS]
KEPT_LIGHT = KEPT + [re.compile(pattern, re.IGNORECASE) for pattern in _METADATA_PARTS]
"""Что переносится в выход. Список разрешённого, а не запрещённого: новая
часть, о которой мы не знаем, в выход не попадёт сама собой."""

MEDIA_TYPES = {
    "png": "image/png",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "emf": "image/x-emf",
    "wmf": "image/x-wmf",
    "tif": "image/tiff",
    "tiff": "image/tiff",
}
REENCODED = {"png": "PNG", "jpeg": "JPEG", "jpg": "JPEG", "gif": "GIF"}

UNITS = frozenset(
    {
        w("drawing"),
        w("pict"),
        w("object"),
        w("altChunk"),
        w("attachedTemplate"),
        w("embedRegular"),
        w("embedBold"),
        w("embedItalic"),
        w("embedBoldItalic"),
        w("subDoc"),
        w("control"),
        f"{{{C}}}externalData",
        f"{{{C}}}userShapes",
    }
)
"""Что убирать целиком, когда внутри оборвана связь.

Удалить один атрибут `r:embed` мало: картинка без источника — это разметка,
которую Word объявит повреждённой. Убирается ближайший осмысленный целый
элемент — рисунок, объект, вставка.
"""

ALWAYS_DROPPED = frozenset({w("mailMerge"), w("frameset"), w("docVars")})
"""Источник данных слияния — запрос к внешней базе; набор фреймов — загрузка
страниц при открытии; переменные документа — хранилище макросов, куда кладут
полезную нагрузку (`docx_docvar_payload`). Макросов в выходе нет, значит, и
читать переменные некому."""

MAX_STRICT_IMAGES = 500
EMU_LIMIT = 20 * 914400
"""Размер картинки на странице, в EMU: не больше 50 см по стороне."""


def _macro(main_type: str) -> bool:
    return "macroenabled" in main_type.lower()


class DocxSanitizer(Sanitizer):
    name = "docx"
    mimes = DOCX_MIMES

    def sanitize(self, src: Path, dst_dir: Path, profile: CdrProfile) -> SanitizeOutcome:
        with open_archive(src) as zin:
            inventory = inspect(zin, UnpackBudget(root_size=src.stat().st_size), 0, collect=False)
            if inventory.bomb or inventory.encrypted or inventory.incomplete:
                raise SanitizeError("документ не распаковывается в пределах бюджета")
            main, main_type = _main_part(zin)
            # Макросов в выходе нет, но тип документа сохраняется: `.docm`
            # с типом обычного документа Word откажется открывать вовсе.
            suffix, mime = (".docm", DOCM_MIME) if _macro(main_type) else (".docx", DOCX_MIME)
            dst = dst_dir / f"clean{suffix}"
            if profile is CdrProfile.STRICT:
                transforms = _Strict(zin, main, main_type).build(dst)
            else:
                transforms = _rebuild(zin, main, main_type, dst, profile)

        if dst.stat().st_size > MAX_SANITIZED_BYTES:
            dst.unlink(missing_ok=True)
            raise SanitizeError("выход CDR превысил лимит размера")
        return SanitizeOutcome(path=dst, content_type=mime, transforms=sorted(set(transforms)))

    def verify(self, path: Path) -> list[str]:
        """Активное содержимое, оставшееся в выходе.

        Проверяется независимо от того, как выход собран: и состав частей, и
        типы содержимого, и связи, и поля в каждой XML-части.
        """
        problems: set[str] = set()
        with open_archive(path) as zf:
            inventory = inspect(zf, UnpackBudget(root_size=path.stat().st_size), 0, collect=False)
            problems.update(code for code, _ in inventory.problems)
            if inventory.incomplete:
                problems.add("incomplete")
            names = [info.filename for info in zf.infolist() if not info.is_dir()]
            for name in names:
                if name.endswith(".rels") or name == "[Content_Types].xml":
                    continue
                if not any(pattern.fullmatch(name) for pattern in KEPT_LIGHT):
                    problems.add(f"part:{PurePosixPath(name).parent}")

            types = ooxml.content_types(_parse(zf, "[Content_Types].xml"))
            for value in [*types.defaults.values(), *types.overrides.values()]:
                lowered = value.lower()
                if any(bad in lowered for bad in ("vbaproject", "activex", "oleobject")):
                    problems.add(f"content_type:{value}")
            if types.of("word/document.xml") not in ooxml.MAIN_TYPES:
                problems.add("main_type")

            for name in names:
                if name.endswith(".rels"):
                    for rel in ooxml.relationships(_parse(zf, name)):
                        if rel.external and (
                            rel.kind.lower() != "hyperlink" or not ooxml.safe_hyperlink(rel.target)
                        ):
                            problems.add(f"external:{rel.kind}")
                elif name.lower().endswith(".xml") and name != "[Content_Types].xml":
                    raw = read_limited(zf, name, MAX_OOXML_PART_BYTES)
                    try:
                        kinds = set(ooxml.scan_fields(raw))
                    except ooxml.DtdError:
                        problems.add("dtd")
                        continue
                    # Разрешённые поля остаются; всё прочее — поле вне списка
                    # или элемент вроде OLE-объекта — пересборка убрать обязана.
                    problems.update(f"active:{kind}" for kind in kinds - {"safe"})
        return sorted(problems)


def _parse(zf: zipfile.ZipFile, name: str) -> ooxml.Part:
    try:
        return ooxml.parse(read_limited(zf, name, MAX_OOXML_PART_BYTES))
    except (ArchiveError, ooxml.XmlError, KeyError) as exc:
        raise SanitizeError(f"часть {name} не разбирается: {type(exc).__name__}") from exc


def _main_part(zf: zipfile.ZipFile) -> tuple[str, str]:
    """Основная часть документа и её тип.

    Путь берётся из связей пакета, но принимается только стандартный:
    документ, у которого основная часть лежит где-то ещё, собран не Word'ом,
    и угадывать, как его прочтёт Word, мы не будем.
    """
    package = ooxml.relationships(_parse(zf, "_rels/.rels"))
    targets = [
        ooxml.resolve("", rel.target)
        for rel in package
        if rel.type == REL_OFFICE_DOCUMENT and not rel.external
    ]
    if targets != ["word/document.xml"]:
        raise SanitizeError("основная часть документа не на своём месте")
    main_type = ooxml.content_types(_parse(zf, "[Content_Types].xml")).of("word/document.xml")
    if main_type not in ooxml.MAIN_TYPES:
        raise SanitizeError("неизвестный тип основной части")
    return "word/document.xml", main_type


# --- light и standard: пересборка по списку разрешённого ---


def _category(name: str) -> str:
    lowered = name.lower()
    for marker, transform in (
        ("vba", "drop_vba"),
        ("activex/", "drop_activex"),
        ("embeddings/", "drop_embeddings"),
        ("fonts/", "drop_fonts"),
        ("glossary/", "drop_glossary"),
        ("docprops/", "strip_metadata"),
        ("customxml/", "strip_metadata"),
    ):
        if marker in lowered:
            return transform
    return "drop_parts"


def _rebuild(
    zin: zipfile.ZipFile, main: str, main_type: str, dst: Path, profile: CdrProfile
) -> list[str]:
    patterns = KEPT_LIGHT if profile is CdrProfile.LIGHT else KEPT
    names = [info.filename for info in zin.infolist() if not info.is_dir()]
    transforms = {"rebuild_package"}

    keep: set[str] = set()
    for name in names:
        if name.endswith(".rels") or name == "[Content_Types].xml":
            continue
        if any(pattern.fullmatch(name) for pattern in patterns):
            keep.add(name)
        else:
            transforms.add(_category(name))
    if main not in keep:
        raise SanitizeError("основная часть не попала в выход")

    media: dict[str, bytes] = {}
    for name in sorted(keep):
        if not name.lower().startswith("word/media/"):
            continue
        ext = PurePosixPath(name).suffix.lower().lstrip(".")
        data = read_limited(zin, name, MAX_OOXML_PART_BYTES)
        if ext in REENCODED:
            clean = _reencode(data, REENCODED[ext])
            if clean is None:
                # Не декодируется — не переносим, а связь на неё уйдёт ниже.
                keep.discard(name)
                transforms.add("drop_broken_images")
                continue
            data = clean
            transforms.add("reencode_images")
        media[name] = data

    source_types = ooxml.content_types(_parse(zin, "[Content_Types].xml"))
    rels_out: dict[str, bytes] = {}
    removed: dict[str, set[str]] = {}
    for source in ["", *sorted(keep)]:
        rels = ooxml.rels_name(source)
        if rels not in names:
            continue
        part = _parse(zin, rels)
        gone: set[str] = set()
        for element in list(part.root):
            rel = ooxml.Relationship(
                id=element.get("Id", ""),
                type=element.get("Type", ""),
                target=element.get("Target", ""),
                external=element.get("TargetMode", "").lower() == "external",
            )
            if rel.external:
                # Гиперссылка остаётся, только если щелчок по ней открывает
                # страницу или письмо, а не запускает что-то.
                drop = rel.kind.lower() != "hyperlink" or not ooxml.safe_hyperlink(rel.target)
            else:
                drop = ooxml.resolve(source, rel.target) not in keep
            if drop:
                part.root.remove(element)
                gone.add(rel.id)
                transforms.add("drop_external_links" if rel.external else "drop_relationships")
        removed[source] = gone
        rels_out[rels] = ooxml.serialize(part)

    with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        zout.writestr(
            _entry("[Content_Types].xml"),
            _content_types(keep, main, main_type, source_types),
        )
        for rels, data in sorted(rels_out.items()):
            zout.writestr(_entry(rels), data)
        for name in sorted(keep):
            if name in media:
                zout.writestr(_entry(name), media[name])
                continue
            part = _parse(zin, name)
            _clean(part, removed.get(name, set()), transforms)
            zout.writestr(_entry(name), ooxml.serialize(part))
    return sorted(transforms)


def _entry(name: str) -> zipfile.ZipInfo:
    """Запись без следов исходника: фиксированная дата, без комментариев."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _content_types(keep: set[str], main: str, main_type: str, source: ooxml.ContentTypes) -> bytes:
    """Типы содержимого собираются заново, а не копируются.

    Исходный `[Content_Types].xml` объявлял бы типы частей, которых в выходе
    нет, — в том числе проект VBA.
    """
    root = ET.Element(f"{{{ooxml.CONTENT_TYPES}}}Types")
    extensions = {"rels": RELS_TYPE, "xml": "application/xml"}
    for name in keep:
        ext = PurePosixPath(name).suffix.lower().lstrip(".")
        if ext in MEDIA_TYPES:
            extensions[ext] = MEDIA_TYPES[ext]
    for ext, value in sorted(extensions.items()):
        ET.SubElement(root, f"{{{ooxml.CONTENT_TYPES}}}Default", Extension=ext, ContentType=value)
    for name in sorted(keep):
        if not name.lower().endswith(".xml"):
            continue
        value = main_type if name == main else source.of(name)
        if name != main and not _plain_xml_type(value):
            continue  # останется `application/xml` по умолчанию
        ET.SubElement(
            root, f"{{{ooxml.CONTENT_TYPES}}}Override", PartName=f"/{name}", ContentType=value
        )
    return ooxml.serialize(ooxml.Part(root=root, prefixes={ooxml.CONTENT_TYPES: ""}))


def _plain_xml_type(value: str) -> bool:
    lowered = value.lower()
    return (
        lowered.endswith("+xml")
        and "macro" not in lowered
        and not any(bad in lowered for bad in ("vba", "activex", "oleobject"))
    )


def _clean(part: ooxml.Part, removed_ids: set[str], transforms: set[str]) -> None:
    up = ooxml.parents(part.root)

    doomed: list[ET.Element] = []
    unwrap: list[ET.Element] = []
    if removed_ids:
        for element in part.root.iter():
            if not any(
                key.startswith(f"{{{R}}}") and value in removed_ids
                for key, value in element.attrib.items()
            ):
                continue
            if element.tag == w("hyperlink"):
                unwrap.append(element)
                continue
            doomed.append(_unit(element, up))
    doomed.extend(e for e in part.root.iter() if e.tag in ALWAYS_DROPPED)

    for element in unwrap:
        ooxml.unwrap(element, up)
    for element in doomed:
        if element is part.root:
            raise SanitizeError("связь оборвана у корня части")
        parent = up.get(element)
        if parent is not None and element in list(parent):
            parent.remove(element)
    if doomed:
        transforms.add("drop_objects")

    if ooxml.strip_fields(part.root, keep_safe=True):
        transforms.add("drop_fields")


def _unit(element: ET.Element, up: dict[ET.Element, ET.Element]) -> ET.Element:
    current = element
    for _ in range(12):
        if current.tag in UNITS:
            return current
        parent = up.get(current)
        if parent is None:
            break
        current = parent
    return element


def _reencode(data: bytes, fmt: str) -> bytes | None:
    """Пиксели в новый файл того же формата. Не декодируется — `None`."""
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.load()
            if fmt in ("JPEG", "GIF"):
                raster = img.convert("RGB")
            else:
                raster = img.convert("RGBA" if "A" in img.getbands() or img.mode == "P" else "RGB")
            clean = Image.frombytes(raster.mode, raster.size, raster.tobytes())
            out = io.BytesIO()
            clean.save(out, format=fmt, **({"quality": 90} if fmt == "JPEG" else {}))
            return out.getvalue()
    except Exception as exc:
        logger.debug("картинка документа не декодируется", extra={"reason": type(exc).__name__})
        return None


# --- strict: документ с нуля ---


class _Strict:
    """Собирает новый документ из текста и пикселей исходного."""

    def __init__(self, zin: zipfile.ZipFile, main: str, main_type: str) -> None:
        self._zin = zin
        self._main = main
        self._main_type = main_type
        self._images: list[bytes] = []
        self._transforms = {"rebuild_from_text"}
        self._up: dict[ET.Element, ET.Element] = {}
        self._rels: dict[str, str] = {}

    def build(self, dst: Path) -> list[str]:
        source = _parse(self._zin, self._main)
        # Коды полей снимаются до извлечения текста: иначе в текст попал бы
        # результат поля, вложенного в инструкцию другого, — строка, которую
        # автор никогда не видел.
        ooxml.strip_fields(source.root, keep_safe=False)
        self._up = ooxml.parents(source.root)
        self._rels = {
            rel.id: ooxml.resolve(self._main, rel.target)
            for rel in (
                ooxml.relationships(_parse(self._zin, ooxml.rels_name(self._main)))
                if ooxml.rels_name(self._main) in self._zin.namelist()
                else []
            )
            if not rel.external and rel.type == REL_IMAGE
        }

        body = ET.Element(w("body"))
        source_body = source.root.find(w("body"))
        if source_body is not None:
            for block in source_body:
                if block.tag == w("p"):
                    body.append(self._paragraph(block))
                elif block.tag == w("tbl"):
                    body.append(self._table(block))
                elif block.tag == w("sdt"):
                    body.extend(self._paragraph(p) for p in block.iter(w("p")))
            body.append(self._section(source_body.find(w("sectPr"))))

        document = ET.Element(w("document"))
        document.append(body)
        prefixes = {W: "w", R: "r", WP: "wp", A: "a", PIC: "pic"}

        with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            zout.writestr(_entry("[Content_Types].xml"), self._content_types())
            zout.writestr(_entry("_rels/.rels"), self._package_rels())
            main = ooxml.serialize(ooxml.Part(document, prefixes))
            zout.writestr(_entry("word/document.xml"), main)
            if self._images:
                zout.writestr(_entry("word/_rels/document.xml.rels"), self._document_rels())
            for index, data in enumerate(self._images, start=1):
                zout.writestr(_entry(f"word/media/image{index}.jpeg"), data)
        return sorted(self._transforms)

    def _skipped(self, element: ET.Element) -> bool:
        """Удалённый в режиме правок текст в выход не идёт."""
        current: ET.Element | None = element
        for _ in range(8):
            if current is None:
                return False
            if current.tag in (w("del"), w("moveFrom")):
                return True
            current = self._up.get(current)
        return False

    def _paragraph(self, source: ET.Element) -> ET.Element:
        paragraph = ET.Element(w("p"))
        align = source.find(f"{w('pPr')}/{w('jc')}")
        if align is not None and align.get(w("val")) in ("left", "center", "right", "both"):
            props = ET.SubElement(paragraph, w("pPr"))
            ET.SubElement(props, w("jc"), {w("val"): str(align.get(w("val")))})

        for run in source.iter(w("r")):
            if self._skipped(run):
                continue
            out = ET.Element(w("r"))
            self._format(run, out)
            for child in run:
                if child.tag == w("t") and child.text:
                    text = ET.SubElement(out, w("t"), {f"{{{ooxml.XML_NS}}}space": "preserve"})
                    text.text = child.text
                elif child.tag == w("tab"):
                    ET.SubElement(out, w("tab"))
                elif child.tag in (w("br"), w("cr")):
                    ET.SubElement(out, w("br"))
                elif child.tag == w("drawing"):
                    drawing = self._drawing(child)
                    if drawing is not None:
                        out.append(drawing)
            if len(out):
                paragraph.append(out)
        return paragraph

    @staticmethod
    def _format(source: ET.Element, out: ET.Element) -> None:
        props = source.find(w("rPr"))
        if props is None:
            return
        flags = []
        for tag in ("b", "i"):
            flag = props.find(w(tag))
            if flag is not None and flag.get(w("val"), "true") not in ("0", "false", "off"):
                flags.append(tag)
        underline = props.find(w("u"))
        if underline is not None and underline.get(w("val"), "single") != "none":
            flags.append("u")
        if flags:
            new_props = ET.SubElement(out, w("rPr"))
            for tag in flags:
                ET.SubElement(new_props, w(tag), {w("val"): "single"} if tag == "u" else {})

    def _table(self, source: ET.Element) -> ET.Element:
        rows = []
        for row in source.findall(w("tr")):
            rows.append([self._cell(cell) for cell in row.findall(w("tc"))])
        width = max((len(row) for row in rows), default=1) or 1

        table = ET.Element(w("tbl"))
        props = ET.SubElement(table, w("tblPr"))
        ET.SubElement(props, w("tblW"), {w("w"): "0", w("type"): "auto"})
        borders = ET.SubElement(props, w("tblBorders"))
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            ET.SubElement(borders, w(side), {w("val"): "single", w("sz"): "4"})
        grid = ET.SubElement(table, w("tblGrid"))
        for _ in range(width):
            ET.SubElement(grid, w("gridCol"), {w("w"): str(9000 // width)})
        for cells in rows:
            row_out = ET.SubElement(table, w("tr"))
            # Каждой строке — полная сетка: ячейка без абзаца, как и строка
            # короче сетки, для Word — повреждённый документ.
            for index in range(width):
                tc = ET.SubElement(row_out, w("tc"))
                cell = cells[index] if index < len(cells) else []
                tc.extend(cell or [ET.Element(w("p"))])
        return table

    def _cell(self, source: ET.Element) -> list[ET.Element]:
        """Содержимое ячейки абзацами. Вложенные таблицы разворачиваются в текст."""
        return [self._paragraph(p) for p in source.iter(w("p"))]

    def _drawing(self, source: ET.Element) -> ET.Element | None:
        blip = next(source.iter(f"{{{A}}}blip"), None)
        extent = next(source.iter(f"{{{WP}}}extent"), None)
        if blip is None or extent is None or len(self._images) >= MAX_STRICT_IMAGES:
            return None
        target = self._rels.get(blip.get(f"{{{R}}}embed", ""))
        if target is None:
            return None
        try:
            data = read_limited(self._zin, target, MAX_OOXML_PART_BYTES)
        except (ArchiveError, KeyError):
            return None
        clean = _reencode(data, "JPEG")
        if clean is None:
            self._transforms.add("drop_broken_images")
            return None
        self._images.append(clean)
        self._transforms.add("reencode_images")
        index = len(self._images)
        cx, cy = _emu(extent.get("cx")), _emu(extent.get("cy"))

        drawing = ET.Element(w("drawing"))
        inline = ET.SubElement(drawing, f"{{{WP}}}inline")
        ET.SubElement(inline, f"{{{WP}}}extent", cx=cx, cy=cy)
        ET.SubElement(inline, f"{{{WP}}}docPr", id=str(index), name=f"Picture {index}")
        graphic = ET.SubElement(inline, f"{{{A}}}graphic")
        data_el = ET.SubElement(graphic, f"{{{A}}}graphicData", uri=PIC)
        pic = ET.SubElement(data_el, f"{{{PIC}}}pic")
        nv = ET.SubElement(pic, f"{{{PIC}}}nvPicPr")
        ET.SubElement(nv, f"{{{PIC}}}cNvPr", id=str(index), name=f"image{index}.jpeg")
        ET.SubElement(nv, f"{{{PIC}}}cNvPicPr")
        fill = ET.SubElement(pic, f"{{{PIC}}}blipFill")
        ET.SubElement(fill, f"{{{A}}}blip", {f"{{{R}}}embed": f"rIdImage{index}"})
        stretch = ET.SubElement(fill, f"{{{A}}}stretch")
        ET.SubElement(stretch, f"{{{A}}}fillRect")
        shape = ET.SubElement(pic, f"{{{PIC}}}spPr")
        xfrm = ET.SubElement(shape, f"{{{A}}}xfrm")
        ET.SubElement(xfrm, f"{{{A}}}off", x="0", y="0")
        ET.SubElement(xfrm, f"{{{A}}}ext", cx=cx, cy=cy)
        geometry = ET.SubElement(shape, f"{{{A}}}prstGeom", prst="rect")
        ET.SubElement(geometry, f"{{{A}}}avLst")
        return drawing

    @staticmethod
    def _section(source: ET.Element | None) -> ET.Element:
        """Размер страницы переносится числами; всё остальное — по умолчанию."""
        section = ET.Element(w("sectPr"))
        width, height = "11906", "16838"  # A4 в twip
        size = source.find(w("pgSz")) if source is not None else None
        if size is not None:
            width = _twip(size.get(w("w")), width)
            height = _twip(size.get(w("h")), height)
        ET.SubElement(section, w("pgSz"), {w("w"): width, w("h"): height})
        margin = {w(side): "1134" for side in ("top", "right", "bottom", "left")}
        ET.SubElement(section, w("pgMar"), margin)
        return section

    def _content_types(self) -> bytes:
        ct = ooxml.CONTENT_TYPES
        root = ET.Element(f"{{{ct}}}Types")
        ET.SubElement(root, f"{{{ct}}}Default", Extension="rels", ContentType=RELS_TYPE)
        ET.SubElement(root, f"{{{ct}}}Default", Extension="xml", ContentType="application/xml")
        ET.SubElement(root, f"{{{ct}}}Default", Extension="jpeg", ContentType="image/jpeg")
        ET.SubElement(
            root, f"{{{ct}}}Override", PartName="/word/document.xml", ContentType=self._main_type
        )
        return ooxml.serialize(ooxml.Part(root=root, prefixes={ct: ""}))

    @staticmethod
    def _package_rels() -> bytes:
        root = ET.Element(f"{{{ooxml.PKG_RELS}}}Relationships")
        ET.SubElement(
            root,
            f"{{{ooxml.PKG_RELS}}}Relationship",
            Id="rId1",
            Type=REL_OFFICE_DOCUMENT,
            Target="word/document.xml",
        )
        return ooxml.serialize(ooxml.Part(root=root, prefixes={ooxml.PKG_RELS: ""}))

    def _document_rels(self) -> bytes:
        root = ET.Element(f"{{{ooxml.PKG_RELS}}}Relationships")
        for index in range(1, len(self._images) + 1):
            ET.SubElement(
                root,
                f"{{{ooxml.PKG_RELS}}}Relationship",
                Id=f"rIdImage{index}",
                Type=REL_IMAGE,
                Target=f"media/image{index}.jpeg",
            )
        return ooxml.serialize(ooxml.Part(root=root, prefixes={ooxml.PKG_RELS: ""}))


def _emu(value: str | None) -> str:
    try:
        number = int(value or "0")
    except ValueError:
        number = 0
    return str(min(max(number, 9525), EMU_LIMIT))


def _twip(value: str | None, default: str) -> str:
    try:
        number = int(value or "")
    except ValueError:
        return default
    return str(min(max(number, 1440), 31680))
