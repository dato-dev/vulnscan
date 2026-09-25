"""Разбор частей документа Word: XML, связи, поля (M6.3, M6.4).

Общий для стадии разбора и санитайзера: что анализ считает опасным полем,
то санитайзер и убирает, и два списка разойтись не могут.

XML разбирается прямо через expat, без `xml.etree.ElementTree.parse`, по
двум причинам.

* **DTD запрещён.** В документах Word его не бывает, а с ним приходят
  внешние сущности и экспоненциальное раскрытие («billion laughs»).
  ElementTree не даёт повесить обработчик на объявление DTD, expat — даёт.
* **Префиксы сохраняются.** ElementTree при записи переименовывает их в
  `ns0`, `ns1`… Word же читает атрибут `mc:Ignorable="w14 wp14"`, где
  префиксы названы по имени, и документ с переименованными префиксами
  объявляет повреждённым.
"""

from __future__ import annotations

import re
import xml.parsers.expat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import NoReturn
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types"
XML_NS = "http://www.w3.org/XML/1998/namespace"

REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
REL_MS = "http://schemas.microsoft.com/office/2006/relationships/"

MAX_ELEMENTS = 5_000_000
"""Элементов в одной части. Защита не от вложенности, а от объёма дерева."""

MAX_DEPTH = 256
"""Вложенность элементов. Word пишет десятки уровней; сотни — это атака на
тех, кто обходит дерево рекурсией, включая сериализатор."""


class XmlError(ValueError):
    """Часть не разбирается."""


class DtdError(XmlError):
    """В части объявлен DTD или сущность. В документах Word их не бывает."""


def w(tag: str) -> str:
    return f"{{{W}}}{tag}"


# --- разбор и запись ---


@dataclass(slots=True)
class Part:
    root: ET.Element
    prefixes: dict[str, str]
    """uri → префикс, как в исходнике. Нужен, чтобы записать тем же."""


def _forbid(*_args: object) -> NoReturn:
    raise DtdError("DTD или сущности в части документа")


def parse(raw: bytes) -> Part:
    """Разбор части в дерево. DTD, сущности и внешние ссылки — отказ."""
    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _forbid
    parser.EntityDeclHandler = _forbid
    parser.ExternalEntityRefHandler = _forbid
    parser.buffer_text = True
    parser.ordered_attributes = True

    prefixes: dict[str, str] = {}
    stack: list[ET.Element] = []
    root: list[ET.Element] = []
    count = 0

    def start_ns(prefix: str | None, uri: str) -> None:
        # Префикс, уже занятый другим пространством, не переиспользуем:
        # такому пространству сериализатор выдаст свой.
        if uri not in prefixes and (prefix or "") not in prefixes.values():
            prefixes[uri] = prefix or ""

    def start(name: str, attrs: list[str]) -> None:
        nonlocal count
        count += 1
        if count > MAX_ELEMENTS or len(stack) >= MAX_DEPTH:
            raise XmlError("часть слишком велика или вложена")
        element = ET.Element(_clark(name))
        for key, value in zip(attrs[::2], attrs[1::2], strict=True):
            element.set(_clark(key), value)
        if stack:
            stack[-1].append(element)
        else:
            root.append(element)
        stack.append(element)

    def end(_name: str) -> None:
        stack.pop()

    def text(data: str) -> None:
        if not stack:
            return
        current = stack[-1]
        if len(current):
            last = current[-1]
            last.tail = (last.tail or "") + data
        else:
            current.text = (current.text or "") + data

    parser.StartNamespaceDeclHandler = start_ns
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    try:
        parser.Parse(raw, True)
    except xml.parsers.expat.ExpatError as exc:
        raise XmlError(f"XML не разбирается: {exc.code}") from exc
    if not root:
        raise XmlError("пустая часть")
    return Part(root=root[0], prefixes=prefixes)


def _clark(name: str) -> str:
    uri, _, local = name.rpartition(" ")
    return f"{{{uri}}}{local}" if uri else local


def serialize(part: Part) -> bytes:
    """Запись дерева с исходными префиксами. Комментарии и PI не переносятся.

    Обход итеративный: вложенность ограничена при разборе, но сериализатор
    не должен зависеть от того, что ограничение где-то есть.
    """
    names = dict(part.prefixes)
    names[XML_NS] = "xml"
    used = set(names.values())

    def prefix_for(uri: str) -> str:
        if uri not in names:
            candidate, n = "ns", 0
            while f"{candidate}{n}" in used:
                n += 1
            names[uri] = f"{candidate}{n}"
            used.add(names[uri])
        return names[uri]

    def qname(clark: str) -> str:
        if not clark.startswith("{"):
            return clark
        uri, _, local = clark[1:].partition("}")
        prefix = prefix_for(uri)
        return f"{prefix}:{local}" if prefix else local

    out: list[str] = []
    # (элемент, закрыть ли его) — стек вместо рекурсии.
    stack: list[tuple[ET.Element, bool]] = [(part.root, False)]
    root_open = len(out)
    while stack:
        element, closing = stack.pop()
        if closing:
            out.append(f"</{qname(element.tag)}>")
            if element.tail and element is not part.root:
                out.append(escape(element.tail))
            continue
        attrs = "".join(f" {qname(k)}={quoteattr(v)}" for k, v in element.attrib.items())
        tag = qname(element.tag)
        if not len(element) and not element.text:
            out.append(f"<{tag}{attrs}/>")
            if element.tail and element is not part.root:
                out.append(escape(element.tail))
            continue
        out.append(f"<{tag}{attrs}>")
        if element.text:
            out.append(escape(element.text))
        stack.append((element, True))
        stack.extend((child, False) for child in reversed(element))

    # Объявления пространств имён — на корне, все сразу: так префиксы, на
    # которые ссылается `mc:Ignorable`, гарантированно объявлены.
    declarations = "".join(
        f" xmlns={quoteattr(uri)}" if not prefix else f" xmlns:{prefix}={quoteattr(uri)}"
        for uri, prefix in sorted(names.items(), key=lambda item: item[1])
        if uri != XML_NS
    )
    head = out[root_open]
    cut = head.find(">") if not head.endswith("/>") else len(head) - 2
    out[root_open] = head[:cut] + declarations + head[cut:]
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + "".join(out)).encode()


def parents(root: ET.Element) -> dict[ET.Element, ET.Element]:
    return {child: parent for parent in root.iter() for child in parent}


# --- пакет: связи и типы содержимого ---


@dataclass(frozen=True, slots=True)
class Relationship:
    id: str
    type: str
    target: str
    external: bool

    @property
    def kind(self) -> str:
        """Последний сегмент типа: `oleObject`, `attachedTemplate`…"""
        return self.type.rstrip("/").rsplit("/", 1)[-1]


def relationships(part: Part) -> list[Relationship]:
    found = []
    for rel in part.root.iter(f"{{{PKG_RELS}}}Relationship"):
        found.append(
            Relationship(
                id=rel.get("Id", ""),
                type=rel.get("Type", ""),
                target=rel.get("Target", ""),
                external=rel.get("TargetMode", "").lower() == "external",
            )
        )
    return found


SAFE_LINK_SCHEMES = frozenset({"http", "https", "mailto"})


def safe_hyperlink(target: str) -> bool:
    """Гиперссылка, щелчок по которой только открывает страницу или письмо.

    Схема в гиперссылке решает, что запустит щелчок. `ms-msdt:` — это
    Follina, `search-ms:` открывает проводник на чужой папке, `file:` и
    сетевой путь — запуск файла и заодно хэш пароля Windows по сети.
    Относительная ссылка на соседний документ — норма.
    """
    stripped = target.strip()
    if stripped.startswith(("\\\\", "//")):
        return False
    scheme, sep, _ = stripped.partition(":")
    if not sep or not scheme.isascii() or not scheme.replace("+", "").replace("-", "").isalnum():
        return True  # схемы нет: относительный путь или якорь
    if len(scheme) == 1:
        return False  # `C:\…` — путь на диске
    return scheme.lower() in SAFE_LINK_SCHEMES


def rels_name(part_name: str) -> str:
    """Где лежат связи части: `word/document.xml` → `word/_rels/document.xml.rels`."""
    if not part_name:
        return "_rels/.rels"
    path = PurePosixPath(part_name)
    return str(path.parent / "_rels" / f"{path.name}.rels")


def source_of(rels: str) -> str:
    """Обратное к `rels_name`: чьи это связи. Пакетные — пустая строка."""
    path = PurePosixPath(rels)
    name = path.name.removesuffix(".rels")
    if not name:
        return ""
    base = path.parent.parent
    return name if str(base) == "." else f"{base}/{name}"


def resolve(source: str, target: str) -> str:
    """Внутренняя цель связи — имя части в архиве."""
    if target.startswith("/"):
        return target.lstrip("/")
    parts: list[str] = []
    base = PurePosixPath(source).parent if source else PurePosixPath("")
    for piece in [*str(base).split("/"), *target.split("/")]:
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    return "/".join(parts)


@dataclass(slots=True)
class ContentTypes:
    defaults: dict[str, str] = field(default_factory=dict)
    overrides: dict[str, str] = field(default_factory=dict)

    def of(self, name: str) -> str:
        override = self.overrides.get(name.lower())
        if override is not None:
            return override
        return self.defaults.get(PurePosixPath(name).suffix.lower().lstrip("."), "")


def content_types(part: Part) -> ContentTypes:
    types = ContentTypes()
    for item in part.root.iter(f"{{{CONTENT_TYPES}}}Default"):
        types.defaults[item.get("Extension", "").lower()] = item.get("ContentType", "")
    for item in part.root.iter(f"{{{CONTENT_TYPES}}}Override"):
        types.overrides[item.get("PartName", "").lstrip("/").lower()] = item.get("ContentType", "")
    return types


MAIN_TYPES = frozenset(
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
        "application/vnd.ms-word.document.macroEnabled.main+xml",
        "application/vnd.ms-word.template.macroEnabledTemplate.main+xml",
    }
)


# --- поля ---

SAFE_FIELDS = frozenset(
    {
        "PAGE", "NUMPAGES", "SECTION", "SECTIONPAGES", "TOC", "TC", "TOA", "TA",
        "HYPERLINK", "REF", "PAGEREF", "NOTEREF", "STYLEREF", "SEQ", "XE", "INDEX",
        "DATE", "TIME", "CREATEDATE", "SAVEDATE", "PRINTDATE", "EDITTIME",
        "NUMWORDS", "NUMCHARS", "FORMTEXT", "FORMCHECKBOX", "FORMDROPDOWN",
        "SYMBOL", "LISTNUM", "AUTONUM", "AUTONUMLGL", "AUTONUMOUT", "EQ",
        "BIBLIOGRAPHY", "CITATION", "ADVANCE", "MERGEFORMAT",
    }
)  # fmt: skip
"""Поля, которые остаются в пересобранном документе.

Список разрешённых, а не запрещённых: полей в Word больше восьмидесяти, и
опасное среди них — не только DDE. `INCLUDETEXT` тянет файл по сети, `QUOTE`
собирает команду из кодов символов, и следующее такое поле в запретный
список попадёт только после того, как им воспользуются.
"""

OFFICE = "urn:schemas-microsoft-com:office:office"

MARKERS = {
    w("altChunk"): "altchunk",
    w("control"): "control",
    w("mailMerge"): "mailmerge",
    w("frameset"): "frameset",
    f"{{{OFFICE}}}OLEObject": "ole",
}
"""Элементы, которые `scan_fields` сообщает вместе с полями.

Стадии они подтверждают то, что видно по связям; проверке выхода CDR —
что пересборка их действительно убрала.
"""

INSTRUCTION_TAGS = frozenset({w("instrText"), w("delInstrText")})
"""Инструкция поля — в том числе удалённая в режиме правок.

Удалённая инструкция возвращается, стоит получателю нажать «отклонить
исправление». Спрятать DDE в удалённом фрагменте — дёшево.
"""

DDE_FIELDS = frozenset({"DDE", "DDEAUTO"})
INCLUDE_FIELDS = frozenset({"INCLUDETEXT", "INCLUDEPICTURE", "INCLUDE", "LINK", "IMPORT"})

_TOKEN = re.compile(r"[\s\"']*([A-Za-z]+)")


@dataclass(slots=True)
class Field:
    instruction: list[str] = field(default_factory=list)
    nested_first: bool = False
    """Инструкция начинается с вложенного поля: имя поля вычисляется при
    открытии. Так прячут DDE — `{ {QUOTE 68 68 69} … }`."""

    in_result: bool = False

    @property
    def text(self) -> str:
        return "".join(self.instruction)


def field_name(instruction: str) -> str:
    match = _TOKEN.match(instruction)
    return match.group(1).upper() if match else ""


def classify(instruction: str, nested_first: bool = False) -> str:
    """`safe`, `dde`, `include`, `obfuscated` или `other`.

    Поле, чья инструкция начинается с вложенного поля, — `obfuscated`
    независимо от того, что написано после: имя такого поля вычисляется при
    открытии, и видимый текст инструкции о нём ничего не говорит.
    """
    if nested_first:
        return "obfuscated"
    name = field_name(instruction)
    if not name:
        return "other"
    if name in DDE_FIELDS:
        return "dde"
    if name in INCLUDE_FIELDS:
        return "include"
    if name in SAFE_FIELDS:
        return "safe"
    return "other"


def scan_fields(raw: bytes) -> Iterator[str]:
    """Классы полей части потоком, без построения дерева.

    Инструкция поля бывает разрезана на десятки фрагментов `w:instrText` —
    ровно для того, чтобы поиск «DDEAUTO» по тексту её не нашёл. Поэтому
    фрагменты склеиваются по границам поля (`w:fldChar`), а не ищутся по
    одному.
    """
    parser = xml.parsers.expat.ParserCreate(namespace_separator=" ")
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _forbid
    parser.EntityDeclHandler = _forbid
    parser.ExternalEntityRefHandler = _forbid
    parser.buffer_text = True

    found: list[str] = []
    fields: list[Field] = []
    in_instr = False

    def start(name: str, attrs: dict[str, str]) -> None:
        nonlocal in_instr
        tag = _clark(name)
        if tag == w("fldChar"):
            kind = attrs.get(f"{W} fldCharType", "")
            if kind == "begin":
                if fields and not fields[-1].in_result and not fields[-1].text.strip():
                    fields[-1].nested_first = True
                fields.append(Field())
            elif kind == "separate" and fields:
                fields[-1].in_result = True
            elif kind == "end" and fields:
                done = fields.pop()
                found.append(classify(done.text, done.nested_first))
        elif tag in INSTRUCTION_TAGS:
            in_instr = True
        elif tag == w("fldSimple"):
            found.append(classify(attrs.get(f"{W} instr", "")))
        elif tag in MARKERS:
            marker = MARKERS[tag]
            if marker == "ole" and attrs.get("Type") == "Link":
                # Связанный, а не встроенный: это внешняя связь, и признак
                # за неё ставится по связи. Двойной счёт одного объекта.
                marker = "ole_link"
            found.append(marker)

    def end(name: str) -> None:
        nonlocal in_instr
        if _clark(name) in INSTRUCTION_TAGS:
            in_instr = False

    def text(data: str) -> None:
        if in_instr and fields and not fields[-1].in_result:
            fields[-1].instruction.append(data)

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    try:
        parser.Parse(raw, True)
    except xml.parsers.expat.ExpatError as exc:
        raise XmlError(f"XML не разбирается: {exc.code}") from exc
    # Незакрытое поле — тоже поле: Word его выполнит, а документ с оборванной
    # разметкой — ровно то, что пишут руками ради обхода проверок.
    found.extend(classify(f.text, f.nested_first) for f in fields)
    yield from found


@dataclass(slots=True)
class _OpenField:
    instruction: list[str] = field(default_factory=list)
    region: list[ET.Element] = field(default_factory=list)
    """Прогоны от начала поля до разделителя и прогон конца. Результат поля
    — прогоны между разделителем и концом — сюда не входит и остаётся."""

    nested_first: bool = False
    separated: bool = False


def _run_of(element: ET.Element, up: dict[ET.Element, ET.Element]) -> ET.Element:
    """Прогон `w:r`, в котором лежит элемент. Нет прогона — сам элемент."""
    current = element
    for _ in range(4):
        if current.tag == w("r"):
            return current
        parent = up.get(current)
        if parent is None:
            break
        current = parent
    return element


def strip_fields(root: ET.Element, keep_safe: bool) -> int:
    """Убирает коды полей, оставляя их последний сохранённый результат.

    Поле в разметке — это не один элемент, а последовательность прогонов:
    начало, инструкция (возможно, из многих кусков и с вложенными полями),
    разделитель, результат, конец. Убирается всё, кроме результата: текст,
    который видел автор, остаётся, а вычислять его заново больше нечему.

    `keep_safe` — оставить поля из `SAFE_FIELDS` (номера страниц, оглавление).
    Возвращает число убранных полей.
    """
    up = parents(root)
    stack: list[_OpenField] = []
    doomed: list[_OpenField] = []
    strays: list[ET.Element] = []
    removed = 0

    for element in root.iter():
        if element.tag == w("r"):
            # Прогон внутри инструкции принадлежит всем открытым полям, чья
            # инструкция ещё не закончилась: вложенное поле — часть
            # инструкции внешнего.
            for open_field in stack:
                if not open_field.separated:
                    open_field.region.append(element)
        elif element.tag == w("fldChar"):
            kind = element.get(w("fldCharType"), "")
            run = _run_of(element, up)
            if kind == "begin":
                if stack and not stack[-1].separated and not "".join(stack[-1].instruction).strip():
                    stack[-1].nested_first = True
                stack.append(_OpenField(region=[run]))
            elif kind == "separate" and stack:
                stack[-1].separated = True
                stack[-1].region.append(run)
            elif kind == "end" and stack:
                done = stack.pop()
                done.region.append(run)
                name = classify("".join(done.instruction), done.nested_first)
                if not (keep_safe and name == "safe"):
                    doomed.append(done)
        elif element.tag in INSTRUCTION_TAGS:
            if stack and not stack[-1].separated:
                stack[-1].instruction.append(element.text or "")
            else:
                # Инструкция вне поля — обрывок, который Word соберёт
                # по-своему. Оставлять его незачем.
                strays.append(element)

    # Незакрытое поле тоже убирается: безопасную сторону ошибки здесь
    # выбирать легко — потерять можно разве что номер страницы.
    doomed.extend(stack)

    gone: set[int] = set()
    for open_field in doomed:
        removed += 1
        for run in open_field.region:
            if id(run) in gone:
                continue
            gone.add(id(run))
            parent = up.get(run)
            if parent is not None and run in list(parent):
                parent.remove(run)

    for simple in list(root.iter(w("fldSimple"))):
        name = classify(simple.get(w("instr"), ""))
        if keep_safe and name == "safe":
            continue
        unwrap(simple, up)
        removed += 1

    for element in strays:
        parent = up.get(element)
        if parent is not None and element in list(parent):
            parent.remove(element)
    return removed


def unwrap(element: ET.Element, up: dict[ET.Element, ET.Element]) -> None:
    """Заменяет элемент его содержимым: гиперссылка без цели становится текстом."""
    parent = up.get(element)
    if parent is None:
        return
    index = list(parent).index(element)
    parent.remove(element)
    for offset, child in enumerate(list(element)):
        parent.insert(index + offset, child)
        up[child] = parent
