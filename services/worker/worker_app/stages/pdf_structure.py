"""Структурный анализ PDF по §8 ТЗ.

Разбор идёт двумя проходами. Байтовый работает всегда, даже на документе,
который парсер отказывается открывать, — намеренно битые PDF на это и
рассчитаны. Разбор через pikepdf добавляет то, что видно только в графе
объектов: аннотации, шрифты, потоки, глубину вложенности.

Всё, что здесь делается, ограничено по стоимости: конвейер живёт в бюджете
сотен миллисекунд, а на вход может прийти документ, собранный так, чтобы
анализ занял часы.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from vscommon.limits import MAX_PDF_NESTING_DEPTH, MAX_PDF_OBJECTS, MAX_PDF_PAGES

from .base import ScanContext

logger = logging.getLogger(__name__)

# Активные элементы, видимые в байтах: (маркер, код признака).
PDF_MARKERS: list[tuple[bytes, str]] = [
    # /OpenAction и /AA здесь намеренно нет: они оцениваются по тому, какое
    # действие вызывают, см. `_auto_actions`. Само по себе наличие ничего не
    # значит — почти каждый генератор PDF пишет `/OpenAction [страница /FitH]`,
    # то есть «открыть на такой-то странице».
    (b"/JavaScript", "PDF_JAVASCRIPT"),
    (b"/Launch", "PDF_LAUNCH"),
    (b"/EmbeddedFile", "PDF_EMBEDDED_FILE"),
    (b"/RichMedia", "PDF_RICHMEDIA"),
    (b"/GoToE", "PDF_GOTOE"),
    (b"/GoToR", "PDF_GOTOR"),
    (b"/SubmitForm", "PDF_SUBMITFORM"),
    (b"/ImportData", "PDF_IMPORTDATA"),
    (b"/SetOCGState", "PDF_SETOCGSTATE"),
    (b"/Rendition", "PDF_RENDITION"),
    (b"/Movie", "PDF_MOVIE"),
    (b"/Sound", "PDF_SOUND"),
    (b"/JBIG2Decode", "PDF_JBIG2"),
    (b"/ObjStm", "PDF_OBJSTM"),
]

SUSPICIOUS_ACTIONS = frozenset(
    {
        "/Launch",
        "/JavaScript",
        "/JS",
        "/SubmitForm",
        "/ImportData",
        "/GoToE",
        "/GoToR",
        "/Rendition",
        "/Movie",
        "/Sound",
    }
)

UNUSUAL_FILTERS = frozenset({"/Crypt", "/JBIG2Decode", "/DCTDecode/JBIG2Decode"})

EXECUTABLE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ\x90\x00", "PE"),
    (b"\x7fELF", "ELF"),
    (b"This program cannot be run in DOS mode", "PE-stub"),
    (b"\xca\xfe\xba\xbe", "Mach-O"),
)

ANNOT_FLAG_HIDDEN = 0b10
ANNOT_FLAG_NOVIEW = 0b100000

# Бюджеты. Без них специально собранный документ съедает таймаут стадии.
MAX_STREAMS_INSPECTED = 200
MAX_STREAM_DECODE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_DECODE_BYTES = 32 * 1024 * 1024
MAX_WALK_STEPS = 50_000
MAX_EMBEDDED_FONT_BYTES = 2 * 1024 * 1024
MAX_EMBEDDED_FONTS = 50
STREAM_EXPANSION_RATIO = 200

LENGTH_SLACK_BYTES = 32
LENGTH_SLACK_RATIO = 0.1
"""Допуск на расхождение объявленной и фактической длины потока.

Спецификация разрешает перевод строки перед `endstream`, и генераторы PDF
регулярно ошибаются на несколько байт — сам по себе такой разброс уликой не
является. Приём, который проверка ловит, — намеренно заниженная длина, чтобы
наивный разборщик пропустил часть данных, а это расхождение крупное.
"""
TRAILING_WHITESPACE = b"\r\n \t\x00"
"""После %%EOF законно бывает только перевод строки.

Прежний допуск в 64 байта пропускал приклеенный payload: типичный хвост
короче и целиком укладывался в него.
"""

_URI_RE = re.compile(rb"/URI\s*\(([^)]{0,2048})\)")


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Поле недоверенного объекта или `default`.

    Битый объект в PDF — норма, а не исключительная ситуация: специально
    собранные документы ломаются ровно на обращении к полям. Логировать каждый
    отказ нельзя — один файл зальёт логи целиком; факт битой структуры
    фиксируют признаки `PDF_DAMAGED` и `PDF_MALFORMED`.
    """
    try:
        # .get() есть не у всех объектов pikepdf — отсутствие ловит except.
        return obj.get(key, default)
    except Exception:
        return default


def _call(fn: Any, default: Any = None) -> Any:
    """Вызов метода недоверенного объекта с тем же контрактом, что у `_get`."""
    try:
        return fn()
    except Exception:
        return default


_FONT_FILE_KEYS = ("/FontFile", "/FontFile2", "/FontFile3")

_WARNING_CODES = (
    ("reconstruct", "PDF_XREF_RECONSTRUCTED"),
    ("damaged", "PDF_DAMAGED"),
    ("startxref", "PDF_XREF_BROKEN"),
)


def analyse_bytes(ctx: ScanContext, stage: str, raw: bytes) -> None:
    """Проход по сырым байтам: работает и на документе, который не открывается."""
    for marker, code in PDF_MARKERS:
        if marker in raw:
            ctx.add(stage, code, f"маркер {marker.decode()}")

    _external_uri(ctx, stage, raw)
    _xref_anomalies(ctx, stage, raw)


SHORT_KEYS: tuple[tuple[str, str], ...] = (
    ("/JS", "PDF_JS"),
    ("/XFA", "PDF_XFA"),
)
"""Ключи, которые ищутся в графе объектов, а не в байтах.

`/JS` — три байта: в 12 МБ сжатых данных такая последовательность встречается
случайно с вероятностью около половины. Ровно на этом обычный двенадцатимегабайтный
документ и получал признак JavaScript.
"""

FALLBACK_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"/OpenAction", "PDF_OPENACTION"),
    (b"/AA", "PDF_AUTO_ACTION"),
    (b"/JS", "PDF_JS"),
    (b"/XFA", "PDF_XFA"),
)
"""Запасной вариант: применяется, только если документ не разобрался.

Точность здесь хуже, но выбор между неточным признаком и полным отсутствием
признака у намеренно сломанного документа очевиден.
"""


def analyse_unparsed(ctx: ScanContext, stage: str, raw: bytes) -> None:
    """Признаки, которые обычно берутся из графа, — по байтам.

    Нужно ровно тогда, когда парсер не открыл документ: иначе намеренно битый
    PDF прятал бы автозапуск и скрипты за поломкой структуры.
    """
    for marker, code in FALLBACK_MARKERS:
        if marker in raw:
            ctx.add(stage, code, f"маркер {marker.decode()}, разбор недоступен")


def analyse_parsed(ctx: ScanContext, stage: str, pdf: Any, file_size: int) -> None:
    """Проход по графу объектов."""
    _warnings(ctx, stage, pdf)
    _auto_actions(ctx, stage, pdf)
    _short_keys(ctx, stage, pdf)
    _pages(ctx, stage, pdf)
    _objects(ctx, stage, pdf)
    _nesting(ctx, stage, pdf)
    _annotations(ctx, stage, pdf)
    _fonts(ctx, stage, pdf)
    _streams(ctx, stage, pdf, file_size)


# --- байтовый проход ---


def _external_uri(ctx: ScanContext, stage: str, raw: bytes) -> None:
    for match in _URI_RE.finditer(raw):
        uri = match.group(1)[:256].decode("latin-1", "replace")
        if uri.lower().startswith(("http://", "https://")):
            ctx.add(stage, "PDF_EXTERNAL_URI", _host_only(uri))
            return


def _xref_anomalies(ctx: ScanContext, stage: str, raw: bytes) -> None:
    """Аномалии таблицы перекрёстных ссылок и данные за концом документа."""
    eof_count = raw.count(b"%%EOF")
    if eof_count > 1:
        # Нормально для подписанных документов, но заодно так прячут содержимое.
        ctx.add(stage, "PDF_INCREMENTAL_UPDATES", f"{eof_count} ревизий")

    last_eof = raw.rfind(b"%%EOF")
    if last_eof == -1:
        ctx.add(stage, "PDF_XREF_BROKEN", "нет %%EOF")
        return

    tail = raw[last_eof + len(b"%%EOF") :].strip(TRAILING_WHITESPACE)
    if tail:
        ctx.add(stage, "PDF_TRAILING_DATA", f"{len(tail)} байт после конца документа")

    if raw.count(b"startxref") == 0:
        ctx.add(stage, "PDF_XREF_BROKEN", "нет startxref")


def _host_only(uri: str) -> str:
    """В detail попадает только хост — полный URL может содержать ПДн."""
    return uri.split("://", 1)[-1].split("/", 1)[0][:128]


# --- разбор графа объектов ---


def _action_kind(action: Any) -> str:
    """Тип действия или пустая строка, если это не действие.

    Массив — это назначение («открыть на такой-то странице»), а не действие.
    """
    if action is None or not hasattr(action, "get"):
        return ""
    return str(_get(action, "/S", ""))


def _auto_actions(ctx: ScanContext, stage: str, pdf: Any) -> None:
    """Автозапуск оценивается по вызываемому действию.

    Опасно не то, что документ что-то делает при открытии, а что именно.
    Навигация внутри документа (`/GoTo`) и назначение страницы — норма и
    встречаются в большинстве обычных PDF.
    """
    if _action_kind(_get(pdf.Root, "/OpenAction")) in SUSPICIOUS_ACTIONS:
        ctx.add(stage, "PDF_OPENACTION", "действие при открытии документа")

    for holder in (pdf.Root, *pdf.pages):
        additional = _get(holder, "/AA")
        if additional is None or not hasattr(additional, "keys"):
            continue
        for trigger in _safe_keys(additional):
            if _action_kind(_get(additional, trigger)) in SUSPICIOUS_ACTIONS:
                ctx.add(stage, "PDF_AUTO_ACTION", f"действие по событию {trigger}")
                return


def _short_keys(ctx: ScanContext, stage: str, pdf: Any) -> None:
    """Обход графа в поисках коротких ключей.

    Их нельзя искать в байтах: слишком велика вероятность случайного
    совпадения в сжатых потоках.
    """
    wanted = dict(SHORT_KEYS)
    found: set[str] = set()
    stack: list[Any] = [pdf.Root]
    seen: set[tuple[int, int]] = set()
    steps = 0

    while stack and steps < MAX_WALK_STEPS and len(found) < len(wanted):
        obj = stack.pop()
        steps += 1

        objgen = getattr(obj, "objgen", None)
        if objgen and objgen != (0, 0):
            if objgen in seen:
                continue
            seen.add(objgen)

        if hasattr(obj, "keys"):
            keys = _safe_keys(obj)
            found.update(k for k in keys if k in wanted)
            stack.extend(_get(obj, k) for k in keys)
        elif isinstance(obj, list) or hasattr(obj, "__getitem__"):
            stack.extend(_call(obj.__iter__, iter(())))

    for key in sorted(found):
        ctx.add(stage, wanted[key], f"ключ {key} в графе объектов")


def _safe_keys(obj: Any) -> list[str]:
    try:
        return list(obj.keys())
    except Exception:
        return []


def _warnings(ctx: ScanContext, stage: str, pdf: Any) -> None:
    """Жалобы qpdf на структуру.

    Текст жалобы содержит путь к файлу, поэтому наружу отдаём только код.
    """
    warnings = _call(pdf.get_warnings, []) or []
    warnings = [str(w).lower() for w in warnings]

    seen: set[str] = set()
    for warning in warnings:
        for needle, code in _WARNING_CODES:
            if needle in warning and code not in seen:
                seen.add(code)
                ctx.add(stage, code, "парсер восстанавливал структуру")


def _pages(ctx: ScanContext, stage: str, pdf: Any) -> None:
    pages = len(pdf.pages)
    ctx.engines.setdefault("pdf", {})["pages"] = pages
    if pages > MAX_PDF_PAGES:
        ctx.add(stage, "PDF_TOO_MANY_PAGES", str(pages))


def _objects(ctx: ScanContext, stage: str, pdf: Any) -> None:
    count = sum(1 for _ in pdf.objects)
    ctx.engines.setdefault("pdf", {})["objects"] = count
    if count > MAX_PDF_OBJECTS:
        ctx.add(stage, "PDF_TOO_MANY_OBJECTS", str(count))


def _nesting(ctx: ScanContext, stage: str, pdf: Any) -> None:
    """Глубина графа объектов.

    Обход итеративный: рекурсия по специально вложенному документу — это
    RecursionError, то есть падение стадии вместо признака.
    """
    depth = _max_depth(pdf.Root, MAX_PDF_NESTING_DEPTH)
    ctx.engines.setdefault("pdf", {})["depth"] = depth
    if depth >= MAX_PDF_NESTING_DEPTH:
        ctx.add(stage, "PDF_DEEP_NESTING", f"глубина ≥ {depth}")


def _max_depth(root: Any, limit: int) -> int:
    stack: list[tuple[Any, int]] = [(root, 0)]
    seen: set[tuple[int, int]] = set()
    best = 0
    steps = 0

    while stack:
        obj, depth = stack.pop()
        steps += 1
        if steps > MAX_WALK_STEPS:
            break
        best = max(best, depth)
        if depth >= limit:
            break

        objgen = getattr(obj, "objgen", None)
        if objgen and objgen != (0, 0):
            if objgen in seen:
                continue
            seen.add(objgen)

        for child in _children(obj):
            stack.append((child, depth + 1))
    return best


def _children(obj: Any) -> list[Any]:
    try:
        if isinstance(obj, dict) or hasattr(obj, "keys"):
            return [obj[key] for key in list(obj.keys())]
        if isinstance(obj, list) or (hasattr(obj, "__len__") and hasattr(obj, "__getitem__")):
            return list(obj)
    except Exception:
        return []
    return []


def _annotations(ctx: ScanContext, stage: str, pdf: Any) -> None:
    """Аннотации с действиями — один из самых частых носителей payload."""
    with_action = 0
    hidden_with_action = 0
    with_auto_action = 0

    for page in pdf.pages:
        annots = _get(page, "/Annots")
        if annots is None:
            continue

        for annot in _call(annots.__iter__, iter(())):
            action = _get(annot, "/A")
            subtype = str(_get(action, "/S", "")) if action is not None else ""
            flags = int(_get(annot, "/F", 0) or 0)

            if subtype in SUSPICIOUS_ACTIONS:
                with_action += 1
                if flags & (ANNOT_FLAG_HIDDEN | ANNOT_FLAG_NOVIEW):
                    # Невидимая аннотация с действием не бывает случайной.
                    hidden_with_action += 1
            if _get(annot, "/AA") is not None:
                with_auto_action += 1

    if with_action:
        ctx.add(stage, "PDF_ANNOT_ACTION", f"{with_action} аннотаций с действием")
    if hidden_with_action:
        ctx.add(stage, "PDF_ANNOT_HIDDEN_ACTION", f"{hidden_with_action} скрытых с действием")
    if with_auto_action:
        ctx.add(stage, "PDF_ANNOT_AUTO_ACTION", f"{with_auto_action} с /AA")


def _fonts(ctx: ScanContext, stage: str, pdf: Any) -> None:
    """Встроенные шрифты: исторически богатый источник CVE в парсерах."""
    embedded = 0
    oversized = 0

    for obj in pdf.objects:
        if not hasattr(obj, "keys"):
            continue
        for key in _FONT_FILE_KEYS:
            font = _get(obj, key)
            if font is None:
                continue
            embedded += 1
            if _font_size(font) > MAX_EMBEDDED_FONT_BYTES:
                oversized += 1

    if embedded:
        ctx.engines.setdefault("pdf", {})["fonts"] = embedded
        ctx.add(stage, "PDF_FONT_EMBEDDED", f"{embedded} встроенных")
    if embedded > MAX_EMBEDDED_FONTS:
        ctx.add(stage, "PDF_TOO_MANY_FONTS", str(embedded))
    if oversized:
        ctx.add(stage, "PDF_FONT_OVERSIZED", f"{oversized} крупнее лимита")


def _font_size(font: Any) -> int:
    """Размер программы шрифта — того, что попадёт в парсер.

    `/Length` у потока — длина ПОСЛЕ сжатия, по ней судить нельзя: гигантский
    шрифт из повторяющихся байт ужимается до десятков байт. По спецификации
    несжатый размер лежит в `/Length1` (плюс `/Length2`, `/Length3` у Type1).
    """
    declared = sum(int(_get(font, key, 0) or 0) for key in ("/Length1", "/Length2", "/Length3"))
    return declared or int(_get(font, "/Length", 0) or 0)


def _streams(ctx: ScanContext, stage: str, pdf: Any, file_size: int) -> None:
    """Фильтры, расхождения длин, бомбы и исполняемые файлы внутри потоков."""
    import pikepdf

    inspected = 0
    decoded_total = 0
    reported: set[str] = set()

    for obj in pdf.objects:
        if inspected >= MAX_STREAMS_INSPECTED:
            break
        if not isinstance(obj, pikepdf.Stream):
            continue
        inspected += 1

        _stream_filters(ctx, stage, obj, reported)

        raw_stream = _call(obj.read_raw_bytes)
        if raw_stream is None:
            continue
        rawlen = len(raw_stream)

        declared = int(_get(obj, "/Length", rawlen) or rawlen)
        drift = abs(declared - rawlen)
        significant = drift > LENGTH_SLACK_BYTES and drift > rawlen * LENGTH_SLACK_RATIO
        if significant and "PDF_STREAM_LENGTH_MISMATCH" not in reported:
            reported.add("PDF_STREAM_LENGTH_MISMATCH")
            ctx.add(
                stage,
                "PDF_STREAM_LENGTH_MISMATCH",
                f"объявлено {declared}, фактически {rawlen}",
            )

        if rawlen > MAX_STREAM_DECODE_BYTES or decoded_total >= MAX_TOTAL_DECODE_BYTES:
            continue

        data = _call(obj.read_bytes)
        if data is None:
            continue
        decoded_total += len(data)

        ratio = len(data) / max(rawlen, 1)
        if rawlen and ratio > STREAM_EXPANSION_RATIO and "PDF_STREAM_BOMB" not in reported:
            reported.add("PDF_STREAM_BOMB")
            ctx.add(stage, "PDF_STREAM_BOMB", f"распаковка x{int(ratio)}")

        _embedded_executable(ctx, stage, data, reported)

    ctx.engines.setdefault("pdf", {})["streams_inspected"] = inspected
    if decoded_total > file_size * STREAM_EXPANSION_RATIO:
        # Дубль по коду отсекается в ctx.add: если бомбу уже нашли в отдельном
        # потоке, суммарная оценка вес не удваивает.
        ctx.add(stage, "PDF_STREAM_BOMB", f"суммарная распаковка {decoded_total} байт")


def _stream_filters(ctx: ScanContext, stage: str, obj: Any, reported: set[str]) -> None:
    raw_filter = _get(obj, "/Filter")
    if raw_filter is None:
        return

    if hasattr(raw_filter, "__iter__"):
        names = [str(f) for f in _call(raw_filter.__iter__, iter(()))]
    else:
        names = [str(raw_filter)]
    filters = [f for f in names if f.startswith("/")]

    for name in filters:
        if name in UNUSUAL_FILTERS and f"UF:{name}" not in reported:
            reported.add(f"UF:{name}")
            ctx.add(stage, "PDF_UNUSUAL_FILTER", name)

    if len(filters) > 2 and "PDF_FILTER_CHAIN" not in reported:
        reported.add("PDF_FILTER_CHAIN")
        ctx.add(stage, "PDF_FILTER_CHAIN", f"{len(filters)} фильтров подряд")


def _embedded_executable(ctx: ScanContext, stage: str, data: bytes, reported: set[str]) -> None:
    if "PDF_EMBEDDED_EXECUTABLE" in reported:
        return
    head = data[:4096]
    for signature, label in EXECUTABLE_SIGNATURES:
        if head.startswith(signature) or signature in head:
            reported.add("PDF_EMBEDDED_EXECUTABLE")
            ctx.add(stage, "PDF_EMBEDDED_EXECUTABLE", label)
            return
