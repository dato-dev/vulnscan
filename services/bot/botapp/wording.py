"""Тексты для пользователя.

Два правила. Первое: человек должен понимать, что получил **пересобранную
копию**, а не свой файл, — это происходит всегда, в том числе когда ничего не
найдено, и без этого «обезврежен» звучит так, будто в файле что-то было.
Второе: если что-то нашли, надо сказать что именно — обычными словами, не
кодами признаков и не именами сигнатур.
"""

from __future__ import annotations

GREETING = (
    "Пришлите документ или фотографию — проверю содержимое.\n\n"
    "В ответ придёт не ваш оригинал, а пересобранная копия: документ "
    "собирается заново, поэтому в нём не остаётся ни скрытых элементов, ни "
    "сценариев, ни служебных данных о том, кто и чем его создал. Текст и "
    "изображения сохраняются.\n\n"
    "Поддерживаются PDF, JPEG и PNG."
)

COPY_NOTE = "Это пересобранная копия, оригинал не пересылаю."

CLEAN_CAPTION = f"🟢 Ничего опасного не нашёл.\n\n{COPY_NOTE}"

SUSPICIOUS_CAPTION = (
    "🟡 В файле есть то, что обычно в документах не нужно:\n{reasons}\n\n"
    f"Само по себе это не значит, что файл вредоносный. {COPY_NOTE} "
    "Перечисленного в ней уже нет."
)

BLOCKED = (
    "🔴 Файл не пропускаю: в нём есть содержимое, опасное при открытии.\n\n"
    "Копию не отправляю — пересобирать такой файл небезопасно."
)

ENCRYPTED = (
    "⚠️ Файл защищён паролем, поэтому заглянуть внутрь я не могу.\n\n"
    "Раз содержимое не проверено, не пропускаю. Снимите пароль и пришлите снова."
)

UNSUPPORTED = (
    "⚠️ Такой формат я проверять не умею, поэтому не пропускаю.\n\n"
    "Пока поддерживаются PDF, JPEG и PNG."
)

UNAVAILABLE = (
    "⚠️ Проверка сейчас недоступна.\n\n"
    "Непроверенный файл не пропускаю — попробуйте, пожалуйста, позже."
)

TOO_BIG = "Файл слишком большой: через Telegram я могу получить не больше {} МБ."


# Категории вместо кодов признаков. Пользователю нужно понимать суть, а не
# внутреннюю кухню; имена сигнатур наружу не отдаём в любом случае.
_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "встроенный сценарий или действие при открытии",
        ("PDF_JAVASCRIPT", "PDF_JS", "PDF_OPENACTION", "PDF_AUTO_ACTION", "PDF_LAUNCH"),
    ),
    (
        "вложенный внутрь файл",
        ("PDF_EMBEDDED_FILE", "PDF_EMBEDDED_NAMES", "PDF_EMBEDDED_EXECUTABLE"),
    ),
    (
        "интерактивные элементы с действиями",
        ("PDF_ANNOT_ACTION", "PDF_ANNOT_HIDDEN_ACTION", "PDF_ANNOT_AUTO_ACTION", "PDF_XFA"),
    ),
    (
        "обращение к внешнему адресу",
        ("PDF_EXTERNAL_URI", "PDF_GOTOR", "PDF_GOTOE", "PDF_SUBMITFORM", "PDF_IMPORTDATA"),
    ),
    (
        "данные, приклеенные после конца файла",
        ("PDF_TRAILING_DATA", "POLYGLOT_ARCHIVE"),
    ),
    (
        "повреждённая структура документа",
        (
            "PDF_DAMAGED",
            "PDF_MALFORMED",
            "PDF_XREF_BROKEN",
            "PDF_XREF_RECONSTRUCTED",
            "PDF_STREAM_LENGTH_MISMATCH",
            "IMG_MALFORMED",
        ),
    ),
    (
        "содержимое не совпадает с расширением файла",
        ("MIME_MISMATCH", "EXT_MISMATCH", "TYPE_SIGNATURE_OFFSET", "TYPE_DETECTOR_CONFLICT"),
    ),
    (
        "необычно большое изображение",
        ("IMG_PIXEL_BOMB", "IMG_DECOMPRESSION_BOMB", "IMG_TOO_MANY_FRAMES", "PDF_STREAM_BOMB"),
    ),
    (
        "мультимедиа внутри документа",
        ("PDF_RICHMEDIA", "PDF_MOVIE", "PDF_SOUND", "PDF_RENDITION"),
    ),
    (
        "совпадение с известной угрозой",
        ("AV_SIGNATURE_MATCH",),
    ),
    (
        "исполняемый файл вместо документа",
        ("TYPE_EXECUTABLE", "EXT_DANGEROUS"),
    ),
    (
        "формат файла определить не удалось",
        ("TYPE_UNKNOWN", "TYPE_UNSUPPORTED"),
    ),
    (
        "файл защищён паролем",
        ("PDF_ENCRYPTED", "PDF_ENCRYPTED_OWNER"),
    ),
    (
        "непривычно устроенное содержимое",
        (
            "PDF_UNUSUAL_FILTER",
            "PDF_FILTER_CHAIN",
            "PDF_JBIG2",
            "PDF_OBJSTM",
            "PDF_DEEP_NESTING",
            "PDF_SETOCGSTATE",
        ),
    ),
    (
        "документ необычно большой или сложный",
        ("PDF_TOO_MANY_OBJECTS", "PDF_TOO_MANY_PAGES", "PDF_TOO_MANY_FONTS", "PDF_FONT_OVERSIZED"),
    ),
    (
        "документ правился после создания",
        ("PDF_INCREMENTAL_UPDATES",),
    ),
    (
        "проверка прошла не полностью",
        ("STAGE_FAILED", "STAGE_TIMEOUT", "AV_ERROR", "CDR_FAILED"),
    ),
)

DYNAMIC_PREFIXES: tuple[tuple[str, str], ...] = (
    # Имя правила наружу не отдаём — только сам факт совпадения.
    ("YARA_", "совпадение с известным образцом"),
)

MAX_LISTED = 3

# Насколько исход хуже. Нужен, чтобы понять, стоит ли беспокоить человека
# вторым сообщением: улучшение вердикта его не касается.
SEVERITY_ORDER: tuple[str, ...] = (
    "clean",
    "unsupported",
    "encrypted",
    "suspicious",
    "malicious",
)


def got_worse(before: str, after: str) -> bool:
    """Стал ли вердикт хуже прежнего.

    Неизвестный исход поводом для тревоги не считаем: сообщать «кажется, что-то
    не так» бессмысленно.
    """
    if before not in SEVERITY_ORDER or after not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(after) > SEVERITY_ORDER.index(before)


WORSE_AFTER_DEEP = (
    "⚠️ Я перепроверил присланный вами файл внимательнее.\n\n"
    "Углублённая проверка нашла в нём то, чего не увидела быстрая:\n{reasons}\n\n"
    "Копию, которую я отправил, лучше не открывать и удалить. "
    "Она пересобрана, так что опасного содержимого в ней быть не должно, "
    "но раз исходный документ вызывает вопросы, осторожность не лишняя."
)

BLOCKED_AFTER_DEEP = (
    "🔴 Я перепроверил присланный вами файл внимательнее.\n\n"
    "Он признан опасным. Копию, которую я отправил, лучше удалить."
)


def describe(codes: list[str] | None) -> str:
    """Список категорий обычными словами, по одной строке.

    Признаки нулевого веса сюда не попадают: они справочные и человеку
    ничего не говорят.
    """
    if not codes:
        return "• точную причину подскажет служба поддержки"

    found = [name for name, group in _CATEGORIES if any(c in group for c in codes)]
    found += [
        name
        for prefix, name in DYNAMIC_PREFIXES
        if any(c.startswith(prefix) for c in codes) and name not in found
    ]
    if not found:
        # Код есть, а категории для него нет — новый признак, который забыли
        # описать. Врать про «ничего не нашли» нельзя.
        found = ["необычное содержимое"]

    listed = found[:MAX_LISTED]
    text = "\n".join(f"• {name}" for name in listed)
    if len(found) > MAX_LISTED:
        text += f"\n• и ещё {len(found) - MAX_LISTED}"
    return text
