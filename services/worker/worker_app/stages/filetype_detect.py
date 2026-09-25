"""Определение фактического типа файла.

§2 ТЗ: расширению и заявленному клиентом MIME не доверяем, тип определяется
по содержимому. Детектор двухслойный:

* **таблица сигнатур** — своя, быстрая, доступна всегда;
* **libmagic** — глубже и шире, но это системная библиотека и C-парсер с
  собственной историей CVE.

Отсутствие libmagic не должно тихо отключать определение типа, поэтому
таблица работает самостоятельно, а libmagic только уточняет её вывод.
"""

from __future__ import annotations

import logging
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

HEAD_BYTES = 8192
"""Сколько байт достаточно для определения типа. Больше libmagic не нужно."""

SIGNATURE_SEARCH_WINDOW = 1024
"""В каком окне искать сигнатуру PDF, если её нет в нулевом смещении."""

# (смещение, сигнатура, mime, расширение)
SIGNATURES: tuple[tuple[int, bytes, str, str], ...] = (
    (0, b"%PDF-", "application/pdf", ".pdf"),
    (0, b"\xff\xd8\xff", "image/jpeg", ".jpg"),
    (0, b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
    (0, b"GIF87a", "image/gif", ".gif"),
    (0, b"GIF89a", "image/gif", ".gif"),
    (0, b"II*\x00", "image/tiff", ".tif"),
    (0, b"MM\x00*", "image/tiff", ".tif"),
    (8, b"WEBP", "image/webp", ".webp"),
    (0, b"BM", "image/bmp", ".bmp"),
    (0, b"\x00\x00\x01\x00", "image/vnd.microsoft.icon", ".ico"),
    (0, b"8BPS", "image/vnd.adobe.photoshop", ".psd"),
    (0, b"PK\x03\x04", "application/zip", ".zip"),
    (0, b"Rar!\x1a\x07", "application/vnd.rar", ".rar"),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ".7z"),
    (0, b"\x1f\x8b", "application/gzip", ".gz"),
    (0, b"BZh", "application/x-bzip2", ".bz2"),
    (0, b"\xfd7zXZ\x00", "application/x-xz", ".xz"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", ".doc"),
    (0, b"{\\rtf", "application/rtf", ".rtf"),
    (0, b"%!PS", "application/postscript", ".ps"),
    (0, b"MZ", "application/x-dosexec", ".exe"),
    (0, b"\x7fELF", "application/x-elf", ".elf"),
    (0, b"\xcf\xfa\xed\xfe", "application/x-mach-binary", ".macho"),
    (0, b"\xfe\xed\xfa\xcf", "application/x-mach-binary", ".macho"),
    (0, b"\xca\xfe\xba\xbe", "application/x-mach-binary", ".macho"),
    (4, b"ftyp", "video/mp4", ".mp4"),
    (0, b"\x1aE\xdf\xa3", "video/x-matroska", ".mkv"),
    (0, b"OggS", "audio/ogg", ".ogg"),
    (0, b"ID3", "audio/mpeg", ".mp3"),
    (0, b"<?xml", "application/xml", ".xml"),
    (0, b"<svg", "image/svg+xml", ".svg"),
)

KNOWN_MIMES = frozenset(mime for _, _, mime, _ in SIGNATURES)
"""Типы, о которых у нас есть собственное мнение.

Расхождение с libmagic имеет смысл считать сигналом только внутри этого
множества: для DOCX libmagic скажет `...wordprocessingml.document`, а таблица
`application/zip` — это уточнение, а не конфликт.
"""

_EXT_BY_MIME = {mime: ext for _, _, mime, ext in SIGNATURES}


@dataclass(frozen=True, slots=True)
class DetectedType:
    mime: str | None
    ext: str | None
    offset: int = 0
    """Смещение сигнатуры. Ненулевое — сама по себе аномалия."""

    libmagic_mime: str | None = None
    """Что сказал libmagic. `None` — библиотека недоступна или промолчала."""

    @property
    def conflict(self) -> bool:
        """Оба детектора уверенно назвали разные известные типы."""
        if self.mime is None or self.libmagic_mime is None:
            return False
        if self.libmagic_mime not in KNOWN_MIMES:
            return False
        return self.mime != self.libmagic_mime


class TypeDetector:
    """Ленивая инициализация libmagic: без неё детектор просто беднее."""

    def __init__(self, magic_impl: object | None = None) -> None:
        self._magic = magic_impl
        self._checked = magic_impl is not None
        # Стадии выполняются в пуле потоков, а объект libmagic держит cookie
        # библиотеки и потокобезопасным не является. Критическая секция —
        # микросекунды, поэтому обычной блокировки достаточно.
        self._lock = threading.Lock()

    @property
    def libmagic_available(self) -> bool:
        self._ensure_magic()
        return self._magic is not None

    def _ensure_magic(self) -> None:
        if self._checked:
            return
        self._checked = True
        try:
            import magic

            self._magic = magic.Magic(mime=True)
            logger.info("libmagic подключён")
        except Exception as exc:
            # Не ошибка: таблица сигнатур работает самостоятельно. Но знать
            # о деградации нужно — это видно в /readyz.
            logger.warning(
                "libmagic недоступен, работаем на таблице сигнатур",
                extra={"reason": type(exc).__name__},
            )
            self._magic = None

    def detect(self, head: bytes) -> DetectedType:
        mime, ext, offset = _match_signature(head)
        return DetectedType(
            mime=mime,
            ext=ext,
            offset=offset,
            libmagic_mime=self._detect_libmagic(head),
        )

    def _detect_libmagic(self, head: bytes) -> str | None:
        self._ensure_magic()
        if self._magic is None:
            return None
        try:
            with self._lock:
                value = self._magic.from_buffer(head[:HEAD_BYTES])
        except Exception:
            logger.warning("libmagic не смог определить тип")
            return None
        mime = str(value).split(";")[0].strip().lower()
        return mime or None


def _match_signature(head: bytes) -> tuple[str | None, str | None, int]:
    for offset, magic, mime, ext in SIGNATURES:
        if head[offset : offset + len(magic)] == magic:
            return mime, ext, 0

    # PDF допускает мусор перед сигнатурой, и этим пользуются: файл открывается
    # просмотрщиком, но обходит наивную проверку нулевого смещения.
    found = head[:SIGNATURE_SEARCH_WINDOW].find(b"%PDF-")
    if found > 0:
        return "application/pdf", ".pdf", found

    return None, None, 0


def extension_for(mime: str | None) -> str | None:
    return _EXT_BY_MIME.get(mime) if mime else None


# --- контейнеры на основе ZIP (M6) ---

ZIP_MIME = "application/zip"
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
DOCM_MIME = "application/vnd.ms-word.document.macroEnabled.12"
DOCX_MIMES = frozenset({DOCX_MIME, DOCM_MIME})

JAR_MIME = "application/java-archive"
APK_MIME = "application/vnd.android.package-archive"

_OOXML_MAIN = (
    ("word/document.xml", DOCX_MIME, ".docx"),
    (
        "xl/workbook.xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xlsx",
    ),
    (
        "ppt/presentation.xml",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".pptx",
    ),
)

CONTENT_TYPES_READ_LIMIT = 256 * 1024
"""Сколько читать из `[Content_Types].xml`, чтобы отличить DOCM от DOCX."""


def refine_zip(path: Path) -> tuple[str, str]:
    """Что за контейнер лежит в ZIP: документ Word, таблица, Java — или просто архив.

    Таблица сигнатур видит у всех них одно и то же `PK\\x03\\x04`, а libmagic
    может быть недоступен. Без уточнения DOCX проверялся бы как архив из
    XML-файлов, а JAR — как безобидный архив.

    Читается только центральный каталог и, для Word, начало одной части.
    Битый архив остаётся `application/zip`: признак о поломке поставит разбор.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            if "[Content_Types].xml" in names:
                for main, mime, ext in _OOXML_MAIN:
                    if main not in names:
                        continue
                    if mime == DOCX_MIME:
                        with zf.open("[Content_Types].xml") as handle:
                            types = handle.read(CONTENT_TYPES_READ_LIMIT)
                        if b"macroEnabled" in types:
                            return DOCM_MIME, ".docm"
                    return mime, ext
            if "mimetype" in names:
                with zf.open("mimetype") as handle:
                    declared = handle.read(128).decode("ascii", "replace").strip()
                if declared.startswith("application/vnd.oasis.opendocument."):
                    return declared, ".odf"
            if "AndroidManifest.xml" in names and "classes.dex" in names:
                return APK_MIME, ".apk"
            if "META-INF/MANIFEST.MF" in names and any(n.endswith(".class") for n in names):
                return JAR_MIME, ".jar"
    except Exception as exc:
        logger.debug("архив не открылся при уточнении типа", extra={"reason": type(exc).__name__})
    return ZIP_MIME, ".zip"


def sniff(path: Path) -> str | None:
    """Тип по содержимому без libmagic — для санитайзера, выбирающего обработчик.

    Решение «проверено» принимает конвейер со всеми детекторами; здесь нужно
    лишь понять, чем пересобирать вложение, которое конвейер уже пропустил.
    """
    with path.open("rb") as handle:
        head = handle.read(HEAD_BYTES)
    mime, _ext, _offset = _match_signature(head)
    if mime == ZIP_MIME:
        mime, _ext = refine_zip(path)
    return mime
