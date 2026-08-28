"""S0: фактический тип файла, polyglot, расхождение с заявленным."""

from __future__ import annotations

import logging

from .base import ScanContext, Stage
from .filetype_detect import HEAD_BYTES, TypeDetector

logger = logging.getLogger(__name__)

SUPPORTED_MIMES = frozenset(
    {"application/pdf", "image/jpeg", "image/png", "image/gif", "image/tiff"}
)

EXECUTABLE_MIMES = frozenset(
    {"application/x-dosexec", "application/x-elf", "application/x-mach-binary"}
)

# Расширения, которые в потоке документов не встречаются легитимно.
GENERIC_MIMES = frozenset(
    {"application/octet-stream", "binary/octet-stream", "application/unknown", "*/*"}
)
"""«Тип неизвестен», а не заявление о типе.

Telegram присылает такое для многих документов, и считать это расхождением
означало бы поднимать балл каждому второму файлу.
"""

DANGEROUS_EXT = frozenset(
    {".exe", ".scr", ".js", ".vbs", ".hta", ".lnk", ".ps1", ".jar", ".bat", ".cmd"}
)

ARCHIVE_TAIL_MARKERS: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
)

TAIL_PADDING = b"\r\n \t\x00"
"""Перевод строки в конце файла — норма, а не приклеенный payload."""


def container_end(mime: str, raw: bytes) -> int | None:
    """Смещение, на котором кончается сам документ.

    `None` — у формата нет надёжного признака конца, и говорить о «хвосте»
    нельзя. Без этого проверка вырождается в поиск сигнатуры по всему файлу:
    Word кладёт исходный .docx внутрь PDF отдельным потоком, и любой документ
    из Word выглядел бы как polyglot.
    """
    if mime == "application/pdf":
        found = raw.rfind(b"%%EOF")
        return found + len(b"%%EOF") if found != -1 else None
    if mime == "image/jpeg":
        found = raw.rfind(b"\xff\xd9")
        return found + 2 if found != -1 else None
    if mime == "image/png":
        found = raw.rfind(b"IEND")
        return found + 8 if found != -1 else None  # IEND + CRC
    if mime == "image/gif":
        return len(raw) if raw.endswith(b"\x3b") else None
    return None


class FiletypeStage(Stage):
    name = "filetype"

    def __init__(self, detector: TypeDetector | None = None) -> None:
        # Детектор держит дескриптор базы libmagic — создаём один на процесс.
        self._detector = detector or TypeDetector()

    @property
    def libmagic_available(self) -> bool:
        return self._detector.libmagic_available

    def run(self, ctx: ScanContext) -> None:
        with ctx.path.open("rb") as handle:
            head = handle.read(HEAD_BYTES)

        detected = self._detector.detect(head)
        ctx.detected_mime = detected.mime
        ctx.detected_ext = detected.ext
        ctx.engines["filetype"] = {
            "mime": detected.mime,
            "libmagic": detected.libmagic_mime,
            "offset": detected.offset,
        }

        if detected.mime is None:
            ctx.supported = False
            ctx.add(self.name, "TYPE_UNKNOWN", detected.libmagic_mime or "тип не распознан")
            return

        if detected.mime not in SUPPORTED_MIMES:
            ctx.supported = False
            ctx.add(self.name, "TYPE_UNSUPPORTED", detected.mime)

        if detected.mime in EXECUTABLE_MIMES:
            ctx.add(self.name, "TYPE_EXECUTABLE", detected.mime)

        if detected.offset > 0:
            # Файл открывается просмотрщиком, но обходит наивную проверку
            # нулевого смещения — этим и пользуются.
            ctx.add(self.name, "TYPE_SIGNATURE_OFFSET", f"сигнатура на смещении {detected.offset}")

        if detected.conflict:
            ctx.add(
                self.name,
                "TYPE_DETECTOR_CONFLICT",
                f"таблица: {detected.mime}, libmagic: {detected.libmagic_mime}",
            )

        self._check_declared(ctx, detected.mime)
        self._check_extension(ctx, detected.ext)
        self._check_polyglot(ctx, detected.mime)

        logger.debug("тип определён", extra={"stage": self.name, "mime": detected.mime})

    def _check_declared(self, ctx: ScanContext, mime: str) -> None:
        declared = (ctx.job.declared_mime or "").split(";")[0].strip().lower()
        if declared in GENERIC_MIMES:
            return
        if declared and declared != mime:
            # Само по себе не приговор: пользователи переименовывают файлы.
            # Вес складывается с остальным.
            ctx.add(
                self.name,
                "MIME_MISMATCH",
                f"заявлен {declared}, определён {mime}",
            )

    def _check_extension(self, ctx: ScanContext, ext: str | None) -> None:
        declared_ext = ctx.job.filename_ext
        if declared_ext in DANGEROUS_EXT:
            ctx.add(self.name, "EXT_DANGEROUS", declared_ext)
        if declared_ext and ext and declared_ext != ext:
            ctx.add(
                self.name,
                "EXT_MISMATCH",
                f"расширение {declared_ext}, содержимое {ext}",
            )

    def _check_polyglot(self, ctx: ScanContext, mime: str) -> None:
        """Архив, приклеенный ПОСЛЕ конца документа.

        libmagic сообщает только основной тип файла и такой хвост не видит,
        поэтому проверка остаётся своей. Но искать сигнатуру по всему файлу
        нельзя: у форматов-контейнеров внутри законно лежат чужие данные.
        Улика — только то, что находится за пределами самого документа.
        """
        if mime.startswith("application/zip"):
            return

        data = ctx.path.read_bytes()
        end = container_end(mime, data)
        if end is None or end >= len(data):
            return

        tail = data[end:].strip(TAIL_PADDING)
        if not tail:
            return

        for marker, label in ARCHIVE_TAIL_MARKERS:
            if marker in tail:
                ctx.add(
                    self.name,
                    "POLYGLOT_ARCHIVE",
                    f"после конца {mime} приклеен {label}, {len(tail)} байт",
                )
                return
