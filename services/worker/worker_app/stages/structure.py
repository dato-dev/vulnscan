"""S1: структурный анализ. Здесь ловится большинство реальных PDF-атак.

Разбор PDF вынесен в `pdf_structure`: проверок по §8 ТЗ там на отдельный
модуль. Здесь остаются диспетчеризация по типу и анализ изображений.
"""

from __future__ import annotations

import logging

from vscommon.limits import MAX_IMAGE_PIXELS

from . import pdf_structure
from .base import ScanContext, Stage

logger = logging.getLogger(__name__)

IMAGE_BOMB_RATIO = 1000
MAX_IMAGE_FRAMES = 1000


class StructureStage(Stage):
    name = "structure"

    def run(self, ctx: ScanContext) -> None:
        if ctx.detected_mime == "application/pdf":
            self._scan_pdf(ctx)
        elif ctx.detected_mime and ctx.detected_mime.startswith("image/"):
            self._scan_image(ctx)

    def _scan_pdf(self, ctx: ScanContext) -> None:
        raw = ctx.path.read_bytes()
        # Байтовый проход первым: он работает и на документе, который парсер
        # отказывается открывать, а именно на это битые PDF и рассчитаны.
        pdf_structure.analyse_bytes(ctx, self.name, raw)
        if not self._scan_pdf_parsed(ctx, raw):
            # Документ не открылся: об автозапуске судим по байтам, иначе
            # намеренная поломка структуры прятала бы его целиком.
            pdf_structure.analyse_unparsed(ctx, self.name, raw)

    def _scan_pdf_parsed(self, ctx: ScanContext, raw: bytes) -> bool:
        """True — документ разобран, признакам из графа можно доверять."""
        try:
            import pikepdf
        except ImportError:
            logger.warning("pikepdf недоступен, только байтовый разбор", extra={"stage": self.name})
            if b"/Encrypt" in raw:
                # Без парсера нельзя убедиться, что содержимое читается.
                # Считаем недоступным: это безопасная сторона ошибки.
                ctx.encrypted = True
                ctx.add(self.name, "PDF_ENCRYPTED", "разбор недоступен")
            return False

        try:
            with pikepdf.open(ctx.path) as pdf:
                ctx.engines.setdefault("pdf", {})["version"] = str(pdf.pdf_version)
                if pdf.is_encrypted:
                    # Открылся, значит пароль пользователя пуст: стоит только
                    # владельческий. Содержимое читается, проверяем как обычно,
                    # а CDR отдаст расшифрованную копию.
                    ctx.add(
                        self.name,
                        "PDF_ENCRYPTED_OWNER",
                        "владельческий пароль, содержимое читается",
                    )
                pdf_structure.analyse_parsed(ctx, self.name, pdf, len(raw))
        except pikepdf.PasswordError:
            ctx.encrypted = True
            ctx.add(self.name, "PDF_ENCRYPTED", "требуется пароль, содержимое недоступно")
            return False
        except Exception as exc:
            # Битая структура — сама по себе сигнал: эксплойты часто ломают xref.
            ctx.add(self.name, "PDF_MALFORMED", type(exc).__name__)
            return False
        return True

    def _scan_image(self, ctx: ScanContext) -> None:
        try:
            from PIL import Image
        except ImportError:
            logger.warning("Pillow недоступен", extra={"stage": self.name})
            return

        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
        try:
            with Image.open(ctx.path) as img:
                width, height = img.size
                pixels = width * height
                ctx.engines["image"] = {"format": img.format, "mode": img.mode}
                if pixels > MAX_IMAGE_PIXELS:
                    ctx.add(self.name, "IMG_PIXEL_BOMB", f"{pixels} пикс")
                ratio = pixels * 3 / max(ctx.path.stat().st_size, 1)
                if ratio > IMAGE_BOMB_RATIO:
                    ctx.add(self.name, "IMG_DECOMPRESSION_BOMB", f"x{int(ratio)}")
                if getattr(img, "n_frames", 1) > MAX_IMAGE_FRAMES:
                    ctx.add(self.name, "IMG_TOO_MANY_FRAMES")
                # Значения EXIF в логи и findings не пишем — только факт наличия.
                if img.getexif():
                    ctx.add(self.name, "IMG_HAS_EXIF", "будет удалён при CDR")
        except Exception as exc:
            ctx.add(self.name, "IMG_MALFORMED", type(exc).__name__)
