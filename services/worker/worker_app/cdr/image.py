"""CDR для изображений: полное перекодирование через растр."""

from __future__ import annotations

import logging
from pathlib import Path

from vscommon.limits import MAX_IMAGE_PIXELS, MAX_SANITIZED_BYTES
from vscommon.models import CdrProfile

from .base import SanitizeError, SanitizeOutcome, Sanitizer

logger = logging.getLogger(__name__)

_JPEG = ("JPEG", "image/jpeg", ".jpg")
_PNG = ("PNG", "image/png", ".png")

# Контейнер на выходе не влияет на безопасность: файл в любом случае
# собирается из сырых байт растра. Он влияет на размер и цену, поэтому для
# light и standard семейство формата сохраняется. Пересборка фотографии в
# PNG давала файл втрое больше входа и втрое дороже, чем растеризация в strict.
_SOURCE_FAMILY = {
    "image/jpeg": _JPEG,
    "image/png": _PNG,
    "image/gif": _PNG,
    "image/tiff": _PNG,
}


def _output_for(src: Path, profile: CdrProfile) -> tuple[str, str, str]:
    """strict всегда сводит к JPEG; остальные сохраняют семейство формата."""
    if profile is CdrProfile.STRICT:
        return _JPEG

    from PIL import Image

    with Image.open(src) as probe:
        source_format = (probe.format or "").upper()
    if source_format in ("JPEG", "JPG"):
        return _JPEG
    return _PNG


class ImageSanitizer(Sanitizer):
    name = "image"
    mimes = frozenset({"image/jpeg", "image/png", "image/gif", "image/tiff"})

    def sanitize(self, src: Path, dst_dir: Path, profile: CdrProfile) -> SanitizeOutcome:
        from PIL import Image

        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
        fmt, content_type, suffix = _output_for(src, profile)
        dst = dst_dir / f"clean{suffix}"

        with Image.open(src) as img:
            # Декодирование в память и сохранение нового файла: ни одного
            # исходного чанка (EXIF, XMP, ICC, приклеенный хвост) не переносится.
            img.load()
            raster = img.convert(
                "RGB" if fmt == "JPEG" else "RGBA" if img.mode == "RGBA" else "RGB"
            )
            # Пересборка идёт из сырых байт растра. Через список пикселей это
            # было бы то же самое по смыслу, но в 145 раз дольше и на порядок
            # прожорливее: на пределе MAX_IMAGE_PIXELS список кортежей
            # потребовал бы около 5 ГБ — OOM изнутри собственного санитайзера.
            clean = Image.frombytes(raster.mode, raster.size, raster.tobytes())
            quality = 95 if profile is not CdrProfile.STRICT else 90
            save_opts = {"quality": quality, "optimize": True} if fmt == "JPEG" else {}
            clean.save(dst, format=fmt, **save_opts)

        if not dst.exists() or dst.stat().st_size == 0:
            raise SanitizeError("перекодирование не дало файла")
        if dst.stat().st_size > MAX_SANITIZED_BYTES:
            dst.unlink(missing_ok=True)
            raise SanitizeError("выход CDR превысил лимит размера")

        return SanitizeOutcome(
            path=dst,
            content_type=content_type,
            transforms=["reencode", "strip_exif", "strip_icc", "drop_trailing_data"],
        )

    def verify(self, path: Path) -> list[str]:
        from PIL import Image

        problems: list[str] = []
        with Image.open(path) as img:
            if img.getexif():
                problems.append("exif")
            if img.info.get("icc_profile"):
                problems.append("icc_profile")
        # Хвост после конца изображения — признак не до конца пересобранного файла.
        raw = path.read_bytes()
        if raw.startswith(b"\xff\xd8") and not raw.rstrip(b"\x00").endswith(b"\xff\xd9"):
            problems.append("trailing_data")
        return problems
