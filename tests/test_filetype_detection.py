"""M2.1: тип определяется по содержимому, а не по расширению (§2 ТЗ)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vscommon.models import ObjectRef, ScanJob
from vscommon.weights import WeightTable
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.filetype_detect import SIGNATURES, DetectedType, TypeDetector

# Двадцать типов: то, что реально приходит в бота, плюс то, что приходить
# не должно и обязано быть распознано именно поэтому.
SAMPLES: dict[str, tuple[bytes, str]] = {
    "pdf": (b"%PDF-1.7\n" + b"\x00" * 64, "application/pdf"),
    "jpeg": (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 64, "image/jpeg"),
    "png": (b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "image/png"),
    "gif87": (b"GIF87a" + b"\x00" * 64, "image/gif"),
    "gif89": (b"GIF89a" + b"\x00" * 64, "image/gif"),
    "tiff-le": (b"II*\x00" + b"\x00" * 64, "image/tiff"),
    "tiff-be": (b"MM\x00*" + b"\x00" * 64, "image/tiff"),
    "webp": (b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 64, "image/webp"),
    "bmp": (b"BM" + b"\x00" * 64, "image/bmp"),
    "ico": (b"\x00\x00\x01\x00" + b"\x00" * 64, "image/vnd.microsoft.icon"),
    "psd": (b"8BPS" + b"\x00" * 64, "image/vnd.adobe.photoshop"),
    "zip": (b"PK\x03\x04" + b"\x00" * 64, "application/zip"),
    "rar": (b"Rar!\x1a\x07\x00" + b"\x00" * 64, "application/vnd.rar"),
    "7z": (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64, "application/x-7z-compressed"),
    "gzip": (b"\x1f\x8b\x08" + b"\x00" * 64, "application/gzip"),
    "bzip2": (b"BZh9" + b"\x00" * 64, "application/x-bzip2"),
    "xz": (b"\xfd7zXZ\x00" + b"\x00" * 64, "application/x-xz"),
    "ole2": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, "application/x-ole-storage"),
    "rtf": (b"{\\rtf1\\ansi" + b"\x00" * 64, "application/rtf"),
    "postscript": (b"%!PS-Adobe-3.0" + b"\x00" * 64, "application/postscript"),
    "pe": (b"MZ\x90\x00" + b"\x00" * 64, "application/x-dosexec"),
    "elf": (b"\x7fELF\x02\x01\x01" + b"\x00" * 64, "application/x-elf"),
    "mach-o": (b"\xcf\xfa\xed\xfe" + b"\x00" * 64, "application/x-mach-binary"),
    "mp4": (b"\x00\x00\x00\x18ftypisom" + b"\x00" * 64, "video/mp4"),
    "matroska": (b"\x1aE\xdf\xa3" + b"\x00" * 64, "video/x-matroska"),
    "ogg": (b"OggS\x00" + b"\x00" * 64, "audio/ogg"),
    "mp3": (b"ID3\x03\x00" + b"\x00" * 64, "audio/mpeg"),
    "xml": (b'<?xml version="1.0"?>' + b"\x00" * 64, "application/xml"),
    "svg": (b'<svg xmlns="http://www.w3.org/2000/svg">' + b"\x00" * 64, "image/svg+xml"),
}


def _job(**kwargs) -> ScanJob:
    return ScanJob(
        scan_id="t", sha256="a" * 64, source=ObjectRef(bucket="b", key="k"), size=1, **kwargs
    )


def _scan(path: Path, **job_kwargs) -> ScanContext:
    ctx = ScanContext(job=_job(**job_kwargs), path=path, weights=WeightTable())
    FiletypeStage().safe_run(ctx)
    return ctx


# --- таблица сигнатур: работает без системной библиотеки ---


def test_at_least_twenty_types_covered() -> None:
    assert len(SAMPLES) >= 20


@pytest.mark.parametrize(("label", "sample"), sorted(SAMPLES.items()))
def test_type_detected_by_content(tmp_path: Path, label: str, sample: tuple[bytes, str]) -> None:
    data, expected = sample
    path = tmp_path / f"{label}.bin"
    path.write_bytes(data)

    assert _scan(path).detected_mime == expected


def test_detection_works_without_libmagic(tmp_path: Path) -> None:
    """Отсутствие системной библиотеки не должно отключать определение типа."""
    path = tmp_path / "f.pdf"
    path.write_bytes(b"%PDF-1.7\n" + b"\x00" * 64)
    detector = TypeDetector(magic_impl=None)
    detector._checked = True

    detected = detector.detect(path.read_bytes())

    assert detected.mime == "application/pdf"
    assert detected.libmagic_mime is None


# --- главный критерий: расширению не верим ---


def test_pdf_renamed_to_jpg(tmp_path: Path) -> None:
    """Критерий приёмки M2.1."""
    path = tmp_path / "invoice.jpg"
    path.write_bytes(b"%PDF-1.7\n" + b"\x00" * 200)

    ctx = _scan(path, filename_ext=".jpg", declared_mime="image/jpeg")

    assert ctx.detected_mime == "application/pdf"
    codes = {f.code for f in ctx.findings}
    assert "MIME_MISMATCH" in codes
    assert "EXT_MISMATCH" in codes


def test_executable_renamed_to_pdf(tmp_path: Path) -> None:
    path = tmp_path / "договор.pdf"
    path.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

    ctx = _scan(path, filename_ext=".pdf", declared_mime="application/pdf")

    codes = {f.code for f in ctx.findings}
    assert "TYPE_EXECUTABLE" in codes
    assert "MIME_MISMATCH" in codes
    assert not ctx.supported


def test_honest_file_raises_nothing(tmp_path: Path) -> None:
    """Ложные срабатывания на обычном файле дороже пропущенного эксплойта."""
    path = tmp_path / "scan.pdf"
    path.write_bytes(b"%PDF-1.7\n" + b"\x00" * 200)

    ctx = _scan(path, filename_ext=".pdf", declared_mime="application/pdf")

    assert ctx.findings == []
    assert ctx.supported


# --- сигнатура не в начале файла ---


def test_pdf_with_junk_before_signature(tmp_path: Path) -> None:
    """Такой файл открывается просмотрщиком, но обходит проверку смещения 0."""
    path = tmp_path / "shifted.pdf"
    path.write_bytes(b"JUNK" * 30 + b"%PDF-1.7\n" + b"\x00" * 100)

    ctx = _scan(path)

    assert ctx.detected_mime == "application/pdf"
    assert "TYPE_SIGNATURE_OFFSET" in {f.code for f in ctx.findings}


def test_signature_at_zero_is_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "ok.pdf"
    path.write_bytes(b"%PDF-1.7\n" + b"\x00" * 100)

    assert "TYPE_SIGNATURE_OFFSET" not in {f.code for f in _scan(path).findings}


# --- слой libmagic ---


class FakeMagic:
    def __init__(self, answer: str) -> None:
        self._answer = answer

    def from_buffer(self, buf: bytes) -> str:
        return self._answer


def test_libmagic_result_recorded(tmp_path: Path) -> None:
    detector = TypeDetector(magic_impl=FakeMagic("application/pdf"))

    detected = detector.detect(b"%PDF-1.7\n" + b"\x00" * 64)

    assert detected.libmagic_mime == "application/pdf"
    assert not detected.conflict


def test_conflict_between_detectors_is_a_signal() -> None:
    """Уверенное расхождение двух детекторов — сам по себе признак."""
    detector = TypeDetector(magic_impl=FakeMagic("application/pdf"))

    detected = detector.detect(b"\xff\xd8\xff\xe0" + b"\x00" * 64)

    assert detected.mime == "image/jpeg"
    assert detected.conflict


def test_refinement_is_not_a_conflict() -> None:
    """DOCX: libmagic уточняет `application/zip`, а не спорит с ним."""
    ooxml = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    detector = TypeDetector(magic_impl=FakeMagic(ooxml))

    detected = detector.detect(b"PK\x03\x04" + b"\x00" * 64)

    assert detected.mime == "application/zip"
    assert not detected.conflict


def test_libmagic_charset_suffix_stripped() -> None:
    detector = TypeDetector(magic_impl=FakeMagic("text/plain; charset=us-ascii"))

    assert detector.detect(b"hello").libmagic_mime == "text/plain"


def test_broken_libmagic_does_not_break_detection() -> None:
    class Exploding:
        def from_buffer(self, buf: bytes) -> str:
            raise RuntimeError("сломалось")

    detector = TypeDetector(magic_impl=Exploding())

    detected = detector.detect(b"%PDF-1.7\n")

    assert detected.mime == "application/pdf"
    assert detected.libmagic_mime is None


# --- собственный polyglot-детект остаётся ---


def test_polyglot_still_detected(tmp_path: Path) -> None:
    """libmagic сообщает только основной тип и приклеенный хвост не видит."""
    from PIL import Image

    path = tmp_path / "photo.jpg"
    Image.new("RGB", (32, 32)).save(path, "JPEG")
    path.write_bytes(path.read_bytes() + b"PK\x03\x04" + b"\x00" * 64)

    ctx = _scan(path)

    assert ctx.detected_mime == "image/jpeg"
    assert "POLYGLOT_ARCHIVE" in {f.code for f in ctx.findings}


def test_plain_zip_is_not_polyglot(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 300)

    assert "POLYGLOT_ARCHIVE" not in {f.code for f in _scan(path).findings}


def test_every_signature_has_extension() -> None:
    for _offset, _magic, mime, ext in SIGNATURES:
        assert ext.startswith("."), mime


def test_detected_type_without_libmagic_never_conflicts() -> None:
    assert not DetectedType(mime="application/pdf", ext=".pdf").conflict


def test_libmagic_calls_are_serialised() -> None:
    """Объект libmagic держит cookie библиотеки и не потокобезопасен."""
    import threading

    class Counting:
        def __init__(self) -> None:
            self.concurrent = 0
            self.peak = 0
            self._guard = threading.Lock()

        def from_buffer(self, buf: bytes) -> str:
            with self._guard:
                self.concurrent += 1
                self.peak = max(self.peak, self.concurrent)
            try:
                for _ in range(200):
                    pass
                return "application/pdf"
            finally:
                with self._guard:
                    self.concurrent -= 1

    impl = Counting()
    detector = TypeDetector(magic_impl=impl)
    threads = [threading.Thread(target=detector.detect, args=(b"%PDF-1.7\n",)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert impl.peak == 1


@pytest.mark.parametrize("declared", ["application/octet-stream", "binary/octet-stream", ""])
def test_generic_mime_is_not_a_mismatch(tmp_path: Path, declared: str) -> None:
    """Telegram присылает octet-stream для многих документов.

    Это «тип неизвестен», а не заявление о типе: считать расхождением значило
    бы поднимать балл каждому второму файлу.
    """
    path = tmp_path / "scan.pdf"
    path.write_bytes(b"%PDF-1.7\n" + b"\x00" * 200)

    ctx = _scan(path, filename_ext=".pdf", declared_mime=declared)

    assert "MIME_MISMATCH" not in {f.code for f in ctx.findings}


def test_real_mismatch_still_flagged(tmp_path: Path) -> None:
    """Обратный инвариант: honest-to-goodness подмена типа видна."""
    path = tmp_path / "invoice.jpg"
    path.write_bytes(b"%PDF-1.7\n" + b"\x00" * 200)

    ctx = _scan(path, filename_ext=".jpg", declared_mime="image/jpeg")

    assert "MIME_MISMATCH" in {f.code for f in ctx.findings}
