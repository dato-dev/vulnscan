from __future__ import annotations

from pathlib import Path

from vscommon.models import ObjectRef, ScanJob
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage


def _job(**kwargs) -> ScanJob:
    defaults = {
        "scan_id": "test",
        "sha256": "0" * 64,
        "source": ObjectRef(bucket="b", key="k"),
        "size": 100,
    }
    return ScanJob(**{**defaults, **kwargs})


def test_detects_pdf(tmp_path: Path) -> None:
    path = tmp_path / "f.pdf"
    path.write_bytes(b"%PDF-1.7\n" + b"\x00" * 100)
    ctx = ScanContext(job=_job(), path=path)

    FiletypeStage().run(ctx)

    assert ctx.detected_mime == "application/pdf"
    assert ctx.supported


def test_mime_mismatch_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / "f.pdf"
    path.write_bytes(b"MZ" + b"\x00" * 100)
    ctx = ScanContext(job=_job(declared_mime="application/pdf"), path=path)

    FiletypeStage().run(ctx)

    codes = {f.code for f in ctx.findings}
    assert "MIME_MISMATCH" in codes
    assert "TYPE_EXECUTABLE" in codes


def _jpeg(path: Path, tail: bytes = b"") -> Path:
    """Настоящий JPEG: у него есть маркер конца, после которого и ищем хвост."""
    from PIL import Image

    Image.new("RGB", (32, 32), (128, 128, 128)).save(path, "JPEG")
    if tail:
        path.write_bytes(path.read_bytes() + tail)
    return path


def test_polyglot_archive_after_end_of_image(tmp_path: Path) -> None:
    path = _jpeg(tmp_path / "f.jpg", tail=b"PK\x03\x04" + b"\x00" * 64)
    ctx = ScanContext(job=_job(), path=path)

    FiletypeStage().run(ctx)

    assert "POLYGLOT_ARCHIVE" in {f.code for f in ctx.findings}


def test_archive_signature_inside_image_is_not_polyglot(tmp_path: Path) -> None:
    """Сигнатура внутри данных — не улика: это ловил ложное срабатывание."""
    from PIL import Image

    path = tmp_path / "f.jpg"
    Image.new("RGB", (64, 64), (10, 20, 30)).save(path, "JPEG", comment=b"PK\x03\x04")
    ctx = ScanContext(job=_job(), path=path)

    FiletypeStage().run(ctx)

    assert "POLYGLOT_ARCHIVE" not in {f.code for f in ctx.findings}


def test_stage_failure_becomes_finding(tmp_path: Path) -> None:
    ctx = ScanContext(job=_job(), path=tmp_path / "missing.bin")

    ok = FiletypeStage().safe_run(ctx)

    assert not ok
    assert "STAGE_FAILED" in {f.code for f in ctx.findings}
