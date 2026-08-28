"""Основная гарантия сервиса: активный элемент есть на входе, нет на выходе."""

from __future__ import annotations

from pathlib import Path

import pytest

from vscommon.models import CdrProfile
from worker_app.cdr.pdf import PdfSanitizer

pikepdf = pytest.importorskip("pikepdf")


def _pdf_with_openaction(path: Path) -> Path:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS=pikepdf.String("app.alert(1);"))
    )
    pdf.save(path)
    return path


def test_openaction_removed(tmp_path: Path) -> None:
    src = _pdf_with_openaction(tmp_path / "in.pdf")
    assert b"/OpenAction" in src.read_bytes()

    outcome = PdfSanitizer().sanitize(src, tmp_path, CdrProfile.STANDARD)

    assert PdfSanitizer().verify(outcome.path) == []
    with pikepdf.open(outcome.path) as pdf:
        assert "/OpenAction" not in pdf.Root


def test_metadata_stripped_in_standard(tmp_path: Path) -> None:
    src = _pdf_with_openaction(tmp_path / "in.pdf")

    outcome = PdfSanitizer().sanitize(src, tmp_path, CdrProfile.STANDARD)

    assert "strip_metadata" in outcome.transforms


def test_verify_detects_dangerous_autorun(tmp_path: Path) -> None:
    """Автозапуск, вызывающий действие, из выхода уйти не должен."""
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/Launch"), F=pikepdf.String("calc.exe"))
    )
    dirty = tmp_path / "dirty.pdf"
    pdf.save(dirty)

    assert "/OpenAction" in PdfSanitizer().verify(dirty)


def test_verify_ignores_view_destination(tmp_path: Path) -> None:
    """Ghostscript при растеризации пишет «открыть на такой-то странице».

    Проверка по наличию `/OpenAction` объявляла провал на каждом обычном
    документе, и профиль `strict` не отдавал копию вовсе.
    """
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/OpenAction"] = pikepdf.Array([page.obj, pikepdf.Name("/Fit")])
    clean = tmp_path / "clean.pdf"
    pdf.save(clean)

    assert PdfSanitizer().verify(clean) == []


def test_verify_ignores_internal_navigation(tmp_path: Path) -> None:
    """`/GoTo` — переход внутри документа, это не выполнение."""
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(
            S=pikepdf.Name("/GoTo"), D=pikepdf.Array([page.obj, pikepdf.Name("/Fit")])
        )
    )
    clean = tmp_path / "clean.pdf"
    pdf.save(clean)

    assert PdfSanitizer().verify(clean) == []


def test_registry_wraps_unexpected_parser_errors(tmp_path: Path) -> None:
    """Любая ошибка парсера наружу выходит как SanitizeError, а не как своя."""
    from worker_app.cdr.base import SanitizeError
    from worker_app.cdr.registry import sanitize

    broken = tmp_path / "broken.jpg"
    broken.write_bytes(b"\xff\xd8\xff" + b"\x00" * 64)  # заголовок есть, кадра нет

    with pytest.raises(SanitizeError):
        sanitize(broken, tmp_path, "image/jpeg", CdrProfile.STANDARD)


def test_registry_rejects_unknown_mime(tmp_path: Path) -> None:
    from worker_app.cdr.base import SanitizeError
    from worker_app.cdr.registry import sanitize

    with pytest.raises(SanitizeError):
        sanitize(tmp_path / "x", tmp_path, None, CdrProfile.STANDARD)


def _ballast(size: int) -> bytes:
    """Псевдослучайные байты: в них встречаются любые короткие маркеры."""
    data, value = bytearray(), 0x2545F491
    while len(data) < size:
        value = (value * 1103515245 + 12345) & 0xFFFFFFFF
        data += value.to_bytes(4, "little")
    return bytes(data[:size])


def test_random_bytes_do_not_trip_verification(tmp_path: Path) -> None:
    """M2.7: `/JS` — три байта. В 10 МБ сжатых данных он встречается случайно
    почти в половине случаев, и скан паспорта отвергался бы как грязный."""
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(595, 842))
    payload = _ballast(6_000_000)
    assert b"/JS" in payload or b"/AA" in payload, "сэмпл обязан содержать короткий маркер"
    pdf.Root["/VSBallast"] = pdf.make_indirect(pikepdf.Stream(pdf, payload))
    src = tmp_path / "scan.pdf"
    pdf.save(src)

    outcome = PdfSanitizer().sanitize(src, tmp_path, CdrProfile.STANDARD)

    assert PdfSanitizer().verify(outcome.path) == []


def test_real_javascript_still_caught(tmp_path: Path) -> None:
    """Обратный инвариант: настоящий активный элемент верификация видит."""
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/VSAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS=pikepdf.String("app.alert(1)"))
    )
    dirty = tmp_path / "dirty.pdf"
    pdf.save(dirty)

    problems = PdfSanitizer().verify(dirty)

    assert "/JavaScript" in problems
    assert "/JS" in problems


def test_unparsable_output_fails_verification(tmp_path: Path) -> None:
    """Не разобрали собственный выход — это отказ, а не повод пропустить."""
    broken = tmp_path / "broken.pdf"
    broken.write_bytes(b"%PDF-1.7\n" + b"\xff" * 500)

    assert "unparsable" in PdfSanitizer().verify(broken)
