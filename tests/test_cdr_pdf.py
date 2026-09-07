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


# --- профиль strict: растеризация ------------------------------------------


def _fake_ghostscript(monkeypatch: pytest.MonkeyPatch, pages: int = 2) -> list[list[str]]:
    """Подменяет ghostscript тем, что он и делает: рисует страницы в JPEG.

    Настоящий gs есть в образе воркера, но не на машине разработчика, и
    единственным местом проверки оставался сквозной стенд. Здесь подделан
    ровно внешний инструмент — сборка PDF, лимиты и верификация настоящие.

    Подделка рисует страницы ТОЛЬКО когда её позвали растровым устройством.
    Возврат к `-sDEVICE=pdfwrite` — то есть к передистилляции вместо
    растеризации — не даст ни одного файла, и тест упадёт сам.
    """
    import io

    from PIL import Image

    from worker_app.cdr import pdf as pdf_module

    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> object:
        calls.append(argv)
        device = next((a for a in argv if a.startswith("-sDEVICE=")), "")
        output = next((a for a in argv if a.startswith("-sOutputFile=")), "")
        template = output.removeprefix("-sOutputFile=")

        if device == "-sDEVICE=jpeg" and "%05d" in template:
            frame = Image.new("RGB", (300, 400), (250, 250, 245))
            for number in range(1, pages + 1):
                buf = io.BytesIO()
                frame.save(buf, "JPEG", quality=90)
                Path(template.replace("%05d", f"{number:05d}")).write_bytes(buf.getvalue())

        class _Result:
            returncode = 0
            ok = True

        return _Result()

    monkeypatch.setattr(pdf_module, "run_sandboxed", fake_run)
    return calls


def test_strict_carries_no_object_from_the_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Главное свойство профиля: выход собран из пикселей, а не из документа.

    `-sDEVICE=pdfwrite` разбирал исходник и писал новый PDF, перенося текст и
    аннотации вместе с действиями. Гарантия при этом держалась на чужом
    распознавателе: `/Launch` её пережил, и сквозной стенд поймал это тем, что
    `verify()` отверг собственный выход.
    """
    _fake_ghostscript(monkeypatch, pages=3)
    src = _pdf_with_openaction(tmp_path / "in.pdf")

    outcome = PdfSanitizer().sanitize(src, tmp_path, CdrProfile.STRICT)

    assert PdfSanitizer().verify(outcome.path) == []
    with pikepdf.open(outcome.path) as out:
        assert len(out.pages) == 3
        assert "/OpenAction" not in out.Root
        for page in out.pages:
            names = set(page.Resources.XObject.keys())
            assert names == {"/Im0"}, f"на странице не только растр: {names}"


def test_strict_embeds_the_raster_as_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Байты JPEG уезжают в поток как есть.

    Разжатие страницы ради перекладывания в PDF стоило бы гигабайтов памяти на
    многостраничном документе — OOM внутри собственного санитайзера.
    """
    _fake_ghostscript(monkeypatch, pages=1)
    src = _pdf_with_openaction(tmp_path / "in.pdf")

    outcome = PdfSanitizer().sanitize(src, tmp_path, CdrProfile.STRICT)

    with pikepdf.open(outcome.path) as out:
        image = out.pages[0].Resources.XObject["/Im0"]
        assert image.Filter == pikepdf.Name.DCTDecode
        assert image.read_raw_bytes().startswith(b"\xff\xd8")


def test_strict_fails_loudly_when_nothing_was_drawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ноль нарисованных страниц — отказ, а не пустой «обезвреженный» файл.

    Пустой PDF выглядел бы успехом: вердикт мягчал бы, а клиент получал бы
    документ без содержимого под видом проверенного.
    """
    from worker_app.cdr.base import SanitizeError

    _fake_ghostscript(monkeypatch, pages=0)
    src = _pdf_with_openaction(tmp_path / "in.pdf")

    with pytest.raises(SanitizeError):
        PdfSanitizer().sanitize(src, tmp_path, CdrProfile.STRICT)
