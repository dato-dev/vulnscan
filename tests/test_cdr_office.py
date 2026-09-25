"""M6.4 и CDR архивов: активное есть на входе — нет на выходе."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import office_samples as samples
import pytest

from vscommon.models import CdrProfile, ObjectRef, ScanJob
from worker_app.cdr.archive import ZipSanitizer
from worker_app.cdr.base import SanitizeError
from worker_app.cdr.docx import DocxSanitizer
from worker_app.cdr.registry import sanitize
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.filetype_detect import DOCM_MIME, DOCX_MIME, ZIP_MIME
from worker_app.stages.structure import StructureStage

pikepdf = pytest.importorskip("pikepdf")

ACTIVE = [
    "macro_docm",
    "dde_docx",
    "dde_simple_docx",
    "obfuscated_field_docx",
    "remote_template_docx",
    "remote_object_docx",
    "embedded_ole_docx",
    "altchunk_docx",
]


def _analyse(path: Path) -> set[str]:
    ctx = ScanContext(
        job=ScanJob(
            scan_id="s",
            sha256="a" * 64,
            source=ObjectRef(backend="local", bucket="b", key="k"),
            size=path.stat().st_size,
        ),
        path=path,
    )
    FiletypeStage().safe_run(ctx)
    StructureStage().safe_run(ctx)
    return {f.code for f in ctx.findings}


def _write(tmp_path: Path, data: bytes, name: str = "in.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _mime(sample: str) -> str:
    return DOCM_MIME if sample == "macro_docm" else DOCX_MIME


@pytest.mark.parametrize("profile", list(CdrProfile))
@pytest.mark.parametrize("sample", ACTIVE)
def test_active_content_gone_after_rebuild(
    tmp_path: Path, sample: str, profile: CdrProfile
) -> None:
    """Признак есть у входа, нет у выхода — по тому же разбору, что в конвейере."""
    src = _write(tmp_path, getattr(samples, sample)())
    assert _analyse(src), "образец должен давать признак"

    outcome = sanitize(src, tmp_path, _mime(sample), profile)

    assert _analyse(outcome.path) == set()
    assert DocxSanitizer().verify(outcome.path) == []


@pytest.mark.parametrize("profile", list(CdrProfile))
def test_macro_present_on_input_absent_on_output(tmp_path: Path, profile: CdrProfile) -> None:
    """Критерий M6.4 буквально: макрос есть на входе, отсутствует на выходе."""
    src = _write(tmp_path, samples.macro_docm())
    with zipfile.ZipFile(src) as zf:
        assert "word/vbaProject.bin" in zf.namelist()

    outcome = DocxSanitizer().sanitize(src, tmp_path, profile)

    with zipfile.ZipFile(outcome.path) as zf:
        assert not any("vba" in name.lower() for name in zf.namelist())
        assert b"vbaProject" not in zf.read("[Content_Types].xml")
        rels = [n for n in zf.namelist() if n.endswith(".rels")]
        assert all(b"vbaProject" not in zf.read(n) for n in rels)


def test_macro_document_stays_docm(tmp_path: Path) -> None:
    """`.docm` с типом обычного документа Word не откроет вовсе."""
    outcome = DocxSanitizer().sanitize(
        _write(tmp_path, samples.macro_docm()), tmp_path, CdrProfile.STANDARD
    )

    assert outcome.path.suffix == ".docm"
    assert outcome.content_type == DOCM_MIME


def test_standard_keeps_text_and_safe_fields(tmp_path: Path) -> None:
    outcome = DocxSanitizer().sanitize(
        _write(tmp_path, samples.clean_docx()), tmp_path, CdrProfile.STANDARD
    )

    with zipfile.ZipFile(outcome.path) as zf:
        document = zf.read("word/document.xml")
    assert "Договор аренды".encode() in document
    assert b"PAGE" in document  # номер страницы — не угроза
    assert b'mc:Ignorable="w14"' in document


def test_dde_result_text_survives(tmp_path: Path) -> None:
    """Поле уходит, его последний результат остаётся текстом."""
    outcome = DocxSanitizer().sanitize(
        _write(tmp_path, samples.obfuscated_field_docx()), tmp_path, CdrProfile.STANDARD
    )

    with zipfile.ZipFile(outcome.path) as zf:
        document = zf.read("word/document.xml")
    assert "видимое".encode() in document
    assert b"QUOTE" not in document and b"calc" not in document


def test_strict_is_built_from_scratch(tmp_path: Path) -> None:
    """В `strict` нет ни одной части исходника: только то, что собрали мы."""
    outcome = DocxSanitizer().sanitize(
        _write(tmp_path, samples.image_docx()), tmp_path, CdrProfile.STRICT
    )

    with zipfile.ZipFile(outcome.path) as zf:
        names = set(zf.namelist())
        document = zf.read("word/document.xml").decode()
        image = zf.read("word/media/image1.jpeg")
    assert names == {
        "[Content_Types].xml",
        "_rels/.rels",
        "word/document.xml",
        "word/_rels/document.xml.rels",
        "word/media/image1.jpeg",
    }
    assert "Скан паспорта" in document
    assert "ячейка 2" in document and "<w:b/>" in document
    assert image.startswith(b"\xff\xd8")  # перекодировано в JPEG из пикселей


def test_strict_does_not_leak_field_instruction_text(tmp_path: Path) -> None:
    """Результат поля, вложенного в инструкцию, текстом документа не был."""
    outcome = DocxSanitizer().sanitize(
        _write(tmp_path, samples.obfuscated_field_docx()), tmp_path, CdrProfile.STRICT
    )

    with zipfile.ZipFile(outcome.path) as zf:
        document = zf.read("word/document.xml")
    assert b"DDEAUTO" not in document
    assert "видимое".encode() in document


def test_verify_catches_what_rebuild_must_remove(tmp_path: Path) -> None:
    """Верификатор обязан отвергать грязный вход — иначе он ничего не проверяет."""
    for sample in ACTIVE[:-1]:
        assert DocxSanitizer().verify(_write(tmp_path, getattr(samples, sample)())), sample


def test_document_with_dtd_is_refused(tmp_path: Path) -> None:
    """Не разобрали — не пересобираем, и исходник под видом копии не отдаём."""
    with pytest.raises(SanitizeError):
        sanitize(_write(tmp_path, samples.dtd_docx()), tmp_path, DOCX_MIME, CdrProfile.STANDARD)


def test_unknown_part_is_not_carried_over(tmp_path: Path) -> None:
    """Список разрешённого: часть, о которой мы не знаем, в выход не попадает."""
    data = samples.docx(
        samples.paragraph("x"),
        parts={"word/novel/thing.xml": b"<x/>", "word/fonts/font1.odttf": b"\x00" * 64},
    )

    outcome = DocxSanitizer().sanitize(_write(tmp_path, data), tmp_path, CdrProfile.LIGHT)

    with zipfile.ZipFile(outcome.path) as zf:
        assert not any(n.startswith(("word/novel", "word/fonts")) for n in zf.namelist())


def test_metadata_stripped_in_standard_kept_in_light(tmp_path: Path) -> None:
    core = (
        b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
        b'metadata/core-properties"/>'
    )
    data = samples.docx(samples.paragraph("x"), parts={"docProps/core.xml": core})

    src = _write(tmp_path, data)
    (tmp_path / "light").mkdir()
    (tmp_path / "standard").mkdir()

    light = DocxSanitizer().sanitize(src, tmp_path / "light", CdrProfile.LIGHT)
    standard = DocxSanitizer().sanitize(src, tmp_path / "standard", CdrProfile.STANDARD)

    with zipfile.ZipFile(light.path) as zf:
        assert "docProps/core.xml" in zf.namelist()
    with zipfile.ZipFile(standard.path) as zf:
        assert "docProps/core.xml" not in zf.namelist()
    assert "strip_metadata" in standard.transforms


# --- архивы ---


def _pdf_with_js() -> bytes:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS=pikepdf.String("app.alert(1);"))
    )
    buffer = io.BytesIO()
    pdf.save(buffer)
    return buffer.getvalue()


def test_archive_rebuilt_member_by_member(tmp_path: Path) -> None:
    data = samples.zip_of(
        {
            "../../evil.pdf": _pdf_with_js(),
            "Договор.docm": samples.macro_docm(),
            "__MACOSX/._evil.pdf": b"\x00\x05\x16\x07",
            "inner.zip": samples.zip_of({"deep/doc.pdf": _pdf_with_js()}),
            "empty.txt": b"",
        }
    )

    outcome = sanitize(_write(tmp_path, data), tmp_path, ZIP_MIME, CdrProfile.STANDARD)

    with zipfile.ZipFile(outcome.path) as zf:
        names = zf.namelist()
        assert sorted(names) == ["empty.txt", "evil.pdf", "inner.zip", "Договор.docm"]
        assert b"/OpenAction" not in zf.read("evil.pdf")
        assert not any(
            "vba" in n.lower()
            for n in zipfile.ZipFile(io.BytesIO(zf.read("Договор.docm"))).namelist()
        )
        with zipfile.ZipFile(io.BytesIO(zf.read("inner.zip"))) as inner:
            assert b"/OpenAction" not in inner.read("deep/doc.pdf")
    assert {"normalize_paths", "drop_os_metadata"} <= set(outcome.transforms)


def test_member_named_by_its_new_content(tmp_path: Path) -> None:
    """GIF пересобирается в PNG — и называется `.png`, а не `.gif`."""
    from PIL import Image

    gif = io.BytesIO()
    Image.new("RGB", (4, 4)).save(gif, "GIF")
    data = samples.zip_of({"pic.gif": gif.getvalue(), "счёт.pdf.exe": _pdf_with_js()})

    outcome = ZipSanitizer().sanitize(_write(tmp_path, data), tmp_path, CdrProfile.STANDARD)

    with zipfile.ZipFile(outcome.path) as zf:
        assert sorted(zf.namelist()) == ["pic.png", "счёт.pdf.pdf"]


def test_archive_with_unsanitizable_member_is_refused(tmp_path: Path) -> None:
    """Архив без одного файла пользователь принял бы за полный."""
    data = samples.zip_of({"a.pdf": _pdf_with_js(), "notes.txt": b"hello"})

    with pytest.raises(SanitizeError):
        sanitize(_write(tmp_path, data), tmp_path, ZIP_MIME, CdrProfile.STANDARD)


def test_archive_verify_catches_links_and_leftovers(tmp_path: Path) -> None:
    assert "ARCHIVE_SYMLINK" in ZipSanitizer().verify(_write(tmp_path, samples.zip_with_symlink()))
    dirty = samples.zip_of({"a.docm": samples.macro_docm()})
    assert ZipSanitizer().verify(_write(tmp_path, dirty, "dirty.zip"))


def test_archive_bomb_is_not_rebuilt(tmp_path: Path) -> None:
    data = samples.with_declared_size(
        samples.zip_of({"a": b"1", "b": b"2", "c": b"3"}), 3_500_000_000
    )

    with pytest.raises(SanitizeError):
        sanitize(_write(tmp_path, data), tmp_path, ZIP_MIME, CdrProfile.STANDARD)


def test_rebuilt_archive_members_pass_analysis(tmp_path: Path) -> None:
    """Каждое вложение выхода, поданное на вход, признаков не даёт."""
    data = samples.zip_of({"a.pdf": _pdf_with_js(), "b.docx": samples.dde_docx()})

    outcome = sanitize(_write(tmp_path, data), tmp_path, ZIP_MIME, CdrProfile.STANDARD)

    with zipfile.ZipFile(outcome.path) as zf:
        for name in zf.namelist():
            member = _write(tmp_path, zf.read(name), f"member{Path(name).suffix}")
            # Потоки объектов пишет сама пересборка PDF: справочный признак
            # весом 5, а не остаток исходника.
            assert _analyse(member) <= {"PDF_OBJSTM"}, name
