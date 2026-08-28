"""M2.2: покрытие §8 ТЗ. На каждый пункт — синтетический сэмпл.

Сэмплы собираются pikepdf в момент прогона: реальные вредоносные файлы
в репозиторий не кладутся (см. CLAUDE.md).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vscommon.models import ObjectRef, ScanJob
from vscommon.weights import WeightTable
from worker_app.stages import pdf_structure
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.structure import StructureStage

pikepdf = pytest.importorskip("pikepdf")


def _job() -> ScanJob:
    return ScanJob(scan_id="t", sha256="a" * 64, source=ObjectRef(bucket="b", key="k"), size=1)


def scan(path: Path) -> set[str]:
    ctx = ScanContext(job=_job(), path=path, weights=WeightTable())
    FiletypeStage().safe_run(ctx)
    StructureStage().safe_run(ctx)
    return {f.code for f in ctx.findings}


def new_pdf():
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    return pdf


def save(pdf, path: Path) -> Path:
    pdf.save(path)
    return path


def with_marker(tmp_path: Path, name: str, filename: str) -> Path:
    """Документ, содержащий маркер в графе объектов."""
    pdf = new_pdf()
    pdf.Root["/VSMarker"] = pikepdf.Name(name)
    return save(pdf, tmp_path / filename)


# --- §8: JavaScript, OpenAction, AA, Launch ---


def test_javascript_and_openaction(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS=pikepdf.String("app.alert(1)"))
    )
    codes = scan(save(pdf, tmp_path / "js.pdf"))

    assert "PDF_OPENACTION" in codes
    assert "PDF_JAVASCRIPT" in codes


def test_additional_actions(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.pages[0]["/AA"] = pikepdf.Dictionary(O=pikepdf.Dictionary(S=pikepdf.Name("/JavaScript")))
    assert "PDF_AUTO_ACTION" in scan(save(pdf, tmp_path / "aa.pdf"))


def test_launch_action(tmp_path: Path) -> None:
    assert "PDF_LAUNCH" in scan(with_marker(tmp_path, "/Launch", "launch.pdf"))


# --- §8: embedded files, external URLs ---


def test_embedded_file(tmp_path: Path) -> None:
    assert "PDF_EMBEDDED_FILE" in scan(with_marker(tmp_path, "/EmbeddedFile", "embed.pdf"))


def test_external_url(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.Root["/VSLink"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/URI"), URI=pikepdf.String("http://evil.example/x?a=1"))
    )
    codes = scan(save(pdf, tmp_path / "uri.pdf"))
    assert "PDF_EXTERNAL_URI" in codes


def test_external_url_detail_keeps_only_host(tmp_path: Path) -> None:
    """Полный URL может содержать ПДн — в признак попадает только хост."""
    pdf = new_pdf()
    pdf.Root["/VSLink"] = pdf.make_indirect(
        pikepdf.Dictionary(
            S=pikepdf.Name("/URI"), URI=pikepdf.String("https://host.example/passport/12345")
        )
    )
    ctx = ScanContext(job=_job(), path=save(pdf, tmp_path / "uri.pdf"), weights=WeightTable())
    FiletypeStage().safe_run(ctx)
    StructureStage().safe_run(ctx)

    detail = next(f.detail for f in ctx.findings if f.code == "PDF_EXTERNAL_URI")
    assert detail == "host.example"
    assert "passport" not in (detail or "")


# --- §8: suspicious actions ---


@pytest.mark.parametrize(
    ("marker", "code"),
    [
        ("/SubmitForm", "PDF_SUBMITFORM"),
        ("/ImportData", "PDF_IMPORTDATA"),
        ("/GoToE", "PDF_GOTOE"),
        ("/GoToR", "PDF_GOTOR"),
        ("/Rendition", "PDF_RENDITION"),
        ("/Movie", "PDF_MOVIE"),
        ("/Sound", "PDF_SOUND"),
        ("/SetOCGState", "PDF_SETOCGSTATE"),
        ("/RichMedia", "PDF_RICHMEDIA"),
    ],
)
def test_suspicious_actions(tmp_path: Path, marker: str, code: str) -> None:
    assert code in scan(with_marker(tmp_path, marker, "action.pdf"))


def test_xfa_form_detected_by_key(tmp_path: Path) -> None:
    """`/XFA` — короткий ключ, он ищется в графе, а не в байтах файла."""
    pdf = new_pdf()
    pdf.Root["/AcroForm"] = pdf.make_indirect(
        pikepdf.Dictionary(XFA=pikepdf.Array([pikepdf.String("template")]))
    )

    assert "PDF_XFA" in scan(save(pdf, tmp_path / "xfa.pdf"))


def test_javascript_key_detected_in_graph(tmp_path: Path) -> None:
    """`/JS` — три байта: в сжатых данных он встречается случайно."""
    pdf = new_pdf()
    pdf.Root["/VSAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS=pikepdf.String("app.alert(1)"))
    )

    assert "PDF_JS" in scan(save(pdf, tmp_path / "js.pdf"))


def test_random_bytes_do_not_produce_javascript(tmp_path: Path) -> None:
    """Обратный инвариант: 12 МБ сжатых данных давали `/JS` в половине случаев."""
    pdf = new_pdf()
    payload = bytearray()
    value = 0x2545F491
    while len(payload) < 4_000_000:
        value = (value * 1103515245 + 12345) & 0xFFFFFFFF
        payload += value.to_bytes(4, "little")
    pdf.Root["/VSBallast"] = pdf.make_indirect(pikepdf.Stream(pdf, bytes(payload)))
    path = tmp_path / "big.pdf"
    pdf.save(path, compress_streams=False)

    assert b"/JS" in path.read_bytes(), "сэмпл обязан содержать случайную последовательность"
    assert "PDF_JS" not in scan(path)


# --- §8: подозрительные аннотации ---


def _annot(action: str, flags: int = 0, auto: bool = False):
    fields = {
        "Type": pikepdf.Name("/Annot"),
        "Subtype": pikepdf.Name("/Widget"),
        "Rect": pikepdf.Array([0, 0, 10, 10]),
        "F": flags,
        "A": pikepdf.Dictionary(S=pikepdf.Name(action)),
    }
    if auto:
        fields["AA"] = pikepdf.Dictionary(E=pikepdf.Dictionary(S=pikepdf.Name("/JavaScript")))
    return pikepdf.Dictionary(**fields)


def test_annotation_with_action(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.pages[0]["/Annots"] = pikepdf.Array([pdf.make_indirect(_annot("/Launch"))])
    assert "PDF_ANNOT_ACTION" in scan(save(pdf, tmp_path / "annot.pdf"))


def test_hidden_annotation_with_action(tmp_path: Path) -> None:
    """Невидимая аннотация с действием не бывает случайной."""
    pdf = new_pdf()
    pdf.pages[0]["/Annots"] = pikepdf.Array(
        [pdf.make_indirect(_annot("/Launch", flags=pdf_structure.ANNOT_FLAG_HIDDEN))]
    )
    codes = scan(save(pdf, tmp_path / "hidden.pdf"))

    assert "PDF_ANNOT_HIDDEN_ACTION" in codes
    assert "PDF_ANNOT_ACTION" in codes


def test_visible_annotation_is_not_hidden(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.pages[0]["/Annots"] = pikepdf.Array([pdf.make_indirect(_annot("/SubmitForm"))])
    assert "PDF_ANNOT_HIDDEN_ACTION" not in scan(save(pdf, tmp_path / "visible.pdf"))


def test_annotation_with_additional_actions(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.pages[0]["/Annots"] = pikepdf.Array([pdf.make_indirect(_annot("/GoToR", auto=True))])
    assert "PDF_ANNOT_AUTO_ACTION" in scan(save(pdf, tmp_path / "annot_aa.pdf"))


# --- §8: нестандартные streams ---


def test_filter_chain(tmp_path: Path) -> None:
    pdf = new_pdf()
    stream = pikepdf.Stream(pdf, b"x" * 100)
    stream.stream_dict["/Filter"] = pikepdf.Array(
        [
            pikepdf.Name("/FlateDecode"),
            pikepdf.Name("/ASCIIHexDecode"),
            pikepdf.Name("/RunLengthDecode"),
        ]
    )
    pdf.Root["/VSChain"] = pdf.make_indirect(stream)
    assert "PDF_FILTER_CHAIN" in scan(save(pdf, tmp_path / "chain.pdf"))


def test_jbig2_filter_flagged(tmp_path: Path) -> None:
    """Декодер JBIG2 — классический вектор эксплойтов."""
    assert "PDF_JBIG2" in scan(with_marker(tmp_path, "/JBIG2Decode", "jbig2.pdf"))


# --- §8: аномальные размеры ---


def test_stream_decompression_bomb(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.Root["/VSBomb"] = pdf.make_indirect(pikepdf.Stream(pdf, b"\x00" * 2_000_000))
    assert "PDF_STREAM_BOMB" in scan(save(pdf, tmp_path / "bomb.pdf"))


def test_ordinary_document_is_not_a_bomb(tmp_path: Path) -> None:
    assert "PDF_STREAM_BOMB" not in scan(save(new_pdf(), tmp_path / "plain.pdf"))


# --- §8: большое количество объектов ---


def test_too_many_objects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pdf_structure, "MAX_PDF_OBJECTS", 3)
    pdf = new_pdf()
    for i in range(10):
        pdf.Root[f"/VS{i}"] = pdf.make_indirect(pikepdf.Dictionary(N=i))
    assert "PDF_TOO_MANY_OBJECTS" in scan(save(pdf, tmp_path / "many.pdf"))


# --- §8: глубина вложенности ---


def test_deep_nesting(tmp_path: Path) -> None:
    """Обход итеративный: рекурсия здесь дала бы RecursionError вместо признака."""
    pdf = new_pdf()
    node = pikepdf.Dictionary(Leaf=pikepdf.String("x"))
    for _ in range(pdf_structure.MAX_PDF_NESTING_DEPTH + 20):
        node = pikepdf.Dictionary(Child=node)
    pdf.Root["/VSDeep"] = pdf.make_indirect(node)

    assert "PDF_DEEP_NESTING" in scan(save(pdf, tmp_path / "deep.pdf"))


def test_real_document_nesting_is_not_flagged(tmp_path: Path) -> None:
    """У реальных документов медиана глубины 2, p99 — 49. Предел был занижен."""
    pdf = new_pdf()
    node = pikepdf.Dictionary(Leaf=pikepdf.String("x"))
    for _ in range(50):
        node = pikepdf.Dictionary(Child=node)
    pdf.Root["/VSNested"] = pdf.make_indirect(node)

    assert "PDF_DEEP_NESTING" not in scan(save(pdf, tmp_path / "normal.pdf"))


def test_shallow_document_is_not_deep(tmp_path: Path) -> None:
    assert "PDF_DEEP_NESTING" not in scan(save(new_pdf(), tmp_path / "flat.pdf"))


# --- §8: embedded executables ---


def test_embedded_executable(tmp_path: Path) -> None:
    pdf = new_pdf()
    payload = b"MZ\x90\x00\x03" + b"\x00" * 60 + b"This program cannot be run in DOS mode"
    pdf.Root["/VSPayload"] = pdf.make_indirect(pikepdf.Stream(pdf, payload))

    assert "PDF_EMBEDDED_EXECUTABLE" in scan(save(pdf, tmp_path / "exe.pdf"))


def test_elf_payload_detected(tmp_path: Path) -> None:
    pdf = new_pdf()
    pdf.Root["/VSPayload"] = pdf.make_indirect(pikepdf.Stream(pdf, b"\x7fELF" + b"\x00" * 200))

    assert "PDF_EMBEDDED_EXECUTABLE" in scan(save(pdf, tmp_path / "elf.pdf"))


# --- §8: suspicious fonts ---


def _font_pdf(pdf, size: int, count: int = 1):
    """Описатель шрифта со встроенной программой.

    `/Length1` проставляется как в реальных документах: `/Length` у потока —
    это длина после сжатия, и по ней размер шрифта не измерить.
    """
    for i in range(count):
        stream = pikepdf.Stream(pdf, b"\x00" * size)
        stream.stream_dict["/Length1"] = size
        descriptor = pikepdf.Dictionary(Type=pikepdf.Name("/FontDescriptor"), FontFile2=stream)
        pdf.Root[f"/VSFont{i}"] = pdf.make_indirect(descriptor)
    return pdf


def test_embedded_font_reported(tmp_path: Path) -> None:
    pdf = _font_pdf(new_pdf(), size=1000)
    assert "PDF_FONT_EMBEDDED" in scan(save(pdf, tmp_path / "font.pdf"))


def test_oversized_font(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pdf_structure, "MAX_EMBEDDED_FONT_BYTES", 100)
    pdf = _font_pdf(new_pdf(), size=5000)
    assert "PDF_FONT_OVERSIZED" in scan(save(pdf, tmp_path / "bigfont.pdf"))


def test_too_many_fonts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pdf_structure, "MAX_EMBEDDED_FONTS", 2)
    pdf = _font_pdf(new_pdf(), size=100, count=5)
    assert "PDF_TOO_MANY_FONTS" in scan(save(pdf, tmp_path / "fonts.pdf"))


# --- §8: parser anomalies, malformed objects ---


def test_reconstructed_xref(tmp_path: Path) -> None:
    path = save(new_pdf(), tmp_path / "src.pdf")
    broken = tmp_path / "broken.pdf"
    broken.write_bytes(path.read_bytes().replace(b"startxref", b"startxrXf", 1))

    codes = scan(broken)

    assert "PDF_XREF_RECONSTRUCTED" in codes
    assert "PDF_DAMAGED" in codes


def test_malformed_document(tmp_path: Path) -> None:
    path = tmp_path / "junk.pdf"
    path.write_bytes(b"%PDF-1.7\n" + b"\xff" * 500)

    assert "PDF_MALFORMED" in scan(path)


def test_trailing_data_after_eof(tmp_path: Path) -> None:
    """Приклеенный хвост — признак polyglot."""
    path = save(new_pdf(), tmp_path / "tail.pdf")
    path.write_bytes(path.read_bytes() + b"A" * 500)

    assert "PDF_TRAILING_DATA" in scan(path)


def test_newline_after_eof_is_tolerated(tmp_path: Path) -> None:
    """Перевод строки в конце файла — норма, а не приклеенный payload."""
    path = save(new_pdf(), tmp_path / "nl.pdf")
    path.write_bytes(path.read_bytes() + b"\n\r\n")

    assert "PDF_TRAILING_DATA" not in scan(path)


def test_incremental_updates(tmp_path: Path) -> None:
    path = save(new_pdf(), tmp_path / "inc.pdf")
    path.write_bytes(path.read_bytes() + b"\n%%EOF\n")

    assert "PDF_INCREMENTAL_UPDATES" in scan(path)


# --- чистый документ не должен ничего поднимать ---


def test_plain_document_stays_quiet(tmp_path: Path) -> None:
    """Ложные срабатывания на обычном PDF дороже пропущенного тестового эксплойта."""
    codes = scan(save(new_pdf(), tmp_path / "plain.pdf"))

    assert codes - {"PDF_OBJSTM", "PDF_FONT_EMBEDDED"} == set()


# --- ложные срабатывания, найденные на реальных документах ---


def test_word_roundtrip_docx_is_not_polyglot(tmp_path: Path) -> None:
    """Word кладёт исходный .docx внутрь PDF отдельным потоком.

    Такой документ выглядел как polyglot и получал 70 баллов, хотя ZIP лежит
    в теле документа, а не приклеен после `%%EOF`.
    """
    from worker_app.stages.filetype import FiletypeStage

    pdf = new_pdf()
    docx = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"word/document.xml" + b"\x00" * 512
    pdf.Root["/VSMetaOForm"] = pdf.make_indirect(pikepdf.Stream(pdf, docx))
    path = tmp_path / "из-word.pdf"
    # Без сжатия: Word кладёт пакет как есть, и сигнатура видна в байтах файла.
    pdf.save(path, compress_streams=False)

    ctx = ScanContext(job=_job(), path=path, weights=WeightTable())
    FiletypeStage().safe_run(ctx)

    assert b"PK\x03\x04" in path.read_bytes(), "сэмпл обязан содержать сигнатуру ZIP"
    assert "POLYGLOT_ARCHIVE" not in {f.code for f in ctx.findings}


def test_archive_appended_after_eof_is_polyglot(tmp_path: Path) -> None:
    """Обратный инвариант: приклеенный после конца архив по-прежнему виден."""
    from worker_app.stages.filetype import FiletypeStage

    path = save(new_pdf(), tmp_path / "polyglot.pdf")
    path.write_bytes(path.read_bytes() + b"PK\x03\x04" + b"\x00" * 128)

    ctx = ScanContext(job=_job(), path=path, weights=WeightTable())
    FiletypeStage().safe_run(ctx)

    assert "POLYGLOT_ARCHIVE" in {f.code for f in ctx.findings}


def test_short_trailing_data_detected(tmp_path: Path) -> None:
    """Допуск в 64 байта пропускал типичный хвост — он короче."""
    path = save(new_pdf(), tmp_path / "tail.pdf")
    path.write_bytes(path.read_bytes() + b"THIS_IS_TEST_TRAILING_DATA\n")

    assert "PDF_TRAILING_DATA" in scan(path)


def test_small_length_drift_is_tolerated(tmp_path: Path) -> None:
    """Генераторы PDF регулярно ошибаются в длине потока на несколько байт."""
    pdf = new_pdf()
    stream = pikepdf.Stream(pdf, b"x" * 200)
    pdf.Root["/VSData"] = pdf.make_indirect(stream)
    path = save(pdf, tmp_path / "drift.pdf")
    raw = path.read_bytes()
    # Занижаем объявленную длину на пару байт, как это делают кривые генераторы.
    path.write_bytes(raw.replace(b"/Length 200", b"/Length 198", 1))

    assert "PDF_STREAM_LENGTH_MISMATCH" not in scan(path)
