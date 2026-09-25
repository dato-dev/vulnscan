"""M6.3: разбор документа Word и безопасный разбор его XML."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import office_samples as samples
import pytest

from vscommon.models import ObjectRef, ScanJob, TenantPolicy, Verdict
from worker_app import ooxml
from worker_app.scoring import verdict_of
from worker_app.stages.base import ScanContext
from worker_app.stages.docx_structure import is_remote
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.structure import StructureStage


def _scan(tmp_path: Path, data: bytes) -> ScanContext:
    path = tmp_path / "doc.bin"
    path.write_bytes(data)
    ctx = ScanContext(
        job=ScanJob(
            scan_id="s",
            sha256="a" * 64,
            source=ObjectRef(backend="local", bucket="b", key="k"),
            size=len(data),
        ),
        path=path,
    )
    FiletypeStage().safe_run(ctx)
    StructureStage().safe_run(ctx)
    return ctx


def _codes(ctx: ScanContext) -> set[str]:
    return {f.code for f in ctx.findings}


def test_clean_document_has_no_findings(tmp_path: Path) -> None:
    ctx = _scan(tmp_path, samples.clean_docx())

    assert _codes(ctx) == set()
    assert verdict_of(ctx, TenantPolicy())[0] is Verdict.CLEAN


@pytest.mark.parametrize(
    ("sample", "code"),
    [
        ("macro_docm", "DOCX_VBA"),
        ("dde_docx", "DOCX_DDE"),
        ("dde_simple_docx", "DOCX_DDE"),
        ("obfuscated_field_docx", "DOCX_FIELD_OBFUSCATED"),
        ("remote_template_docx", "DOCX_EXTERNAL_TEMPLATE"),
        ("remote_object_docx", "DOCX_EXTERNAL_OBJECT"),
        ("embedded_ole_docx", "DOCX_OLE_OBJECT"),
        ("altchunk_docx", "DOCX_ALTCHUNK"),
        ("dtd_docx", "DOCX_DTD"),
    ],
)
def test_active_content_found(tmp_path: Path, sample: str, code: str) -> None:
    ctx = _scan(tmp_path, getattr(samples, sample)())

    assert code in _codes(ctx)


def test_split_dde_is_found_where_text_search_fails(tmp_path: Path) -> None:
    """Инструкция DDE, разрезанная по прогонам, в тексте части не видна."""
    data = samples.dde_docx()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert b"DDEAUTO" not in zf.read("word/document.xml")

    assert "DOCX_DDE" in _codes(_scan(tmp_path, data))


def test_dde_hidden_in_tracked_deletion(tmp_path: Path) -> None:
    """Удалённая инструкция возвращается кнопкой «отклонить исправление»."""
    body = (
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:del w:id="1" w:author="a"><w:r><w:delInstrText>DDEAUTO calc x</w:delInstrText>'
        "</w:r></w:del>"
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )

    assert "DOCX_DDE" in _codes(_scan(tmp_path, samples.docx(body)))


def test_dde_blocks_by_default(tmp_path: Path) -> None:
    ctx = _scan(tmp_path, samples.dde_docx())

    assert verdict_of(ctx, TenantPolicy())[0] is Verdict.MALICIOUS


def test_macro_alone_is_suspicious_not_blocked(tmp_path: Path) -> None:
    """Макрос уберёт пересборка, и пользователь получит документ без него."""
    ctx = _scan(tmp_path, samples.macro_docm())

    assert verdict_of(ctx, TenantPolicy())[0] is Verdict.SUSPICIOUS


def test_linked_ole_is_counted_once(tmp_path: Path) -> None:
    """Связанный по сети объект — внешняя связь, а не встроенный объект."""
    ctx = _scan(tmp_path, samples.remote_object_docx())

    assert "DOCX_OLE_OBJECT" not in _codes(ctx)


def test_template_on_authors_disk_is_not_a_finding(tmp_path: Path) -> None:
    assert _codes(_scan(tmp_path, samples.local_template_docx())) == set()


@pytest.mark.parametrize(
    "target",
    [
        "https://example.invalid/t.dotm",
        "\\\\host\\share\\t.dotm",
        "file://host/share/t.dotm",
        "mhtml:http://example.invalid/x!y",
    ],
)
def test_remote_targets(target: str) -> None:
    assert is_remote(target)


def test_local_template_is_not_remote() -> None:
    assert not is_remote("file:///C:/Users/a/Templates/Report.dotx")


def test_external_address_not_copied_into_finding(tmp_path: Path) -> None:
    """Адрес — содержимое файла; подробность признака уходит в историю."""
    ctx = _scan(tmp_path, samples.remote_template_docx())

    assert all("example.invalid" not in (f.detail or "") for f in ctx.findings)


def test_docx_bomb_is_caught(tmp_path: Path) -> None:
    """Документ — тоже ZIP, и бомба в нём та же."""
    data = samples.with_declared_size(samples.clean_docx(), 3_500_000_000)

    assert "ARCHIVE_BOMB" in _codes(_scan(tmp_path, data))


def test_broken_part_is_not_clean(tmp_path: Path) -> None:
    ctx = _scan(tmp_path, samples.docx(document_xml="<w:document"))

    assert "DOCX_MALFORMED" in _codes(ctx)
    assert verdict_of(ctx, TenantPolicy())[0] is not Verdict.CLEAN


# --- разбор XML ---


def test_entity_is_refused_not_expanded() -> None:
    """Billion laughs: объявление сущности — отказ до раскрытия."""
    laughs = (
        b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
        b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
        b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><l>&c;</l>'
    )

    with pytest.raises(ooxml.DtdError):
        ooxml.parse(laughs)
    with pytest.raises(ooxml.DtdError):
        list(ooxml.scan_fields(laughs))


def test_external_entity_is_refused() -> None:
    xxe = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'

    with pytest.raises(ooxml.DtdError):
        ooxml.parse(xxe)


def test_deep_nesting_is_refused() -> None:
    deep = b"<a>" * (ooxml.MAX_DEPTH + 1) + b"</a>" * (ooxml.MAX_DEPTH + 1)

    with pytest.raises(ooxml.XmlError):
        ooxml.parse(deep)


def test_round_trip_keeps_prefixes_word_refers_to() -> None:
    """`mc:Ignorable="w14"` называет префикс по имени.

    ElementTree при записи переименовал бы его в `ns1`, и Word объявил бы
    документ повреждённым. Сериализатор свой ровно поэтому.
    """
    with zipfile.ZipFile(io.BytesIO(samples.clean_docx())) as zf:
        part = ooxml.parse(zf.read("word/document.xml"))

    out = ooxml.serialize(part)

    assert b'mc:Ignorable="w14"' in out
    assert b'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"' in out
    assert ooxml.serialize(ooxml.parse(out)) == out


def test_text_survives_round_trip() -> None:
    raw = (
        f'<w:p xmlns:w="{ooxml.W}"><w:r><w:t xml:space="preserve"> a &amp; b &lt;c&gt; </w:t>'
        "</w:r></w:p>"
    ).encode()

    part = ooxml.parse(ooxml.serialize(ooxml.parse(raw)))

    text = part.root.find(f"{ooxml.w('r')}/{ooxml.w('t')}")
    assert text is not None and text.text == " a & b <c> "
    assert text.get(f"{{{ooxml.XML_NS}}}space") == "preserve"


def test_strip_keeps_page_number_and_removes_dde() -> None:
    body = samples.field(["PAGE"], "7") + samples.field(["DDE", "AUTO calc"], "видно")
    part = ooxml.parse(f'<w:body xmlns:w="{ooxml.W}">{body}</w:body>'.encode())

    removed = ooxml.strip_fields(part.root, keep_safe=True)

    out = ooxml.serialize(part)
    assert removed == 1
    assert b"PAGE" in out and b"DDE" not in out
    # Результат поля остаётся: текст, который видел автор, на месте.
    assert "видно".encode() in out
    assert set(ooxml.scan_fields(out)) == {"safe"}


def test_unclosed_field_is_removed() -> None:
    """Поле без конца Word всё равно выполнит. Оставлять его нельзя."""
    raw = (
        f'<w:p xmlns:w="{ooxml.W}"><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        "<w:r><w:instrText>DDEAUTO calc</w:instrText></w:r></w:p>"
    ).encode()
    part = ooxml.parse(raw)

    ooxml.strip_fields(part.root, keep_safe=True)

    assert b"DDEAUTO" not in ooxml.serialize(part)
    assert "dde" in set(ooxml.scan_fields(raw))
