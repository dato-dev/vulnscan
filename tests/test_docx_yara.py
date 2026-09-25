"""YARA по документам Word: правила видят распакованные части, а не сжатый ZIP.

Здесь настоящий `yara-python` и настоящие правила из `rules/yara`: проверяется
не заглушка, а то, что поедет в образ. Где библиотеки нет, тесты пропускаются
— и шлюз `make rules-check` в CI это закрывает.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import office_samples as samples
import pytest

from vscommon.models import CdrProfile, ObjectRef, ScanJob, TenantPolicy, Verdict
from worker_app.cdr.docx import DocxSanitizer
from worker_app.scoring import verdict_of
from worker_app.stages import yara_rules as module
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.filetype_detect import DOCX_MIME
from worker_app.stages.structure import StructureStage
from worker_app.stages.yara_rules import YaraStage

yara = pytest.importorskip("yara")

RULES = Path(__file__).resolve().parents[1] / "rules/yara"


@pytest.fixture()
def stage(monkeypatch: pytest.MonkeyPatch) -> YaraStage:
    monkeypatch.setattr(module.settings, "yara_rules_dir", str(RULES))
    monkeypatch.setattr(module.settings, "yara_enabled", True)
    monkeypatch.setattr(module.settings, "yara_candidate_dir", "")
    return YaraStage()


def _ctx(tmp_path: Path, data: bytes, name: str = "doc.bin") -> ScanContext:
    path = tmp_path / name
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
    return ctx


def _yara_codes(ctx: ScanContext) -> set[str]:
    return {f.code for f in ctx.findings if f.stage == "yara"}


def test_rule_sees_what_compression_hides(tmp_path: Path, stage: YaraStage) -> None:
    """В сжатом документе строки нет; в распакованной части — есть."""
    data = samples.equation_editor_docx()
    assert b"Equation.3" not in data

    ctx = _ctx(tmp_path, data)
    assert stage.safe_run(ctx)

    assert "YARA_DOCX_EQUATION_EDITOR" in _yara_codes(ctx)


def test_finding_names_the_part(tmp_path: Path, stage: YaraStage) -> None:
    ctx = _ctx(tmp_path, samples.equation_editor_docx())
    stage.safe_run(ctx)

    finding = next(f for f in ctx.findings if f.code == "YARA_DOCX_EQUATION_EDITOR")
    assert finding.detail is not None and " в word/" in finding.detail


def test_macro_with_stashed_payload_is_blocked(tmp_path: Path, stage: YaraStage) -> None:
    """Макрос сам по себе — `suspicious`. Макрос плюс нагрузка в переменной —
    схема дроппера, и это два независимых наблюдения."""
    ctx = _ctx(tmp_path, samples.docvar_payload_docm())
    StructureStage().safe_run(ctx)
    stage.safe_run(ctx)

    assert "YARA_DOCX_DOCVAR_PAYLOAD" in _yara_codes(ctx)
    assert verdict_of(ctx, TenantPolicy())[0] is Verdict.MALICIOUS


def test_part_rules_do_not_fire_on_other_formats(tmp_path: Path, stage: YaraStage) -> None:
    """Условие на `part` держит правило внутри документа Word."""
    blob = b"A" * 2000
    data = b'%PDF-1.4\nProgID="Equation.3" <w:docVar w:name="a" w:val="' + blob + b'"/>\n%%EOF'
    ctx = _ctx(tmp_path, data)
    stage.safe_run(ctx)

    assert _yara_codes(ctx) == set()


def test_clean_document_has_no_yara_findings(tmp_path: Path, stage: YaraStage) -> None:
    ctx = _ctx(tmp_path, samples.image_docx())
    stage.safe_run(ctx)

    assert _yara_codes(ctx) == set()


@pytest.mark.parametrize("profile", list(CdrProfile))
@pytest.mark.parametrize("sample", ["equation_editor_docx", "docvar_payload_docm"])
def test_rebuilt_document_no_longer_matches(
    tmp_path: Path, stage: YaraStage, sample: str, profile: CdrProfile
) -> None:
    """То, что нашли правила, пересборка убирает — во всех профилях."""
    src = _ctx(tmp_path, getattr(samples, sample)(), "in.bin")
    outcome = DocxSanitizer().sanitize(src.path, tmp_path, profile)

    ctx = _ctx(tmp_path, outcome.path.read_bytes(), f"out{outcome.path.suffix}")
    stage.safe_run(ctx)

    assert _yara_codes(ctx) == set()


def test_candidate_looks_at_the_same_parts(tmp_path: Path, monkeypatch) -> None:
    """Канарейка обязана видеть то же, что действующий набор.

    Иначе правило-кандидат для Word молчало бы на канарейке и начинало
    срабатывать только после выкатки — ровно то, от чего канарейка защищает.
    """
    active = tmp_path / "active"
    candidate = tmp_path / "candidate"
    active.mkdir()
    candidate.mkdir()
    (active / "a.yar").write_text('rule nothing : low { meta: description = "x" condition: false }')
    (candidate / "c.yar").write_text(
        'rule draft : low { meta: description = "x" strings: $a = "Equation.3" '
        'condition: part != "" and $a }'
    )
    monkeypatch.setattr(module.settings, "yara_rules_dir", str(active))
    monkeypatch.setattr(module.settings, "yara_candidate_dir", str(candidate))
    monkeypatch.setattr(module.settings, "yara_enabled", True)
    seen: list[frozenset[str]] = []
    stage = YaraStage()
    stage.observe_with(lambda _sha, _active, found: seen.append(found))

    ctx = _ctx(tmp_path, samples.equation_editor_docx())
    stage.safe_run(ctx)

    assert seen == [frozenset({"draft"})]
    assert _yara_codes(ctx) == set()


# --- гиперссылки ---


def _with_link(target: str) -> bytes:
    body = '<w:p><w:hyperlink r:id="rIdLink"><w:r><w:t>ссылка</w:t></w:r></w:hyperlink></w:p>'
    return samples.docx(body, rels=[("rIdLink", f"{samples.REL}hyperlink", target, True)])


@pytest.mark.parametrize(
    "target",
    ["ms-msdt:/id PCWDiagnostic", "search-ms:query=x", "file:///C:/Windows/calc.exe", "\\\\h\\s"],
)
def test_hyperlink_that_launches_is_flagged(tmp_path: Path, target: str) -> None:
    ctx = _ctx(tmp_path, _with_link(target))
    StructureStage().safe_run(ctx)

    assert "DOCX_EXTERNAL_LINK" in {f.code for f in ctx.findings}


def test_web_hyperlink_is_not_a_finding(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, _with_link("https://example.invalid/page"))
    StructureStage().safe_run(ctx)

    assert ctx.findings == []


@pytest.mark.parametrize("profile", [CdrProfile.LIGHT, CdrProfile.STANDARD])
def test_rebuild_drops_launching_link_keeps_text(tmp_path: Path, profile: CdrProfile) -> None:
    """Ссылка уходит, текст ссылки остаётся. Веб-ссылка остаётся целиком."""
    src = _ctx(tmp_path, _with_link("ms-msdt:/id PCWDiagnostic"), "in.bin").path
    outcome = DocxSanitizer().sanitize(src, tmp_path, profile)

    with zipfile.ZipFile(outcome.path) as zf:
        document = zf.read("word/document.xml")
        names = zf.namelist()
        rels = (
            zf.read("word/_rels/document.xml.rels")
            if "word/_rels/document.xml.rels" in names
            else b""
        )
    assert b"ms-msdt" not in rels
    assert b"hyperlink" not in document
    assert "ссылка".encode() in document
    assert DocxSanitizer().verify(outcome.path) == []

    (tmp_path / "web").mkdir()
    web = _ctx(tmp_path, _with_link("https://example.invalid/"), "web.bin").path
    kept = DocxSanitizer().sanitize(web, tmp_path / "web", profile)
    with zipfile.ZipFile(kept.path) as zf:
        assert b"example.invalid" in zf.read("word/_rels/document.xml.rels")


def test_verify_rejects_launching_link(tmp_path: Path) -> None:
    src = _ctx(tmp_path, _with_link("ms-msdt:/id x")).path

    assert DocxSanitizer().verify(src)


def test_views_do_not_unpack_a_bomb(tmp_path: Path) -> None:
    """Обход частей для YARA сам по себе не распаковывает бомбу."""
    from worker_app.yara_views import views

    data = samples.with_declared_size(samples.clean_docx(), 3_500_000_000)
    path = tmp_path / "bomb.docx"
    path.write_bytes(data)

    parts = [part for part, _ in views(path, DOCX_MIME)]

    assert parts == [""]
