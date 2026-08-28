"""M2.3: веса Risk Engine — конфигурация, а не литералы в коде стадий."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vscommon.models import ObjectRef, ScanJob, Severity, TenantPolicy, Verdict
from vscommon.weights import DEFAULT_WEIGHTS, FALLBACK, WeightTable
from worker_app.scoring import verdict_of
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.structure import StructureStage


def _job(**kwargs) -> ScanJob:
    return ScanJob(
        scan_id="t", sha256="a" * 64, source=ObjectRef(bucket="b", key="k"), size=1, **kwargs
    )


def _ctx(weights: WeightTable | None = None) -> ScanContext:
    return ScanContext(job=_job(), path=Path("/dev/null"), weights=weights or WeightTable())


# --- таблица весов ---


def test_builtin_defaults_work_without_config() -> None:
    """Сервис обязан работать и без внешнего файла."""
    table = WeightTable.load(None)

    assert table.rule_for("PDF_LAUNCH").score == 85
    assert table.rule_for("PDF_LAUNCH").severity is Severity.CRITICAL


def test_missing_file_falls_back_to_builtins() -> None:
    table = WeightTable.load("/такого/файла/нет.json")

    assert table.rule_for("PDF_LAUNCH").score == 85


def test_file_overrides_builtins(tmp_path: Path) -> None:
    """Критерий приёмки: правка порога — правка конфига, не пересборка."""
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"PDF_EXTERNAL_URI": {"score": 55, "severity": "high"}}))

    table = WeightTable.load(str(path))

    assert table.rule_for("PDF_EXTERNAL_URI").score == 55
    assert table.rule_for("PDF_EXTERNAL_URI").severity is Severity.HIGH
    assert table.rule_for("PDF_LAUNCH").score == 85  # остальные не тронуты


def test_file_can_omit_severity(tmp_path: Path) -> None:
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"PDF_JS": {"score": 70}}))

    rule = WeightTable.load(str(path)).rule_for("PDF_JS")

    assert rule.score == 70
    assert rule.severity is DEFAULT_WEIGHTS["PDF_JS"].severity


def test_comment_keys_ignored(tmp_path: Path) -> None:
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"_комментарий": "текст", "PDF_JS": {"score": 70}}))

    table = WeightTable.load(str(path))

    assert table.rule_for("PDF_JS").score == 70
    assert "_комментарий" not in table._rules


def test_unknown_code_gets_visible_fallback() -> None:
    """Забытый в таблице код должен быть заметен в вердикте, а не исчезать."""
    table = WeightTable()

    rule = table.rule_for("СОВСЕМ_НОВЫЙ_ПРИЗНАК")

    assert rule == FALLBACK
    assert rule.score > 0
    assert "СОВСЕМ_НОВЫЙ_ПРИЗНАК" in table.unknown_codes


# --- переопределения тенанта ---


def test_tenant_overrides_only_scores() -> None:
    table = WeightTable().with_overrides({"PDF_EXTERNAL_URI": 40})

    rule = table.rule_for("PDF_EXTERNAL_URI")

    assert rule.score == 40
    assert rule.severity is DEFAULT_WEIGHTS["PDF_EXTERNAL_URI"].severity


def test_empty_overrides_reuse_same_table() -> None:
    table = WeightTable()

    assert table.with_overrides({}) is table


def _scan(path: Path, weights: WeightTable) -> ScanContext:
    """Полный проход дешёвых стадий: structure диспетчеризуется по типу файла."""
    ctx = ScanContext(job=_job(), path=path, weights=weights)
    FiletypeStage().safe_run(ctx)
    StructureStage().safe_run(ctx)
    return ctx


def test_tenant_override_changes_verdict(tmp_path: Path) -> None:
    """Один и тот же файл — разный вердикт у тенантов с разной чувствительностью."""
    pikepdf = pytest.importorskip("pikepdf")
    # Документ обязан быть валидным: битая структура добавила бы PDF_MALFORMED
    # и вердикт менялся бы не из-за весов, а из-за постороннего признака.
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    pdf.Root["/VSMarker"] = pikepdf.Name("/GoToR")
    path = tmp_path / "doc.pdf"
    pdf.save(path)
    policy = TenantPolicy()

    relaxed = _scan(path, WeightTable())
    strict = _scan(path, WeightTable().with_overrides({"PDF_GOTOR": 90}))

    assert "PDF_GOTOR" in {f.code for f in relaxed.findings}
    assert verdict_of(relaxed, policy)[0] is Verdict.CLEAN
    assert verdict_of(strict, policy)[0] is Verdict.MALICIOUS


# --- стадии больше не назначают веса сами ---


def test_stage_cannot_invent_weight(tmp_path: Path) -> None:
    """Балл приходит из таблицы, даже если стадия о ней ничего не знает."""
    path = tmp_path / "f.pdf"
    path.write_bytes(b"%PDF-1.7\n/OpenAction 1 0 R\n" + b"\x00" * 100)

    ctx = _scan(path, WeightTable().with_overrides({"PDF_OPENACTION": 7}))

    found = next(f for f in ctx.findings if f.code == "PDF_OPENACTION")
    assert found.score == 7
    assert found.severity is DEFAULT_WEIGHTS["PDF_OPENACTION"].severity


def test_shipped_example_file_is_valid() -> None:
    """Пример из репозитория должен грузиться и не ломать существующие коды."""
    table = WeightTable.load("weights.example.json")

    assert table.rule_for("PDF_LAUNCH").score == 85
    assert table.rule_for("YARA:critical").score == 95


def test_real_corpus_uses_only_known_codes(tmp_path: Path) -> None:
    """Ни один признак реальных стадий не должен попадать в запасной вес."""
    table = WeightTable()
    samples = {
        "plain.pdf": b"%PDF-1.7\n" + b"\x00" * 200,
        "active.pdf": b"%PDF-1.7\n/OpenAction /JS /Launch /EmbeddedFile /XFA\n" + b"\x00" * 100,
        "poly.jpg": b"\xff\xd8\xff" + b"\x00" * 200 + b"PK\x03\x04",
        "weird.bin": b"\x01\x02\x03\x04" * 50,
    }

    for name, data in samples.items():
        path = tmp_path / name
        path.write_bytes(data)
        ctx = ScanContext(job=_job(declared_mime="application/pdf"), path=path, weights=table)
        FiletypeStage().safe_run(ctx)
        StructureStage().safe_run(ctx)

    assert table.unknown_codes == set()


@pytest.mark.parametrize("code", sorted(DEFAULT_WEIGHTS))
def test_every_default_weight_is_sane(code: str) -> None:
    rule = DEFAULT_WEIGHTS[code]

    assert 0 <= rule.score <= 100
    assert isinstance(rule.severity, Severity)


def test_duplicate_code_counted_once(tmp_path: Path) -> None:
    """Две проверки, нашедшие одно свойство, не удваивают его вес."""
    ctx = _ctx()

    ctx.add("structure", "PDF_STREAM_BOMB", "в отдельном потоке")
    ctx.add("structure", "PDF_STREAM_BOMB", "суммарно по документу")

    assert len(ctx.findings) == 1
    assert ctx.findings[0].detail == "в отдельном потоке"
    assert ctx.current_score() == DEFAULT_WEIGHTS["PDF_STREAM_BOMB"].score


def test_directory_instead_of_weights_file(tmp_path: Path) -> None:
    """Тот же промах bind-mount, что и с политиками."""
    fake = tmp_path / "weights.json"
    fake.mkdir()

    table = WeightTable.load(str(fake))

    assert table.rule_for("PDF_LAUNCH").score == 85
    assert not table.degraded


def test_broken_weights_file_is_degraded(tmp_path: Path) -> None:
    path = tmp_path / "weights.json"
    path.write_text("{это не json")

    table = WeightTable.load(str(path))

    assert table.degraded
    assert table.rule_for("PDF_LAUNCH").score == 85
