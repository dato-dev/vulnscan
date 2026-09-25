"""M2.4: правила и веса подхватываются без остановки воркера."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vscommon.cache import StructuralCache
from vscommon.models import ObjectRef, ScanJob
from vscommon.storage import LocalStore
from vscommon.weights import WeightTable
from worker_app import pipeline as pipeline_module
from worker_app.pipeline import Pipeline
from worker_app.stages import yara_rules as yara_module
from worker_app.stages.base import ScanContext, Stage
from worker_app.stages.yara_rules import YaraStage

RULE_V1 = 'rule sample : medium { strings: $a = "AAA" condition: $a }'
RULE_V2 = 'rule sample : critical { strings: $a = "BBB" condition: $a }'
RULE_BROKEN = "rule сломанное { это не yara"


@pytest.fixture()
def rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "documents.yar").write_text(RULE_V1)
    monkeypatch.setattr(yara_module.settings, "yara_rules_dir", str(directory))
    return directory


class FakeRules:
    """Заглушка скомпилированных правил: yara-python здесь не установлен."""

    def __init__(self, label: str) -> None:
        self.label = label

    def match(
        self,
        path: str | None = None,
        timeout: int = 0,
        externals: dict | None = None,
        data: bytes | None = None,
    ) -> list:
        return []


def _stage_with_compiler(monkeypatch: pytest.MonkeyPatch, labels: list[str]) -> YaraStage:
    """Стадия, у которой компиляция возвращает очередную метку из списка."""
    stage = YaraStage()
    calls: list[str] = []

    def fake_compile():
        label = labels[len(calls)] if len(calls) < len(labels) else labels[-1]
        calls.append(label)
        if label == "broken":
            raise ValueError("правило не компилируется")
        return FakeRules(label)

    monkeypatch.setattr(stage, "_compile", fake_compile)
    stage.compile_calls = calls  # type: ignore[attr-defined]
    return stage


def _job() -> ScanJob:
    return ScanJob(scan_id="t", sha256="a" * 64, source=ObjectRef(bucket="b", key="k"), size=1)


def _ctx(path: Path) -> ScanContext:
    return ScanContext(job=_job(), path=path, weights=WeightTable())


# --- отпечаток правил ---


def test_fingerprint_changes_with_rules(rules_dir: Path) -> None:
    stage = YaraStage()
    before = stage.rules_fingerprint

    (rules_dir / "documents.yar").write_text(RULE_V2)

    assert YaraStage().rules_fingerprint != before


def test_fingerprint_stable_for_same_content(rules_dir: Path) -> None:
    assert YaraStage().rules_fingerprint == YaraStage().rules_fingerprint


def test_fingerprint_notices_new_file(rules_dir: Path) -> None:
    before = YaraStage().rules_fingerprint

    (rules_dir / "extra.yar").write_text("rule extra : low { condition: false }")

    assert YaraStage().rules_fingerprint != before


# --- перезагрузка ---


def test_rules_replaced_without_restart(
    rules_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Критерий M2.4: подкладываем правило — оно применяется без рестарта."""
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"data")
    stage = _stage_with_compiler(monkeypatch, ["v1", "v2"])
    stage.run(_ctx(sample))
    assert stage._rules.label == "v1"

    (rules_dir / "documents.yar").write_text(RULE_V2)

    assert stage.reload_if_changed()
    assert stage._rules.label == "v2"


def test_reload_changes_cache_key(rules_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Вторая половина критерия: старые записи кэша обесцениваются."""
    stage = _stage_with_compiler(monkeypatch, ["v1", "v2"])
    before = stage.rules_fingerprint
    key_before = StructuralCache._key("a" * 64, "standard", before, "default")

    (rules_dir / "documents.yar").write_text(RULE_V2)
    stage.reload_if_changed()

    key_after = StructuralCache._key("a" * 64, "standard", stage.rules_fingerprint, "default")
    assert key_before != key_after


def test_no_reload_without_changes(rules_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stage = _stage_with_compiler(monkeypatch, ["v1", "v2"])
    stage._ensure_rules()

    assert not stage.reload_if_changed()
    assert len(stage.compile_calls) == 1


def test_touch_without_content_change_does_not_recompile(
    rules_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Перезапись тем же содержимым не должна тратить компиляцию."""
    stage = _stage_with_compiler(monkeypatch, ["v1", "v2"])
    stage._ensure_rules()

    (rules_dir / "documents.yar").write_text(RULE_V1)  # mtime сдвинулся

    assert not stage.reload_if_changed()
    assert len(stage.compile_calls) == 1


# --- главное требование: кривое правило не останавливает проверку ---


def test_broken_rules_keep_previous(
    rules_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Одно кривое правило не должно останавливать проверку файлов."""
    sample = tmp_path / "f.bin"
    sample.write_bytes(b"data")
    stage = _stage_with_compiler(monkeypatch, ["v1", "broken"])
    stage.run(_ctx(sample))

    (rules_dir / "documents.yar").write_text(RULE_BROKEN)

    assert not stage.reload_if_changed()
    assert stage._rules.label == "v1"
    ctx = _ctx(sample)
    stage.run(ctx)
    assert ctx.engines["yara"]["status"] == "ok"


def test_broken_rules_retried_after_fix(rules_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Отметку не двигаем при сбое — иначе исправление не подхватится."""
    stage = _stage_with_compiler(monkeypatch, ["v1", "broken", "v3"])
    stage._ensure_rules()

    (rules_dir / "documents.yar").write_text(RULE_BROKEN)
    assert not stage.reload_if_changed()

    (rules_dir / "documents.yar").write_text(RULE_V2)
    assert stage.reload_if_changed()
    assert stage._rules.label == "v3"


# --- веса тоже подхватываются ---


class QuietStage(Stage):
    name = "filetype"

    def run(self, ctx: ScanContext) -> None:
        return None


def test_weights_reloaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """M2.3 обещал правку весов без пересборки — до перезагрузки нужен был рестарт."""
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"PDF_JS": {"score": 40}}))
    monkeypatch.setattr(pipeline_module.settings, "weights_file", str(path))
    pipe = Pipeline(LocalStore(str(tmp_path)), stages=(QuietStage(),))
    assert pipe._weights.rule_for("PDF_JS").score == 40

    path.write_text(json.dumps({"PDF_JS": {"score": 95}}))

    assert pipe.reload_config()
    assert pipe._weights.rule_for("PDF_JS").score == 95


def test_weights_reload_changes_rules_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"PDF_JS": {"score": 40}}))
    monkeypatch.setattr(pipeline_module.settings, "weights_file", str(path))
    pipe = Pipeline(LocalStore(str(tmp_path)), stages=(QuietStage(),))
    before = pipe.rules_version

    path.write_text(json.dumps({"PDF_JS": {"score": 95}}))
    pipe.reload_config()

    assert pipe.rules_version != before


def test_broken_weights_keep_previous(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"PDF_JS": {"score": 40}}))
    monkeypatch.setattr(pipeline_module.settings, "weights_file", str(path))
    pipe = Pipeline(LocalStore(str(tmp_path)), stages=(QuietStage(),))

    path.write_text("{это не json")

    assert not pipe.reload_config()
    assert pipe._weights.rule_for("PDF_JS").score == 40


def test_reload_is_noop_without_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "weights.json"
    path.write_text(json.dumps({"PDF_JS": {"score": 40}}))
    monkeypatch.setattr(pipeline_module.settings, "weights_file", str(path))
    pipe = Pipeline(LocalStore(str(tmp_path)), stages=(QuietStage(),))

    assert not pipe.reload_config()
