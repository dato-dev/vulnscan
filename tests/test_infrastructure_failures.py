"""M1.7: отказ инфраструктуры не превращается в вердикт «чисто»."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from vscommon.limits import STAGE_TIMEOUT_S
from vscommon.models import (
    FailMode,
    ObjectRef,
    ScanJob,
    ScanMode,
    TenantPolicy,
    Verdict,
)
from vscommon.storage import LocalStore
from worker_app import pipeline as pipeline_module
from worker_app.failure import should_retry
from worker_app.pipeline import Pipeline
from worker_app.scoring import ESSENTIAL_STAGES, coverage_incomplete, verdict_of
from worker_app.stages.base import ScanContext, Stage

DEFAULT = TenantPolicy()
CLOSED = TenantPolicy(fail_mode=FailMode.FAIL_CLOSED)
OPEN = TenantPolicy(fail_mode=FailMode.FAIL_OPEN)


class BrokenStage(Stage):
    """Стадия, чья зависимость недоступна."""

    def __init__(self, name: str, exc: BaseException) -> None:
        self.name = name
        self._exc = exc

    def run(self, ctx: ScanContext) -> None:
        raise self._exc


class SlowStage(Stage):
    def __init__(self, name: str, seconds: float) -> None:
        self.name = name
        self._seconds = seconds

    def run(self, ctx: ScanContext) -> None:
        time.sleep(self._seconds)


class QuietStage(Stage):
    def __init__(self, name: str) -> None:
        self.name = name

    def run(self, ctx: ScanContext) -> None:
        return None


class NoisyStage(Stage):
    name = "structure"

    def run(self, ctx: ScanContext) -> None:
        ctx.add(self.name, "PDF_LAUNCH", "маркер /Launch")


def _job(**kwargs) -> ScanJob:
    return ScanJob(
        scan_id="scan-1",
        sha256="a" * 64,
        source=ObjectRef(backend="local", bucket="raw", key="a/aaa"),
        size=256,
        mode=ScanMode.DETECT,
        **kwargs,
    )


def _ctx() -> ScanContext:
    return ScanContext(job=_job(), path=Path("/dev/null"))


# --- вердикт на неполном покрытии ---


@pytest.mark.parametrize("stage", sorted(ESSENTIAL_STAGES))
def test_failed_essential_stage_forbids_clean(stage: str) -> None:
    """Главный критерий M1.7 — и та самая дыра, из-за которой clamd молчал."""
    ctx = _ctx()
    BrokenStage(stage, ConnectionError("зависимость недоступна")).safe_run(ctx)

    for policy in (DEFAULT, CLOSED):
        verdict, score = verdict_of(ctx, policy)
        assert verdict is not Verdict.CLEAN
        assert score >= policy.suspicious_threshold


def test_dead_clamav_no_longer_yields_clean() -> None:
    ctx = _ctx()
    BrokenStage("clamav", ConnectionError("clamd не отвечает")).safe_run(ctx)

    assert coverage_incomplete(ctx)
    assert verdict_of(ctx, DEFAULT)[0] is Verdict.SUSPICIOUS


def test_fail_closed_blocks_on_incomplete_coverage() -> None:
    ctx = _ctx()
    BrokenStage("clamav", ConnectionError()).safe_run(ctx)

    assert verdict_of(ctx, CLOSED)[0] is Verdict.MALICIOUS


def test_fail_open_is_the_only_way_to_clean() -> None:
    """Осознанный выбор оператора, а не случайность порогов (см. M1.1)."""
    ctx = _ctx()
    BrokenStage("clamav", ConnectionError()).safe_run(ctx)

    assert verdict_of(ctx, OPEN)[0] is Verdict.CLEAN


def test_non_essential_stage_failure_keeps_clean() -> None:
    """YARA — наши правила поверх AV; их падение покрытия не рушит."""
    ctx = _ctx()
    BrokenStage("yara", RuntimeError("правила не компилируются")).safe_run(ctx)

    assert not coverage_incomplete(ctx)
    assert verdict_of(ctx, DEFAULT)[0] is Verdict.CLEAN


def test_findings_survive_infrastructure_failure() -> None:
    """Отказ AV не должен стирать то, что успел найти структурный анализ."""
    ctx = _ctx()
    NoisyStage().safe_run(ctx)
    BrokenStage("clamav", ConnectionError()).safe_run(ctx)

    verdict, score = verdict_of(ctx, DEFAULT)

    assert verdict is Verdict.MALICIOUS
    assert score >= 85


def test_full_coverage_still_gives_clean() -> None:
    """Инвариант в обратную сторону: исправный сканер не портит чистый файл."""
    ctx = _ctx()
    for stage in ESSENTIAL_STAGES:
        QuietStage(stage).safe_run(ctx)

    assert not coverage_incomplete(ctx)
    assert verdict_of(ctx, DEFAULT)[0] is Verdict.CLEAN


# --- конвейер целиком ---


@pytest.fixture()
def local_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Конвейер на локальном хранилище с подменяемым набором стадий."""
    monkeypatch.setattr(pipeline_module.settings, "work_dir", str(tmp_path / "work"))
    root = tmp_path / "store"
    (root / "raw" / "a").mkdir(parents=True)
    (root / "raw" / "a" / "aaa").write_bytes(b"%PDF-1.7\n" + b"\x00" * 200)

    def build(*stages: Stage) -> Pipeline:
        return Pipeline(LocalStore(str(root)), stages=stages)

    return build


async def test_stage_timeout_counts_as_missing_coverage(
    local_pipeline, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Зависшая стадия — такой же пробел, как упавшая."""
    monkeypatch.setitem(STAGE_TIMEOUT_S, "clamav", 0.05)
    pipe = local_pipeline(QuietStage("filetype"), QuietStage("structure"), SlowStage("clamav", 1.0))

    result = await pipe.process(_job())

    assert result.verdict is not Verdict.CLEAN
    assert "STAGE_TIMEOUT" in {f.code for f in result.findings}
    assert next(t for t in result.stages if t.stage == "clamav").ok is False


async def test_unavailable_clamd_through_pipeline(local_pipeline) -> None:
    pipe = local_pipeline(
        QuietStage("filetype"),
        QuietStage("structure"),
        BrokenStage("clamav", ConnectionError("clamd не отвечает")),
    )

    result = await pipe.process(_job())

    assert result.verdict is Verdict.SUSPICIOUS
    assert "STAGE_FAILED" in {f.code for f in result.findings}


async def test_healthy_pipeline_returns_clean(local_pipeline) -> None:
    pipe = local_pipeline(QuietStage("filetype"), QuietStage("structure"), QuietStage("clamav"))

    result = await pipe.process(_job())

    assert result.verdict is Verdict.CLEAN
    assert result.score == 0


# --- недоступное хранилище ---


class DeadStore(LocalStore):
    def get_to_path(self, ref, dest):  # type: ignore[override]
        raise ConnectionError("S3 не отвечает")


async def test_unavailable_storage_raises_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Файл не скачался — проверять нечего. Задача должна вернуться в очередь."""
    monkeypatch.setattr(pipeline_module.settings, "work_dir", str(tmp_path / "work"))
    pipe = Pipeline(DeadStore(str(tmp_path)), stages=(QuietStage("filetype"),))

    with pytest.raises(ConnectionError) as excinfo:
        await pipe.process(_job())

    # Классификация из M1.3: инфраструктурный сбой ретраится, а не закрывает файл.
    assert should_retry(excinfo.value)
