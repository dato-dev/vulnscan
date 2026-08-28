from __future__ import annotations

from pathlib import Path

from vscommon.models import (
    FailMode,
    Finding,
    ObjectRef,
    ScanJob,
    Severity,
    TenantPolicy,
    Verdict,
)
from worker_app.scoring import score_of, should_stop_early, verdict_of, verdict_on_failure
from worker_app.stages.base import ScanContext

POLICY = TenantPolicy()


def _ctx() -> ScanContext:
    job = ScanJob(scan_id="t", sha256="0" * 64, source=ObjectRef(bucket="b", key="k"), size=1)
    return ScanContext(job=job, path=Path("/dev/null"))


def _finding(score: int) -> Finding:
    return Finding(stage="t", code="T", severity=Severity.HIGH, score=score)


def test_critical_finding_saturates_score() -> None:
    assert score_of([_finding(100), _finding(20)]) == 100


def test_clean_when_no_findings() -> None:
    verdict, score = verdict_of(_ctx(), POLICY)
    assert verdict is Verdict.CLEAN
    assert score == 0


def test_suspicious_between_thresholds() -> None:
    ctx = _ctx()
    ctx.findings.append(_finding(45))
    verdict, _ = verdict_of(ctx, POLICY)
    assert verdict is Verdict.SUSPICIOUS


def test_encrypted_never_clean() -> None:
    ctx = _ctx()
    ctx.encrypted = True
    verdict, _ = verdict_of(ctx, POLICY)
    assert verdict is Verdict.ENCRYPTED


def test_thresholds_come_from_tenant_policy() -> None:
    """Строгий тенант блокирует то, что дефолтный считает подозрительным."""
    ctx = _ctx()
    ctx.findings.append(_finding(45))
    strict = TenantPolicy(tenant="strict", block_threshold=40, suspicious_threshold=10)

    assert verdict_of(ctx, POLICY)[0] is Verdict.SUSPICIOUS
    assert verdict_of(ctx, strict)[0] is Verdict.MALICIOUS


def test_early_exit_at_block_threshold() -> None:
    ctx = _ctx()
    ctx.findings.append(_finding(100))
    assert should_stop_early(ctx, POLICY)


def test_fail_mode_maps_to_verdict() -> None:
    assert verdict_on_failure(TenantPolicy(fail_mode=FailMode.FAIL_OPEN)) is Verdict.CLEAN
    assert verdict_on_failure(TenantPolicy(fail_mode=FailMode.FAIL_CLOSED)) is Verdict.MALICIOUS
    assert verdict_on_failure(TenantPolicy(fail_mode=FailMode.SUSPICIOUS)) is Verdict.SUSPICIOUS


def test_default_fail_mode_is_not_open() -> None:
    """Дефолт обязан быть безопасным: молчаливый fail-open недопустим."""
    assert TenantPolicy().fail_mode is not FailMode.FAIL_OPEN
    assert verdict_on_failure(TenantPolicy()) is not Verdict.CLEAN
