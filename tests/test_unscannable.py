"""M1.6: непроверяемый файл никогда не выдаётся за чистый."""

from __future__ import annotations

from pathlib import Path

import pytest

from vscommon.models import (
    UNSCANNABLE_VERDICTS,
    CdrProfile,
    FailMode,
    ObjectRef,
    ScanJob,
    ScanMode,
    ScanResult,
    ScanStatus,
    TenantPolicy,
    Verdict,
)
from worker_app.pipeline import Pipeline
from worker_app.scoring import apply_failure, verdict_of
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.structure import StructureStage

pikepdf = pytest.importorskip("pikepdf")

POLICY = TenantPolicy()
OPEN_POLICY = TenantPolicy(fail_mode=FailMode.FAIL_OPEN)
LOOSE_POLICY = TenantPolicy(suspicious_threshold=50, block_threshold=90)
"""Тенант с высокими порогами — именно на нём старая ошибка проявлялась."""


def _job(**kwargs) -> ScanJob:
    return ScanJob(
        scan_id="t",
        sha256="a" * 64,
        source=ObjectRef(bucket="b", key="k"),
        size=1024,
        **kwargs,
    )


def _pdf(path: Path, **encryption: object) -> Path:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    if encryption:
        pdf.save(path, encryption=pikepdf.Encryption(**encryption))
    else:
        pdf.save(path)
    return path


def _scan(path: Path) -> ScanContext:
    ctx = ScanContext(job=_job(), path=path)
    FiletypeStage().safe_run(ctx)
    StructureStage().safe_run(ctx)
    return ctx


# --- главный критерий приёмки ---


def test_password_protected_pdf_is_never_clean(tmp_path: Path) -> None:
    """PDF с паролем пользователя не получает clean ни при какой политике."""
    ctx = _scan(_pdf(tmp_path / "locked.pdf", user="secret", owner="secret", R=6))

    for policy in (POLICY, LOOSE_POLICY, OPEN_POLICY):
        verdict, score = verdict_of(ctx, policy)
        assert verdict is Verdict.ENCRYPTED
        assert verdict is not Verdict.CLEAN
        assert score >= policy.suspicious_threshold


def test_password_protected_pdf_detected_as_encrypted_not_malformed(tmp_path: Path) -> None:
    """Раньше PasswordError падал в PDF_MALFORMED, и флаг шифрования терялся."""
    ctx = _scan(_pdf(tmp_path / "locked.pdf", user="secret", owner="secret", R=6))

    codes = {f.code for f in ctx.findings}
    assert "PDF_ENCRYPTED" in codes
    assert ctx.encrypted


def test_loose_thresholds_no_longer_leak_clean(tmp_path: Path) -> None:
    """Вердикт не должен зависеть от того, перевесил ли чужой признак порог."""
    ctx = _scan(_pdf(tmp_path / "locked.pdf", user="pw", owner="pw", R=6))
    ctx.findings = [f for f in ctx.findings if f.code == "PDF_ENCRYPTED"]

    verdict, _ = verdict_of(ctx, TenantPolicy(suspicious_threshold=99, block_threshold=100))

    assert verdict is Verdict.ENCRYPTED


# --- владельческий пароль: содержимое читается ---


def test_owner_password_pdf_stays_scannable(tmp_path: Path) -> None:
    """Пустой пароль пользователя — документ читается, проверяем как обычный."""
    ctx = _scan(_pdf(tmp_path / "owner.pdf", user="", owner="ownerpw", R=6))

    codes = {f.code for f in ctx.findings}
    assert "PDF_ENCRYPTED_OWNER" in codes
    assert "PDF_ENCRYPTED" not in codes
    assert not ctx.encrypted
    assert verdict_of(ctx, POLICY)[0] is not Verdict.ENCRYPTED


def test_plain_pdf_has_no_encryption_findings(tmp_path: Path) -> None:
    ctx = _scan(_pdf(tmp_path / "plain.pdf"))

    codes = {f.code for f in ctx.findings}
    assert not codes & {"PDF_ENCRYPTED", "PDF_ENCRYPTED_OWNER"}
    assert verdict_of(ctx, POLICY)[0] is Verdict.CLEAN


# --- неподдерживаемый формат ---


def test_unsupported_format_gets_score_floor(tmp_path: Path) -> None:
    """Иначе клиент с пороговой политикой увидит «почти чисто» у непроверенного."""
    path = tmp_path / "strange.bin"
    path.write_bytes(b"\x00\x01\x02\x03" * 64)
    ctx = _scan(path)

    verdict, score = verdict_of(ctx, POLICY)

    assert verdict is Verdict.UNSUPPORTED
    assert score >= POLICY.suspicious_threshold


# --- непроверяемое не идёт в CDR ---


@pytest.mark.parametrize("verdict", sorted(UNSCANNABLE_VERDICTS))
def test_unscannable_skips_cdr(verdict: Verdict) -> None:
    """Пересобирать нечего, а падение CDR перезаписывало бы вердикт."""
    assert not Pipeline._should_sanitize(_job(mode=ScanMode.BOTH), verdict)


def test_clean_file_still_sanitized() -> None:
    assert Pipeline._should_sanitize(_job(mode=ScanMode.BOTH), Verdict.CLEAN)
    assert Pipeline._should_sanitize(_job(profile=CdrProfile.STRICT), Verdict.SUSPICIOUS)


def test_malicious_skips_cdr() -> None:
    assert not Pipeline._should_sanitize(_job(), Verdict.MALICIOUS)


# --- инвариант: сбой не смягчает вердикт ---


@pytest.mark.parametrize(
    "current",
    [Verdict.ENCRYPTED, Verdict.UNSUPPORTED, Verdict.SUSPICIOUS, Verdict.MALICIOUS],
)
def test_failure_never_softens_verdict(current: Verdict) -> None:
    """Даже fail-open не имеет права превратить найденное в clean."""
    assert apply_failure(current, OPEN_POLICY) is current


def test_failure_applies_only_to_clean() -> None:
    assert apply_failure(Verdict.CLEAN, POLICY) is Verdict.SUSPICIOUS
    assert apply_failure(Verdict.CLEAN, OPEN_POLICY) is Verdict.CLEAN


# --- признак для клиента ---


def test_result_reports_unscannable() -> None:
    result = ScanResult(
        scan_id="s", sha256="a" * 64, status=ScanStatus.DONE, verdict=Verdict.ENCRYPTED
    )

    assert result.unscannable()
    assert result.sanitized is None
    assert not result.blocked()
