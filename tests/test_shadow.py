"""M3.3: теневой режим — считаем, но не действуем."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fakeredis import aioredis

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "bot"))

from botapp.scanner import ScanOutcome
from vscommon.models import (
    Finding,
    ObjectRef,
    ScanFacts,
    ScanJob,
    ScanMode,
    Severity,
    TenantPolicy,
    Verdict,
)
from vscommon.scoring import should_stop_early, verdict_of
from vscommon.shadow import ShadowLedger
from worker_app.pipeline import Pipeline

SHADOW = TenantPolicy(shadow_mode=True)
NORMAL = TenantPolicy()


def _job(policy: TenantPolicy, **kwargs) -> ScanJob:
    return ScanJob(
        scan_id="t",
        sha256="a" * 64,
        source=ObjectRef(bucket="b", key="k"),
        size=1,
        policy=policy,
        **kwargs,
    )


def _facts(score: int) -> ScanFacts:
    return ScanFacts(
        findings=[Finding(stage="s", code="PDF_LAUNCH", severity=Severity.CRITICAL, score=score)]
    )


# --- вердикт остаётся честным ---


def test_shadow_does_not_soften_the_verdict() -> None:
    """Мы измеряем именно то, что блокировали бы. Подкрашивать вердикт нельзя."""
    assert verdict_of(_facts(85), SHADOW)[0] is Verdict.MALICIOUS
    assert verdict_of(_facts(85), NORMAL)[0] is Verdict.MALICIOUS


def test_shadow_disables_early_exit() -> None:
    """Важно знать, согласился ли антивирус со структурным анализом."""
    assert should_stop_early(_facts(100), NORMAL)
    assert not should_stop_early(_facts(100), SHADOW)


# --- заблокированное всё равно пересобирается ---


def test_blocked_file_is_sanitized_in_shadow() -> None:
    """Иначе режим не покрывает как раз те случаи, ради которых нужен."""
    assert Pipeline._should_sanitize(_job(SHADOW), Verdict.MALICIOUS)
    assert not Pipeline._should_sanitize(_job(NORMAL), Verdict.MALICIOUS)


def test_unscannable_is_never_sanitized() -> None:
    """Пересобирать нечего: содержимое недоступно даже в тени."""
    for verdict in (Verdict.ENCRYPTED, Verdict.UNSUPPORTED):
        assert not Pipeline._should_sanitize(_job(SHADOW), verdict)


def test_detect_only_stays_detect_only() -> None:
    assert not Pipeline._should_sanitize(_job(SHADOW, mode=ScanMode.DETECT), Verdict.MALICIOUS)


# --- клиент не действует по теневому вердикту ---


def test_bot_does_not_block_in_shadow() -> None:
    outcome = ScanOutcome(
        verdict="malicious", score=100, scan_id="s", clean_url="http://x/clean", shadow=True
    )

    assert not outcome.blocking
    assert outcome.deliverable, "в тени пользователь получает копию, а не отказ"


def test_bot_blocks_outside_shadow() -> None:
    outcome = ScanOutcome(
        verdict="malicious", score=100, scan_id="s", clean_url="http://x/clean", shadow=False
    )

    assert outcome.blocking
    assert not outcome.deliverable


def test_shadow_does_not_rescue_unavailable_scanner() -> None:
    """Тень отменяет блокировку, а не отсутствие проверки."""
    outcome = ScanOutcome(verdict="unknown", score=0, scan_id="", available=False, shadow=True)

    assert not outcome.deliverable


def test_shadow_without_artifact_is_not_deliverable() -> None:
    outcome = ScanOutcome(verdict="malicious", score=100, scan_id="s", shadow=True)

    assert not outcome.deliverable


# --- учёт ---


@pytest.fixture()
async def ledger():
    redis = aioredis.FakeRedis(decode_responses=True)
    yield ShadowLedger(redis)
    await redis.aclose()


async def test_ledger_counts_what_would_be_blocked(ledger) -> None:
    await ledger.record("clean", False, [], "a" * 64)
    await ledger.record("clean", False, [], "b" * 64)
    await ledger.record("malicious", True, ["PDF_LAUNCH"], "c" * 64)

    report = await ledger.report()

    assert report.total == 3
    assert report.would_block == 1
    assert report.would_block_ratio == pytest.approx(0.3333, abs=1e-3)
    assert report.by_verdict == {"clean": 2, "malicious": 1}


async def test_ledger_ranks_codes_behind_blocks(ledger) -> None:
    """По какому признаку блокировок больше всего — первый вопрос при разборе."""
    for _ in range(3):
        await ledger.record("malicious", True, ["PDF_LAUNCH", "PDF_JS"], "a" * 64)
    await ledger.record("malicious", True, ["POLYGLOT_ARCHIVE"], "b" * 64)

    top = dict((await ledger.report()).top_codes)

    assert top["PDF_LAUNCH"] == 3
    assert top["POLYGLOT_ARCHIVE"] == 1


async def test_ledger_keeps_no_file_content(ledger) -> None:
    """В журнале только усечённый хэш: содержимое туда попадать не должно."""
    await ledger.record("malicious", True, ["PDF_LAUNCH"], "a" * 64)

    (sample,) = (await ledger.report()).recent_blocks

    assert sample == f"{'a' * 12}:malicious"
    assert len(sample.split(":")[0]) == 12


async def test_refusal_counts_more_than_malicious(ledger) -> None:
    """Файл, который не удалось пересобрать, пользователю тоже не отдадут."""
    await ledger.record("clean", False, [], "a" * 64)
    await ledger.record("malicious", True, ["PDF_LAUNCH"], "b" * 64)
    # unsupported: вердикт не malicious, но копии нет — значит отказ
    await ledger.record("unsupported", True, ["TYPE_UNKNOWN"], "c" * 64)

    report = await ledger.report()

    assert report.total == 3
    assert report.would_block == 2, "отказ по невозможности пересобрать тоже считается"


async def test_ledger_reset(ledger) -> None:
    await ledger.record("malicious", True, ["PDF_LAUNCH"], "a" * 64)
    await ledger.reset()

    report = await ledger.report()

    assert report.total == 0 and report.would_block == 0


# --- снятие блокировки не отменяет пересборку ---


async def test_allowlisted_file_still_gets_sanitized() -> None:
    """Блокировку сняли — значит документ доверенный, и копию надо отдать.

    Заблокированный файл в CDR не идёт, поэтому список применяется ДО решения
    о пересборке, иначе доверенный документ остался бы без копии.
    """
    from worker_app.pipeline import _apply_allowlist

    async def trusted(sha: str, tenant: str | None, verdict: Verdict) -> bool:
        return True

    verdict, allowlisted = await _apply_allowlist(trusted, "a" * 64, None, Verdict.MALICIOUS)

    assert allowlisted
    assert verdict is Verdict.SUSPICIOUS, "блокировки нет, но признаки остаются"
    assert Pipeline._should_sanitize(_job(NORMAL), verdict)


async def test_without_allowlist_nothing_changes() -> None:
    from worker_app.pipeline import _apply_allowlist

    verdict, allowlisted = await _apply_allowlist(None, "a" * 64, None, Verdict.MALICIOUS)

    assert verdict is Verdict.MALICIOUS
    assert not allowlisted
