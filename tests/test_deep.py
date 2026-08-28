"""M5.4 и M5.5: углублённая проверка и выборка чистых."""

from __future__ import annotations

import pytest

from vscommon.models import (
    CdrProfile,
    ObjectRef,
    ScanJob,
    ScanMode,
    ScanResult,
    ScanStatus,
    TenantPolicy,
    Verdict,
)
from worker_app.deep import GREY_ZONE, SAMPLED, UNSCANNABLE_RETRY, deep_job, deep_reason
from worker_app.pipeline import Pipeline

POLICY = TenantPolicy()


def _job(**kwargs) -> ScanJob:
    return ScanJob(
        scan_id="быстрый",
        sha256="a" * 64,
        source=ObjectRef(bucket="b", key="k"),
        size=1,
        **kwargs,
    )


def _result(verdict: Verdict, status: ScanStatus = ScanStatus.DONE) -> ScanResult:
    return ScanResult(scan_id="быстрый", sha256="a" * 64, status=status, verdict=verdict)


# --- кого отправлять ---


def test_grey_zone_goes_deep() -> None:
    assert deep_reason(_result(Verdict.SUSPICIOUS), POLICY, 0.0) == GREY_ZONE


def test_blocked_does_not_go_deep() -> None:
    """Решение принято — дорогая проверка ничего не изменит."""
    assert deep_reason(_result(Verdict.MALICIOUS), POLICY, 1.0) == ""


def test_clean_goes_deep_only_by_sampling() -> None:
    assert deep_reason(_result(Verdict.CLEAN), POLICY, 0.0) == ""
    assert deep_reason(_result(Verdict.CLEAN), POLICY, 1.0) == SAMPLED


def test_unscannable_is_retried_deep() -> None:
    assert deep_reason(_result(Verdict.UNSUPPORTED), POLICY, 0.0) == UNSCANNABLE_RETRY
    assert deep_reason(_result(Verdict.CLEAN, ScanStatus.FAILED), POLICY, 0.0) == UNSCANNABLE_RETRY


def test_sampling_rate_is_respected() -> None:
    """Доля должна быть примерно той, что задали: по ней считают пропуски."""
    clean = _result(Verdict.CLEAN)
    picked = sum(1 for _ in range(2000) if deep_reason(clean, POLICY, 0.1))

    assert 120 < picked < 280, f"выбрано {picked} из 2000 при доле 0.1"


# --- как выглядит задача ---


def test_deep_job_gets_own_identifier() -> None:
    """С прежним идентификатором задача не запустилась бы вовсе.

    Воркер пропускает задачи с терминальным статусом, а он уже есть: быстрая
    проверка только что завершилась. И её результат оказался бы затёрт.
    """
    deep = deep_job(_job(), GREY_ZONE)

    assert deep.scan_id != "быстрый"
    assert deep.parent_scan_id == "быстрый"


def test_deep_job_does_not_reuse_cache() -> None:
    """Смысл в том, чтобы разобрать файл заново и целиком."""
    assert deep_job(_job(), GREY_ZONE).cached is None


def test_deep_job_uses_strict_profile() -> None:
    """Растеризация проверяет, поддаётся ли документ безопасной пересборке."""
    assert deep_job(_job(profile=CdrProfile.LIGHT), GREY_ZONE).profile is CdrProfile.STRICT


def test_deep_job_keeps_policy_intact() -> None:
    """Соблазн включить теневой режим есть, но его вердикты испортили бы
    статистику ложных срабатываний."""
    original = TenantPolicy(tenant="team-a", shadow_mode=False)

    deep = deep_job(_job(policy=original), GREY_ZONE)

    assert deep.policy.shadow_mode is False
    assert deep.policy.tenant == "team-a"


def test_deep_job_keeps_callback() -> None:
    """Второй вердикт должен дойти до клиента."""
    deep = deep_job(_job(callback_url="https://bot.example/hook"), GREY_ZONE)

    assert deep.callback_url == "https://bot.example/hook"


# --- как ведёт себя конвейер ---


def test_deep_sanitizes_even_blocked() -> None:
    """Так выясняется, поддаётся ли документ безопасной пересборке вообще."""
    assert Pipeline._should_sanitize(_job(deep=True), Verdict.MALICIOUS)
    assert not Pipeline._should_sanitize(_job(deep=False), Verdict.MALICIOUS)


def test_deep_still_skips_unscannable() -> None:
    """Пересобирать нечего: содержимое недоступно."""
    for verdict in (Verdict.ENCRYPTED, Verdict.UNSUPPORTED):
        assert not Pipeline._should_sanitize(_job(deep=True), verdict)


def test_detect_only_stays_detect_only() -> None:
    assert not Pipeline._should_sanitize(_job(deep=True, mode=ScanMode.DETECT), Verdict.MALICIOUS)


@pytest.mark.parametrize("deep", [True, False])
def test_deep_flag_reaches_result(deep: bool) -> None:
    result = ScanResult(
        scan_id="s", sha256="a" * 64, status=ScanStatus.DONE, verdict=Verdict.CLEAN, deep=deep
    )

    assert result.deep is deep
