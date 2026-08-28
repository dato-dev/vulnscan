"""M1.1: клиент не может выбрать себе режим отказа."""

from __future__ import annotations

import json
from pathlib import Path

from vscommon.config import CommonSettings
from vscommon.models import CdrProfile, FailMode, ScanRequest, TenantPolicy
from vscommon.policy import PolicyRegistry


def test_client_cannot_set_fail_mode() -> None:
    """Присланный клиентом on_timeout молча отбрасывается моделью запроса."""
    request = ScanRequest.model_validate(
        {"tenant": "team-a", "on_timeout": "fail-open", "wait_ms": 400}
    )

    assert not hasattr(request, "on_timeout")
    assert request.model_dump().get("on_timeout") is None


def test_profile_falls_back_to_tenant_default() -> None:
    request = ScanRequest.model_validate({"tenant": "team-a"})
    policy = TenantPolicy(default_profile=CdrProfile.STRICT)

    assert request.profile is None
    assert (request.profile or policy.default_profile) is CdrProfile.STRICT


def test_registry_returns_default_for_unknown_tenant() -> None:
    registry = PolicyRegistry.load(CommonSettings(policy_file=None))

    policy = registry.for_tenant("не-существует")

    assert policy.fail_mode is FailMode.SUSPICIOUS
    assert policy.block_threshold == 80


def test_registry_applies_per_tenant_overrides(tmp_path: Path) -> None:
    path = tmp_path / "policies.json"
    path.write_text(
        json.dumps({"strict-team": {"fail_mode": "fail-closed", "block_threshold": 50}})
    )
    registry = PolicyRegistry.load(CommonSettings(policy_file=str(path)))

    strict = registry.for_tenant("strict-team")
    other = registry.for_tenant("other-team")

    assert strict.fail_mode is FailMode.FAIL_CLOSED
    assert strict.block_threshold == 50
    assert strict.suspicious_threshold == 30  # не переопределяли — берётся из дефолта
    assert other.fail_mode is FailMode.SUSPICIOUS


def test_wait_ms_capped_by_policy() -> None:
    request = ScanRequest.model_validate({"wait_ms": 9000})
    policy = TenantPolicy(max_wait_ms=2000)

    assert min(request.wait_ms, policy.max_wait_ms) == 2000


def test_directory_instead_of_file_does_not_crash(tmp_path: Path) -> None:
    """Промах bind-mount: Docker подменяет отсутствующий файл каталогом.

    Сервис обязан подняться на значениях по умолчанию, а не уйти в цикл
    перезапуска.
    """
    fake = tmp_path / "policies.json"
    fake.mkdir()

    registry = PolicyRegistry.load(CommonSettings(policy_file=str(fake)))

    assert registry.for_tenant("любой").fail_mode is FailMode.SUSPICIOUS
    assert not registry.degraded, "отсутствие настроек — не деградация"


def test_broken_file_is_degraded_not_fatal(tmp_path: Path) -> None:
    """Битый файл — это деградация: настройки были, но не применились."""
    path = tmp_path / "policies.json"
    path.write_text("{это не json")

    registry = PolicyRegistry.load(CommonSettings(policy_file=str(path)))

    assert registry.degraded
    assert registry.for_tenant("strict-team").fail_mode is FailMode.SUSPICIOUS


def test_missing_file_is_not_degraded(tmp_path: Path) -> None:
    registry = PolicyRegistry.load(CommonSettings(policy_file=str(tmp_path / "нет.json")))

    assert not registry.degraded
