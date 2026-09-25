"""Бот: понятная диагностика и fail-closed на стороне клиента."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "telegram-bot"))

from botapp.scanner import CircuitBreaker, ScanOutcome
from botapp.telegram import TelegramError


@pytest.mark.parametrize("status", [401, 404])
def test_bad_token_is_recognised(status: int) -> None:
    """404 на неизвестный токен, 401 на отозванный. Само не починится."""
    assert TelegramError("getUpdates: Not Found", status).bad_token


@pytest.mark.parametrize("status", [429, 500, 502])
def test_transient_errors_are_not_token_problems(status: int) -> None:
    assert not TelegramError("getUpdates: Bad Gateway", status).bad_token


def test_unavailable_scanner_is_not_deliverable() -> None:
    """Файл не пропускается, если проверить его не удалось."""
    outcome = ScanOutcome(verdict="unknown", score=0, scan_id="", available=False)

    assert not outcome.deliverable


def test_malicious_is_not_deliverable() -> None:
    outcome = ScanOutcome(verdict="malicious", score=100, scan_id="s", clean_url="http://x/clean")

    assert not outcome.deliverable


@pytest.mark.parametrize("verdict", ["encrypted", "unsupported"])
def test_unscannable_is_not_deliverable(verdict: str) -> None:
    outcome = ScanOutcome(verdict=verdict, score=30, scan_id="s")

    assert not outcome.deliverable


def test_clean_without_artifact_is_not_deliverable() -> None:
    """Вердикт есть, копии нет — отдавать нечего, оригинал не подходит."""
    outcome = ScanOutcome(verdict="clean", score=0, scan_id="s", clean_url=None)

    assert not outcome.deliverable


def test_clean_with_artifact_is_deliverable() -> None:
    outcome = ScanOutcome(verdict="clean", score=0, scan_id="s", clean_url="http://x/clean")

    assert outcome.deliverable


def test_breaker_opens_after_streak_and_recovers() -> None:
    breaker = CircuitBreaker()

    for _ in range(5):
        breaker.record_failure()
    assert breaker.open

    breaker.record_success()
    assert not breaker.open


# --- бот на отдельном сервере: прокси и сертификат своего центра ---


async def test_scanner_is_never_reached_through_proxy(monkeypatch) -> None:
    """Прокси в окружении стоит ради Telegram; запрос к сканеру с подписью
    через него уйти не должен. На отдельном сервере `NO_PROXY` не прикрывает."""
    from botapp.scanner import ScannerClient

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    client = ScannerClient()
    try:
        assert client._http.trust_env is False
    finally:
        await client.close()


async def test_explicit_telegram_proxy_ignores_environment(monkeypatch) -> None:
    from botapp import telegram as module
    from botapp.telegram import TelegramClient

    monkeypatch.setattr(module.settings, "telegram_proxy", "http://proxy.invalid:3128")
    explicit = TelegramClient()
    monkeypatch.setattr(module.settings, "telegram_proxy", "")
    from_env = TelegramClient()
    try:
        assert explicit._http.trust_env is False
        # Без явного прокси — как прежде: HTTPS_PROXY из окружения работает,
        # на нём держится выкат в Kubernetes.
        assert from_env._http.trust_env is True
    finally:
        await explicit.close()
        await from_env.close()


async def test_bad_ca_stops_bot_with_one_line(monkeypatch, tmp_path, caplog) -> None:
    """Не тот файл сертификата — понятная строка и остановка, а не падение в ssl."""
    import logging

    from botapp import main as module

    monkeypatch.setattr(module.settings, "telegram_token", "x")
    monkeypatch.setattr(module.settings, "metrics_enabled", False)
    monkeypatch.setattr(module.settings, "scanner_ca_file", str(tmp_path / "нет.crt"))
    monkeypatch.setattr(module, "setup_logging", lambda *a, **k: None)
    caplog.set_level(logging.ERROR)

    await module.amain()

    assert any("сертификат своего центра" in r.getMessage() for r in caplog.records)
