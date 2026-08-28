"""Клиентская библиотека (M8.5).

Проверяется то, на чём чужая команда ошибётся молча: подпись, проверка
коллбэка и трактовка вердикта.
"""

from __future__ import annotations

import json
import time

import pytest

from vulnscan_client import (
    CallbackVerificationError,
    ScanOutcome,
    verify_callback,
)
from vulnscan_client.client import _canonical, _sign, _to_outcome

SECRET = "s" * 40


def _signed(body: bytes, secret: str = SECRET, ts: int | None = None) -> dict[str, str]:
    timestamp, signature = _sign(secret, body, ts)
    return {"X-Vulnscan-Timestamp": timestamp, "X-Vulnscan-Signature": signature}


# --- совместимость подписи с сервисом ------------------------------------


def test_sdk_signature_matches_service() -> None:
    """Библиотека и сервис обязаны считать подпись одинаково.

    Иначе интеграция ломается на первом же запросе, а причина выглядит как
    «неверный ключ».
    """
    from vscommon.signing import sign as service_sign

    body = b'{"wait_ms":2000}'
    ts = int(time.time())

    assert _sign(SECRET, body, ts) == service_sign(SECRET, body, ts)


def test_canonical_request_matches_service() -> None:
    """Библиотека и сервис обязаны строить канонический запрос одинаково.

    Расхождение дало бы `401` на каждой загрузке, а выглядело бы как неверный
    ключ. Сравниваем с настоящей функцией сервиса, а не с копией формата:
    копия разошлась бы молча.
    """
    from gateway_app.auth import canonical_request

    assert _canonical("post", "/v1/scan", "k1") == canonical_request("POST", "/v1/scan", "k1")
    assert _canonical("post", "/v1/scan", "k1") == b"POST\n/v1/scan\nk1"


def test_canonical_request_includes_path() -> None:
    """Без пути подпись, снятая с одной ручки, годилась бы для любой другой."""
    assert _canonical("GET", "/v1/scan/a", "k") != _canonical("GET", "/v1/scan/b", "k")


# --- проверка коллбэка ---------------------------------------------------


def test_valid_callback_is_accepted() -> None:
    body = json.dumps({"verdict": "clean"}).encode()

    assert verify_callback(SECRET, body, _signed(body))["verdict"] == "clean"


def test_unsigned_callback_is_refused() -> None:
    """Без проверки эндпоинт принимает вердикт от кого угодно."""
    with pytest.raises(CallbackVerificationError):
        verify_callback(SECRET, b"{}", {})


def test_foreign_secret_is_refused() -> None:
    body = b'{"verdict":"clean"}'

    with pytest.raises(CallbackVerificationError):
        verify_callback("другой" * 8, body, _signed(body))


def test_tampered_body_is_refused() -> None:
    headers = _signed(b'{"verdict":"malicious"}')

    with pytest.raises(CallbackVerificationError):
        verify_callback(SECRET, b'{"verdict":"clean"}', headers)


def test_clock_skew_message_names_the_cause() -> None:
    """Расхождение часов не должно выглядеть как неверный ключ.

    Это ровно та ошибка, на которую уходят часы при подключении новой команды.
    """
    body = b"{}"
    headers = _signed(body, ts=int(time.time()) - 4000)

    with pytest.raises(CallbackVerificationError, match="часов"):
        verify_callback(SECRET, body, headers)


def test_headers_are_case_insensitive() -> None:
    """Разные веб-фреймворки отдают заголовки по-разному."""
    body = b'{"verdict":"clean"}'
    headers = {k.lower(): v for k, v in _signed(body).items()}

    assert verify_callback(SECRET, body, headers)["verdict"] == "clean"


# --- трактовка вердикта --------------------------------------------------


def test_clean_is_safe() -> None:
    outcome = _to_outcome({"verdict": "clean", "status": "done", "scan_id": "x"})

    assert outcome.safe and not outcome.blocked


def test_malicious_is_blocked() -> None:
    assert _to_outcome({"verdict": "malicious", "status": "done"}).blocked


@pytest.mark.parametrize("verdict", ["unsupported", "encrypted"])
def test_unscannable_is_neither_safe_nor_blocked(verdict: str) -> None:
    """Файл, который не удалось проверить, не заблокирован — но и не безопасен.

    Именно здесь интегратор чаще всего ставит `if not blocked` и пропускает
    непроверенное как чистое.
    """
    outcome = _to_outcome({"verdict": verdict, "status": "done"})

    assert not outcome.blocked
    assert not outcome.safe
    assert outcome.unscannable


def test_unknown_verdict_is_not_safe() -> None:
    """Список безопасного положительный, а не отрицательный.

    Вердикт, добавленный в сервисе позже, обязан считаться небезопасным, пока
    интегратор не обновит библиотеку осознанно.
    """
    assert not _to_outcome({"verdict": "нечто-новое", "status": "done"}).safe


def test_pending_is_recognised() -> None:
    outcome = _to_outcome({"verdict": "suspicious", "status": "queued"})

    assert outcome.pending


def test_outcome_exposes_raw_payload() -> None:
    """Библиотека не должна прятать то, чего сама не знает."""
    payload = {"verdict": "clean", "status": "done", "новое_поле": 1}

    assert _to_outcome(payload).raw["новое_поле"] == 1


def test_outcome_is_immutable() -> None:
    outcome = ScanOutcome(
        scan_id="x", verdict="clean", score=0, status="done", pending=False, sanitized=True
    )
    with pytest.raises(AttributeError):
        outcome.verdict = "malicious"  # type: ignore[misc]
