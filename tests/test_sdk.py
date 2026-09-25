"""Клиентская библиотека (M8.5).

Проверяется то, на чём чужая команда ошибётся молча: подпись, проверка
коллбэка и трактовка вердикта.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

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


# --- копия вместе с типом ---


def test_clean_copy_keeps_type_and_safe_name() -> None:
    """Тип и имя — из ответа сервиса; путь из заголовка отбрасывается."""
    import asyncio

    import httpx

    from vulnscan_client import VulnscanClient

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"PK\x03\x04",
            headers={
                "content-type": "application/zip",
                "content-disposition": 'attachment; filename="../../etc/abc123.zip"',
            },
        )

    async def run():
        client = VulnscanClient("http://scanner", key_id="k", secret="s" * 32)
        client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            return await client.download_clean_copy("abc123")
        finally:
            await client.close()

    copy = asyncio.run(run())

    assert copy.content == b"PK\x03\x04"
    assert copy.content_type == "application/zip"
    assert copy.filename == "abc123.zip"


# --- сертификат своего центра ---


def test_ca_not_configured_means_system_trust() -> None:
    """Пусто или /dev/null (необязательное монтирование в compose) — системные центры."""
    import os

    from vulnscan_client import resolve_ca_file

    assert resolve_ca_file("") is True
    assert resolve_ca_file(os.devnull) is True


def test_readable_ca_file_is_used(tmp_path) -> None:
    """Настоящий сертификат из системного хранилища — берётся как есть."""
    import ssl

    from vulnscan_client import resolve_ca_file

    system = ssl.get_default_verify_paths().cafile
    if not system:
        pytest.skip("в системе нет файла с центрами сертификации")
    ca = tmp_path / "ca.crt"
    ca.write_bytes(Path(system).read_bytes())

    assert resolve_ca_file(str(ca)) == str(ca)


def test_not_a_certificate_explains_itself(tmp_path) -> None:
    """Не тот файл — объяснение, а не SSLError из глубины клиента."""
    from vulnscan_client import resolve_ca_file

    ca = tmp_path / "ca.crt"
    ca.write_text("-----BEGIN CERTIFICATE-----\nнеправда\n-----END CERTIFICATE-----\n")

    with pytest.raises(ValueError, match="PEM"):
        resolve_ca_file(str(ca))


@pytest.mark.parametrize(
    ("setup", "hint"),
    [
        ("missing", "не смонтирован"),
        ("directory", "каталог"),
        ("empty", "пустой"),
        ("unreadable", "chmod 644"),
        ("locked_dir", "не от root"),
    ],
)
def test_bad_ca_explains_itself(tmp_path, setup: str, hint: str) -> None:
    """Каждая частая причина — своими словами, а не PermissionError из ssl.

    `locked_dir` — случай с боевого: путь внутри /root, а процесс в контейнере
    работает от uid 10001 и в /root не заходит.
    """
    import os

    from vulnscan_client import resolve_ca_file

    if os.getuid() == 0 and setup in ("unreadable", "locked_dir"):
        pytest.skip("root читает всё, права не проверить")
    target = tmp_path / "ca.crt"
    if setup == "directory":
        target.mkdir()
    elif setup == "empty":
        target.write_text("")
    elif setup == "unreadable":
        target.write_text("cert")
        target.chmod(0)
    elif setup == "locked_dir":
        locked = tmp_path / "root"
        locked.mkdir()
        target = locked / "ca.crt"
        target.write_text("cert")
        locked.chmod(0)
    try:
        with pytest.raises(ValueError, match=hint):
            resolve_ca_file(str(target))
    finally:
        # Вернуть права, иначе pytest не сможет убрать временный каталог.
        for path in (tmp_path / "root", target):
            if path.exists():
                path.chmod(0o700)
