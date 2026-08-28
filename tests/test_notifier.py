"""Доставка результатов: подпись ключом тенанта и долговечные повторы."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from notifierapp.sender import CallbackSender
from vscommon.keys import MIN_SECRET_LEN, KeyRegistry
from vscommon.models import CallbackTask
from vscommon.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify

SECRET_A = "a" * MIN_SECRET_LEN
SECRET_B = "b" * MIN_SECRET_LEN


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeHttp:
    def __init__(self, status_code: int = 200, error: Exception | None = None) -> None:
        self.status_code = status_code
        self.error = error
        self.sent: list[dict[str, object]] = []

    async def post(self, url: str, content: bytes, headers: dict[str, str]) -> FakeResponse:
        self.sent.append({"url": url, "content": content, "headers": headers})
        if self.error is not None:
            raise self.error
        return FakeResponse(self.status_code)

    async def aclose(self) -> None:
        return None


def _registry(tmp_path: Path, entries: dict[str, object]) -> KeyRegistry:
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(entries))
    return KeyRegistry.load(str(path))


def _sender(keys: KeyRegistry, http: FakeHttp) -> CallbackSender:
    sender = CallbackSender(keys)
    sender._client = http  # type: ignore[assignment]
    return sender


def _task(key_id: str = "k1") -> CallbackTask:
    return CallbackTask(
        scan_id="s" * 32,
        tenant="команда-а",
        key_id=key_id,
        url="https://client.example/hook",
        payload='{"verdict":"clean"}',
    )


@pytest.mark.asyncio
async def test_callback_is_signed_with_tenant_key(tmp_path: Path) -> None:
    """Ключом тенанта, а не общим секретом.

    Общий секрет означал, что любой клиент может подделать коллбэк любому
    другому — подпись доказывала лишь принадлежность к сервису.
    """
    keys = _registry(tmp_path, {"k1": {"tenant": "команда-а", "secret": SECRET_A}})
    http = FakeHttp()

    outcome = await _sender(keys, http).send(_task())

    assert outcome.delivered
    sent = http.sent[0]
    headers = sent["headers"]
    assert verify(
        SECRET_A,
        sent["content"],  # type: ignore[arg-type]
        headers[TIMESTAMP_HEADER],  # type: ignore[index]
        headers[SIGNATURE_HEADER],  # type: ignore[index]
    )
    # Ключом другого тенанта подпись не проверяется.
    assert not verify(
        SECRET_B,
        sent["content"],  # type: ignore[arg-type]
        headers[TIMESTAMP_HEADER],  # type: ignore[index]
        headers[SIGNATURE_HEADER],  # type: ignore[index]
    )


@pytest.mark.asyncio
async def test_revoked_key_stops_delivery(tmp_path: Path) -> None:
    """Повторять бессмысленно: подписать нечем, и через час будет то же."""
    keys = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A, "disabled": True}})

    outcome = await _sender(keys, FakeHttp()).send(_task())

    assert not outcome.delivered
    assert not outcome.retryable


@pytest.mark.asyncio
async def test_unknown_key_is_not_retried(tmp_path: Path) -> None:
    keys = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})

    outcome = await _sender(keys, FakeHttp()).send(_task(key_id="нет-такого"))

    assert not outcome.retryable


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [408, 429, 500, 502, 503, 504])
async def test_transient_codes_are_retried(tmp_path: Path, code: int) -> None:
    keys = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})

    outcome = await _sender(keys, FakeHttp(status_code=code)).send(_task())

    assert not outcome.delivered
    assert outcome.retryable


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
async def test_permanent_codes_are_not_retried(tmp_path: Path, code: int) -> None:
    """Клиент отказал по существу — повторять полчаса незачем."""
    keys = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})

    outcome = await _sender(keys, FakeHttp(status_code=code)).send(_task())

    assert not outcome.retryable


@pytest.mark.asyncio
async def test_network_error_is_retried(tmp_path: Path) -> None:
    """Разрыв между площадками — ровно тот случай, ради которого всё это."""
    import httpx

    keys = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})
    http = FakeHttp(error=httpx.ConnectTimeout("нет связи"))

    outcome = await _sender(keys, http).send(_task())

    assert outcome.retryable


@pytest.mark.asyncio
async def test_payload_is_not_rebuilt(tmp_path: Path) -> None:
    """Подпись считается по готовому телу.

    Повторная сериализация на стороне доставки могла бы дать другой порядок
    полей, и подпись бы не сошлась.
    """
    keys = _registry(tmp_path, {"k1": {"tenant": "а", "secret": SECRET_A}})
    http = FakeHttp()
    task = _task()

    await _sender(keys, http).send(task)

    assert http.sent[0]["content"] == task.payload.encode()


def test_backoff_reaches_useful_span() -> None:
    """Три попытки за секунды хватало соседнему контейнеру, не разрыву связи."""
    from notifierapp.config import settings

    total = sum(
        min(settings.base_backoff_s * 2**i, settings.max_backoff_s)
        for i in range(settings.max_attempts)
    )
    assert total > 15 * 60, "повторы должны покрывать хотя бы четверть часа"


def test_url_is_not_logged_whole() -> None:
    """URL целиком несёт параметры — в логи идёт только хост."""
    task = CallbackTask(
        scan_id="s" * 32,
        url="https://client.example/hook?token=секрет",
        payload="{}",
    )
    assert task.host == "client.example"
    assert "секрет" not in task.host
