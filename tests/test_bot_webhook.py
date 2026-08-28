"""M3.2: коллбэк, его повтор и опрос не должны отвечать пользователю дважды."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "bot"))

from botapp import webhook
from botapp.delivery import DeliveryLedger
from botapp.webhook import WEBHOOK_PATH, build_app
from vscommon.models import ScanResult, ScanStatus, Verdict
from vscommon.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign

SECRET = "секрет-для-теста"


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webhook.settings, "hmac_secret", SECRET)


def _result(scan_id: str = "scan-1") -> ScanResult:
    return ScanResult(
        scan_id=scan_id, sha256="a" * 64, status=ScanStatus.DONE, verdict=Verdict.CLEAN
    )


def _post(client: TestClient, body: bytes, secret: str = SECRET) -> int:
    ts, sig = sign(secret, body)
    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers={TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sig},
    )
    return response.status_code


# --- однократная доставка ---


def test_claim_is_granted_once() -> None:
    """Критерий M3.2: повторная доставка не отправляет второе сообщение."""
    ledger = DeliveryLedger()
    ledger.register("scan-1", chat_id=42, filename="doc.pdf")

    first = ledger.claim("scan-1")
    second = ledger.claim("scan-1")

    assert [w.chat_id for w in first] == [42]
    assert second == []


def test_claim_of_unknown_scan_is_refused() -> None:
    assert DeliveryLedger().claim("никогда-не-регистрировали") == []


def test_claim_is_atomic_under_concurrency() -> None:
    """Вебхук и опрос приходят одновременно — ответить должен ровно один."""
    ledger = DeliveryLedger()
    ledger.register("scan-1", chat_id=42, filename="doc.pdf")
    winners: list[object] = []
    barrier = threading.Barrier(8)

    def race() -> None:
        barrier.wait()
        if ledger.claim("scan-1"):
            winners.append(1)

    threads = [threading.Thread(target=race) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(winners) == 1


def test_answered_is_remembered() -> None:
    ledger = DeliveryLedger()
    ledger.register("scan-1", 42, "doc.pdf")
    ledger.claim("scan-1")

    assert ledger.already_answered("scan-1")


def test_ledger_is_bounded() -> None:
    """Поток запросов не должен раздувать память бота."""
    ledger = DeliveryLedger(max_entries=50)

    for i in range(500):
        ledger.register(f"scan-{i}", i, "doc.pdf")
        ledger.claim(f"scan-{i}")

    assert len(ledger._answered) <= 50
    assert len(ledger._pending) <= 50


# --- приёмник ---


def test_valid_callback_is_accepted() -> None:
    received: list[ScanResult] = []

    async def handle(result: ScanResult) -> None:
        received.append(result)

    with TestClient(build_app(handle)) as client:
        code = _post(client, _result().model_dump_json().encode())

    assert code == 204
    assert received[0].scan_id == "scan-1"


def test_wrong_signature_rejected() -> None:
    async def handle(result: ScanResult) -> None:
        raise AssertionError("обработчик не должен вызываться")

    with TestClient(build_app(handle)) as client:
        assert _post(client, _result().model_dump_json().encode(), secret="чужой") == 401


def test_unsigned_callback_rejected() -> None:
    async def handle(result: ScanResult) -> None:
        raise AssertionError("обработчик не должен вызываться")

    with TestClient(build_app(handle)) as client:
        response = client.post(WEBHOOK_PATH, content=b"{}")

    assert response.status_code == 401


def test_tampered_body_rejected() -> None:
    async def handle(result: ScanResult) -> None:
        raise AssertionError("обработчик не должен вызываться")

    body = _result().model_dump_json().encode()
    ts, sig = sign(SECRET, body)

    with TestClient(build_app(handle)) as client:
        response = client.post(
            WEBHOOK_PATH,
            content=body.replace(b"clean", b"error"),
            headers={TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sig},
        )

    assert response.status_code == 401


def test_unreadable_body_is_bad_request() -> None:
    async def handle(result: ScanResult) -> None:
        raise AssertionError("обработчик не должен вызываться")

    with TestClient(build_app(handle)) as client:
        assert _post(client, "{ это не json".encode()) == 400


def test_repeated_callback_answers_once() -> None:
    """Сканер ретраит коллбэк; пользователю уходит одно сообщение."""
    ledger = DeliveryLedger()
    ledger.register("scan-1", 42, "doc.pdf")
    answered: list[int] = []

    async def handle(result: ScanResult) -> None:
        answered.extend(w.chat_id for w in ledger.claim(result.scan_id))

    body = _result().model_dump_json().encode()
    with TestClient(build_app(handle)) as client:
        for _ in range(3):
            assert _post(client, body) == 204

    assert answered == [42]


# --- второй вердикт (M5.6) ---


def test_ledger_remembers_what_we_told_the_user() -> None:
    """Без этого не понять, ухудшила ли углублённая проверка вердикт."""
    ledger = DeliveryLedger()
    ledger.register("быстрый", 42, "doc.pdf")
    ledger.claim("быстрый")

    ledger.record_verdict("быстрый", "clean")

    answered = ledger.answered("быстрый")
    assert answered is not None and answered.verdict == "clean"


def test_followup_claimed_once() -> None:
    """Углублённый вердикт доставляется не менее одного раза — пугать
    пользователя дважды не нужно."""
    ledger = DeliveryLedger()
    ledger.register("быстрый", 42, "doc.pdf")
    ledger.claim("быстрый")
    ledger.record_verdict("быстрый", "clean")

    first = ledger.claim_followup("быстрый")
    second = ledger.claim_followup("быстрый")

    assert [w.chat_id for w in first] == [42]
    assert second == []


def test_followup_for_forgotten_scan_is_refused() -> None:
    assert DeliveryLedger().claim_followup("никогда-не-отвечали") == []


def test_each_upload_is_answered_when_scan_is_deduplicated() -> None:
    """Один файл, присланный дважды, получает два ответа.

    Сервис дедуплицирует по содержимому и возвращает общий идентификатор.
    Запись, привязанная к нему, затирала предыдущую, и на два сообщения
    пользователя уходил один ответ.
    """
    ledger = DeliveryLedger()

    ledger.register("общий", chat_id=42, filename="скан.pdf")
    ledger.register("общий", chat_id=42, filename="скан.pdf")

    assert [w.chat_id for w in ledger.claim("общий")] == [42, 42]
    # Право разыгрывается один раз на всех: повтор вебхука ничего не добавит.
    assert ledger.claim("общий") == []


def test_deduplicated_uploads_from_different_chats_are_both_answered() -> None:
    """Дедупликация общая на сервис, а чаты разные."""
    ledger = DeliveryLedger()

    ledger.register("общий", chat_id=1, filename="скан.pdf")
    ledger.register("общий", chat_id=2, filename="скан.pdf")

    assert sorted(w.chat_id for w in ledger.claim("общий")) == [1, 2]


def test_followup_reaches_every_waiter() -> None:
    """Уточнение по углублённой проверке идёт всем, кто получил первый ответ."""
    ledger = DeliveryLedger()
    ledger.register("общий", chat_id=1, filename="скан.pdf")
    ledger.register("общий", chat_id=2, filename="скан.pdf")
    ledger.claim("общий")
    ledger.record_verdict("общий", "clean")

    assert sorted(w.chat_id for w in ledger.claim_followup("общий")) == [1, 2]
    assert ledger.claim_followup("общий") == []
