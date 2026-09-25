"""Бот-форма обратной связи: ФИО, затем файл; принимается только проверенное."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import pytest

from feedbackapp import wording
from feedbackapp.bot import Decision, FeedbackBot, decide
from feedbackapp.cards import Submission, card_for, key_for
from feedbackapp.form import Forms, Step, parse_full_name
from feedbackapp.telegram import FileTooBigError, TelegramError
from vulnscan_client import ScanOutcome, VulnscanError
from vulnscan_client.client import _to_outcome

NAME = "иванова мария петровна"
FILE = b"%PDF-1.7 synthetic"


def _outcome(
    verdict: str = "clean", status: str = "done", sanitized: bool = True, shadow: bool = False
) -> ScanOutcome:
    return _to_outcome(
        {
            "scan_id": "scan-42",
            "verdict": verdict,
            "score": 0,
            "status": status,
            "sanitized": {"ref": "x"} if sanitized else None,
            "shadow": shadow,
        }
    )


class FakeChat:
    def __init__(self, content: bytes = FILE, error: Exception | None = None) -> None:
        self.sent: list[str] = []
        self._content = content
        self._error = error

    async def send(self, chat_id: int, text: str) -> None:
        self.sent.append(text)

    async def download(self, file_id: str, limit: int) -> bytes:
        if self._error:
            raise self._error
        return self._content


class FakeScanner:
    def __init__(self, *outcomes: ScanOutcome | Exception) -> None:
        self._outcomes = list(outcomes)
        self.uploads: list[tuple[bytes, str]] = []

    def _next(self) -> ScanOutcome:
        item = self._outcomes.pop(0) if len(self._outcomes) > 1 else self._outcomes[0]
        if isinstance(item, Exception):
            raise item
        return item

    async def scan(self, content: bytes, filename: str, content_type: str = "", profile=None):
        self.uploads.append((content, filename))
        return self._next()

    async def result(self, scan_id: str) -> ScanOutcome | None:
        return self._next()


class FakeCards:
    def __init__(self, failures: int = 0) -> None:
        self.saved: list[Submission] = []
        self._failures = failures

    async def put(self, submission: Submission) -> str:
        if self._failures:
            self._failures -= 1
            raise ConnectionError("s3")
        self.saved.append(submission)
        return "abc123"


def _bot(chat: FakeChat, scanner: FakeScanner, cards: FakeCards, **kw: Any) -> FeedbackBot:
    options = {"max_bytes": 20 * 1024 * 1024, "scan_timeout_s": 1.0, "poll_interval_s": 0.0}
    options.update(kw)
    return FeedbackBot(chat, scanner, cards, Forms(3600), parallel=2, **options)


def _msg(text: str | None = None, document: dict | None = None, chat_type: str = "private"):
    message: dict[str, Any] = {
        "chat": {"id": 7, "type": chat_type},
        "from": {"id": 1001, "username": "masha"},
    }
    if text is not None:
        message["text"] = text
    if document is not None:
        message["document"] = document
    return {"update_id": 1, "message": message}


DOC = {"file_id": "f1", "file_name": "Жалоба Ивановой.pdf", "mime_type": "application/pdf"}


async def _fill(bot: FeedbackBot, *, name: str = NAME) -> None:
    await bot.handle(_msg("/start"))
    await bot.handle(_msg(name))
    await bot.handle(_msg(document=DOC))
    await bot.wait_idle()


# --- ФИО ---


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("иванова мария петровна", "Иванова Мария Петровна"),
        ("Салтыков-Щедрин Михаил", "Салтыков-Щедрин Михаил"),
        ("O'Connor Sean", "O'Connor Sean"),
        ("  Петров   Пётр  ", "Петров Пётр"),
    ],
)
def test_names_accepted(text: str, expected: str) -> None:
    assert parse_full_name(text) == expected


@pytest.mark.parametrize(
    "text",
    ["Мария", "https://example.invalid x", "Иван 123", "😀 Смайл", "/start now", "а б в г д", ""],
)
def test_not_a_name(text: str) -> None:
    assert parse_full_name(text) is None


# --- диалог ---


async def test_happy_path_saves_card_with_name() -> None:
    chat, scanner, cards = FakeChat(), FakeScanner(_outcome()), FakeCards()

    await _fill(_bot(chat, scanner, cards))

    assert chat.sent[0] == wording.GREETING
    assert "Иванова Мария Петровна" in chat.sent[1]
    assert chat.sent[-1] == wording.ACCEPTED.format(number="abc123")
    assert [s.full_name for s in cards.saved] == ["Иванова Мария Петровна"]
    card = cards.saved[0]
    assert card.scan_id == "scan-42" and card.file_name == DOC["file_name"]
    assert card.user_id == 1001 and len(card.sha256) == 64


async def test_file_before_name_is_not_taken() -> None:
    chat, scanner, cards = FakeChat(), FakeScanner(_outcome()), FakeCards()
    bot = _bot(chat, scanner, cards)

    await bot.handle(_msg("/start"))
    await bot.handle(_msg(document=DOC))

    assert chat.sent[-1] == wording.NAME_FIRST
    assert scanner.uploads == []


async def test_group_chat_is_ignored() -> None:
    """В группе ФИО увидели бы все участники."""
    chat = FakeChat()
    bot = _bot(chat, FakeScanner(_outcome()), FakeCards())

    await bot.handle(_msg("/start", chat_type="group"))

    assert chat.sent == []


async def test_second_file_while_checking_is_refused() -> None:
    chat, cards = FakeChat(), FakeCards()
    bot = _bot(chat, FakeScanner(_outcome()), cards)
    await bot.handle(_msg("/start"))
    await bot.handle(_msg(NAME))

    await bot.handle(_msg(document=DOC))
    await bot.handle(_msg(document=DOC))
    await bot.wait_idle()

    assert wording.BUSY in chat.sent
    assert len(cards.saved) == 1


# --- исходы проверки ---


@pytest.mark.parametrize(
    ("outcome", "reply"),
    [
        (_outcome("malicious", sanitized=False), wording.BLOCKED),
        (_outcome("unsupported", sanitized=False), wording.UNSUPPORTED),
        (_outcome("encrypted", sanitized=False), wording.ENCRYPTED),
        (_outcome("error", status="failed", sanitized=False), wording.NOT_VERIFIED),
        (_outcome("что-то-новое"), wording.NOT_VERIFIED),
        # Проверено, но копии нет: принимать нечего — владелец формы получает
        # только пересобранную копию.
        (_outcome("clean", sanitized=False), wording.NOT_VERIFIED),
    ],
)
async def test_unaccepted_outcomes_save_nothing(outcome: ScanOutcome, reply: str) -> None:
    chat, cards = FakeChat(), FakeCards()
    bot = _bot(chat, FakeScanner(outcome), cards)

    await _fill(bot)

    assert chat.sent[-1] == reply
    assert cards.saved == []
    # ФИО помним: следующий файл без повторного ввода.
    assert bot._forms.get(7).step is Step.FILE


async def test_blocked_file_rebuilt_by_policy_is_accepted() -> None:
    """`deliver_blocked: strict`: опасный файл пересобран — копия уходит в
    хранилище, обращение принимается, карточка говорит, где копия."""
    chat, cards = FakeChat(), FakeCards()

    await _fill(_bot(chat, FakeScanner(_outcome("malicious", sanitized=True)), cards))

    assert chat.sent[-1] == wording.ACCEPTED_REBUILT.format(number="abc123")
    assert [s.rebuilt_from_blocked for s in cards.saved] == [True]
    assert cards.saved[0].verdict == "malicious"  # пересборка вердикт не смягчает


async def test_blocked_file_without_copy_is_refused() -> None:
    """Политика `never`: копии нет — принимать нечего."""
    assert decide(_outcome("malicious", sanitized=False)) is Decision.BLOCKED


async def test_blocked_copy_in_shadow_mode_is_refused() -> None:
    """В тени копия есть при любой политике, а выгружается только при
    `strict`. По ответу не различить — значит, не принимаем."""
    assert decide(_outcome("malicious", sanitized=True, shadow=True)) is Decision.BLOCKED


def test_card_says_where_the_rebuilt_copy_is() -> None:
    from dataclasses import replace

    card = card_for(
        replace(_submission(), verdict="malicious", rebuilt_from_blocked=True),
        "one",
        datetime(2026, 9, 25, tzinfo=UTC),
    )

    assert card["scan"]["rebuilt_from_blocked"] is True
    assert card["scan"]["verdict"] == "malicious"


async def test_suspicious_with_rebuilt_copy_is_accepted() -> None:
    """Макрос в договоре — не повод не принять договор: в копии его уже нет."""
    assert decide(_outcome("suspicious")) is Decision.ACCEPTED


async def test_pending_is_polled_until_verdict() -> None:
    chat, cards = FakeChat(), FakeCards()
    scanner = FakeScanner(
        _outcome("", status="queued"), _outcome("", status="scanning"), _outcome()
    )

    await _fill(_bot(chat, scanner, cards))

    assert chat.sent[-1].startswith("✅")


async def test_scan_that_never_finishes_is_not_accepted() -> None:
    chat, cards = FakeChat(), FakeCards()

    await _fill(_bot(chat, FakeScanner(_outcome("", status="queued")), cards, scan_timeout_s=0.0))

    assert chat.sent[-1] == wording.NOT_VERIFIED
    assert cards.saved == []


async def test_scanner_down_is_not_accepted() -> None:
    chat, cards = FakeChat(), FakeCards()

    await _fill(_bot(chat, FakeScanner(VulnscanError("сервис недоступен")), cards))

    assert chat.sent[-1] == wording.NOT_VERIFIED
    assert cards.saved == []


async def test_too_big_file() -> None:
    chat = FakeChat(error=FileTooBigError("больше"))

    await _fill(_bot(chat, FakeScanner(_outcome()), FakeCards(), max_bytes=1024 * 1024))

    assert chat.sent[-1] == wording.TOO_BIG.format(limit=1)


async def test_download_failure_is_not_accepted() -> None:
    chat, scanner = FakeChat(error=TelegramError("getFile")), FakeScanner(_outcome())

    await _fill(_bot(chat, scanner, FakeCards()))

    assert chat.sent[-1] == wording.NOT_VERIFIED
    assert scanner.uploads == []


async def test_card_retried_then_saved() -> None:
    chat, cards = FakeChat(), FakeCards(failures=2)

    await _fill(_bot(chat, FakeScanner(_outcome()), cards))

    assert chat.sent[-1].startswith("✅")
    assert len(cards.saved) == 1


async def test_unsaved_card_is_not_reported_as_accepted() -> None:
    """«Принято» без карточки — обращение, которое никто не найдёт."""
    chat, cards = FakeChat(), FakeCards(failures=10)

    await _fill(_bot(chat, FakeScanner(_outcome()), cards))

    assert chat.sent[-1] == wording.NOT_SAVED


async def test_unexpected_crash_still_answers() -> None:
    """Человек не должен остаться с «проверяю…» навсегда."""

    class Broken(FakeScanner):
        async def scan(self, *args: object, **kwargs: object) -> ScanOutcome:
            raise RuntimeError("неожиданное")

    chat = FakeChat()
    await _fill(_bot(chat, Broken(_outcome()), FakeCards()))

    assert chat.sent[-1] == wording.NOT_VERIFIED


async def test_logs_carry_neither_name_nor_filename(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    await _fill(_bot(FakeChat(), FakeScanner(_outcome()), FakeCards(failures=1)))

    dump = "\n".join(f"{r.getMessage()} {r.__dict__}" for r in caplog.records)
    assert "Иванова" not in dump and "иванова" not in dump
    assert "Жалоба" not in dump


# --- карточка ---


def _submission() -> Submission:
    return Submission(
        full_name="Иванова Мария Петровна",
        user_id=1001,
        username="masha",
        chat_id=7,
        file_name="Жалоба.pdf",
        file_size=10,
        sha256="a" * 64,
        scan_id="scan-42",
        verdict="clean",
        score=0,
    )


def test_card_is_keyed_by_submission_not_by_file() -> None:
    """Один бланк от двух людей — две карточки, а не одна перезаписанная."""
    at = datetime(2026, 9, 24, tzinfo=UTC)

    first = key_for("cards/", _submission(), "one", at)
    second = key_for("cards/", _submission(), "two", at)

    assert first != second
    assert first == "cards/2026/09/24/scan-42--one.json"


def test_card_carries_what_joins_it_to_the_file() -> None:
    card = card_for(_submission(), "one", datetime(2026, 9, 24, tzinfo=UTC))

    assert card["card_version"] == 1
    assert card["scan"]["scan_id"] == "scan-42"
    # sha256 — на случай ответа из кэша: у него свой scan_id (M14.11).
    assert card["file"]["sha256"] == "a" * 64


# --- исправление в SDK, найденное по дороге ---


def test_sdk_treats_scanning_as_pending() -> None:
    """Протокол называет статус `scanning`; SDK ждал несуществующий `running`
    и прекращал опрос посреди проверки."""
    assert _to_outcome({"status": "scanning"}).pending
    assert _to_outcome({"status": "queued"}).pending
    assert not _to_outcome({"status": "done", "verdict": "clean"}).pending
