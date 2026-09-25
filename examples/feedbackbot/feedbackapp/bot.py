"""Диалог формы и приём файла.

Порядок жёсткий: ФИО, потом файл. Файл проверяется сканером; принимается
только тот, у которого есть пересобранная копия, — её сканер сам кладёт в
хранилище, а бот рядом пишет карточку. Отправителю файл не возвращается.

В логи не попадают ни ФИО, ни имя файла: только `scan_id`, расширение,
размер и вердикт. Всё остальное — в карточке, то есть в хранилище владельца
формы, а не в общем журнале.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Protocol

from vulnscan_client import ScanOutcome, VulnscanError

from . import wording
from .cards import CardStore, Submission
from .form import Conversation, Forms, Step, parse_full_name
from .telegram import FileTooBigError, TelegramError

logger = logging.getLogger(__name__)

ACCEPTABLE_VERDICTS = frozenset({"clean", "suspicious"})
"""`suspicious` принимается: владелец формы получает пересобранную копию, а
то, из-за чего файл подозрителен, пересборка из неё убрала. Отказывать в этом
случае значит не принять договор из-за макроса, которого в копии уже нет."""

CARD_ATTEMPTS = 3


class Scanner(Protocol):
    async def scan(
        self, content: bytes, filename: str, content_type: str = ..., profile: str | None = ...
    ) -> ScanOutcome: ...

    async def result(self, scan_id: str) -> ScanOutcome | None: ...


class Chat(Protocol):
    async def send(self, chat_id: int, text: str) -> None: ...

    async def download(self, file_id: str, limit: int) -> bytes: ...


class Decision(StrEnum):
    ACCEPTED = "accepted"
    REBUILT = "rebuilt"
    """Опасный файл, пересобранный из пикселей и текста (`deliver_blocked:
    strict`). Принимается: в хранилище уходит копия, в которой от исходника
    не осталось ни одного объекта."""

    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    ENCRYPTED = "encrypted"
    NOT_VERIFIED = "not_verified"


def decide(outcome: ScanOutcome) -> Decision:
    """Что делать с файлом по вердикту.

    Принимается только то, у чего есть пересобранная копия: именно её
    получает владелец формы. Всё незнакомое — не принято: новый вердикт в
    сервисе не должен молча открывать форму.

    Опасный файл принимается, если сканер его пересобрал. Решает это
    политика тенанта (`deliver_blocked: "strict"`), а не бот: сканер
    пересобирает заблокированное только по ней, и копия в ответе означает,
    что политика разрешила выдачу. Своего переключателя у бота нет — два
    источника одного решения однажды разошлись бы, и карточка обещала бы
    файл, которого в хранилище нет.

    Исключение — теневой режим: там сканер пересобирает заблокированное при
    любой политике, но выгружает только при `strict`. По ответу этого не
    различить, поэтому в тени опасный файл не принимается.
    """
    if outcome.blocked:
        if outcome.sanitized and not outcome.raw.get("shadow"):
            return Decision.REBUILT
        return Decision.BLOCKED
    if outcome.verdict == "unsupported":
        return Decision.UNSUPPORTED
    if outcome.verdict == "encrypted":
        return Decision.ENCRYPTED
    if outcome.verdict in ACCEPTABLE_VERDICTS and outcome.sanitized:
        return Decision.ACCEPTED
    return Decision.NOT_VERIFIED


@dataclass(frozen=True, slots=True)
class Attachment:
    file_id: str
    name: str
    mime: str
    size: int

    @property
    def ext(self) -> str:
        return PurePosixPath(self.name).suffix.lower()[:16] or "?"


def attachment_of(message: dict[str, Any]) -> Attachment | None:
    document = message.get("document")
    if document:
        return Attachment(
            file_id=str(document["file_id"]),
            name=str(document.get("file_name") or "document"),
            mime=str(document.get("mime_type") or "application/octet-stream"),
            size=int(document.get("file_size") or 0),
        )
    photos = message.get("photo")
    if photos:
        # Telegram присылает фото в нескольких размерах; последнее — крупнейшее.
        largest = photos[-1]
        return Attachment(
            file_id=str(largest["file_id"]),
            name="photo.jpg",
            mime="image/jpeg",
            size=int(largest.get("file_size") or 0),
        )
    return None


class FeedbackBot:
    def __init__(
        self,
        chat: Chat,
        scanner: Scanner,
        cards: CardStore,
        forms: Forms,
        *,
        max_bytes: int,
        scan_timeout_s: float,
        poll_interval_s: float,
        parallel: int,
    ) -> None:
        self._chat = chat
        self._scanner = scanner
        self._cards = cards
        self._forms = forms
        self._max_bytes = max_bytes
        self._scan_timeout = scan_timeout_s
        self._poll_interval = poll_interval_s
        self._slots = asyncio.Semaphore(parallel)
        self._tasks: set[asyncio.Task[None]] = set()

    async def wait_idle(self) -> None:
        """Дождаться всех идущих проверок. Нужно тестам и остановке."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def handle(self, update: dict[str, Any]) -> None:
        message = update.get("message")
        if not message or message.get("chat", {}).get("type") != "private":
            # В группе форма не заполняется: ФИО увидели бы все участники.
            return
        chat_id = int(message["chat"]["id"])
        text = (message.get("text") or "").strip()
        attachment = attachment_of(message)

        if text.startswith("/start"):
            self._forms.reset(chat_id)
            await self._say(chat_id, wording.GREETING)
            return

        conversation = self._forms.get(chat_id)
        if conversation.step is Step.CHECKING:
            await self._say(chat_id, wording.BUSY)
        elif conversation.step is Step.NAME:
            await self._take_name(chat_id, conversation, text, attachment)
        elif attachment is None:
            await self._say(chat_id, wording.FILE_EXPECTED)
        else:
            conversation.step = Step.CHECKING
            await self._say(chat_id, wording.CHECKING)
            sender = message.get("from") or {}
            task = asyncio.create_task(self._take_file(chat_id, conversation, attachment, sender))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _take_name(
        self, chat_id: int, conversation: Conversation, text: str, attachment: Attachment | None
    ) -> None:
        if attachment is not None:
            await self._say(chat_id, wording.NAME_FIRST)
            return
        name = parse_full_name(text)
        if name is None:
            await self._say(chat_id, wording.NAME_INVALID)
            return
        conversation.full_name = name
        conversation.step = Step.FILE
        limit = self._max_bytes // (1024 * 1024)
        await self._say(chat_id, wording.ASK_FILE.format(name=name, limit=limit))

    async def _take_file(
        self,
        chat_id: int,
        conversation: Conversation,
        attachment: Attachment,
        sender: dict[str, Any],
    ) -> None:
        try:
            async with self._slots:
                reply, accepted = await self._process(chat_id, conversation, attachment, sender)
        except Exception:
            # Что бы ни случилось, человек не должен остаться с «проверяю…».
            logger.exception("обработка файла упала", extra={"ext": attachment.ext})
            reply, accepted = wording.NOT_VERIFIED, False

        if accepted:
            self._forms.forget(chat_id)
        else:
            conversation.step = Step.FILE  # ФИО помним, ждём другой файл
        await self._say(chat_id, reply)

    async def _process(
        self,
        chat_id: int,
        conversation: Conversation,
        attachment: Attachment,
        sender: dict[str, Any],
    ) -> tuple[str, bool]:
        limit_mb = self._max_bytes // (1024 * 1024)
        try:
            content = await self._chat.download(attachment.file_id, self._max_bytes)
        except FileTooBigError:
            return wording.TOO_BIG.format(limit=limit_mb), False
        except TelegramError:
            logger.warning("файл не скачался из Telegram", extra={"ext": attachment.ext})
            return wording.NOT_VERIFIED, False

        sha256 = hashlib.sha256(content).hexdigest()
        outcome = await self._check(content, attachment)
        size = len(content)
        del content  # дальше файл боту не нужен: копию в хранилище кладёт сканер
        if outcome is None:
            return wording.NOT_VERIFIED, False

        decision = decide(outcome)
        logger.info(
            "решение по файлу",
            extra={
                "scan_id": outcome.scan_id,
                "verdict": outcome.verdict,
                "decision": decision.value,
                "ext": attachment.ext,
                "size": size,
            },
        )
        if decision not in (Decision.ACCEPTED, Decision.REBUILT):
            return {
                Decision.BLOCKED: wording.BLOCKED,
                Decision.UNSUPPORTED: wording.UNSUPPORTED,
                Decision.ENCRYPTED: wording.ENCRYPTED,
            }.get(decision, wording.NOT_VERIFIED), False

        submission = Submission(
            full_name=conversation.full_name,
            user_id=int(sender.get("id") or 0),
            username=sender.get("username"),
            chat_id=chat_id,
            file_name=attachment.name,
            file_size=size,
            sha256=sha256,
            scan_id=outcome.scan_id,
            verdict=outcome.verdict,
            score=outcome.score,
            rebuilt_from_blocked=decision is Decision.REBUILT,
        )
        number = await self._save(submission)
        if number is None:
            return wording.NOT_SAVED, False
        logger.info("обращение принято", extra={"scan_id": outcome.scan_id, "number": number})
        reply = wording.ACCEPTED_REBUILT if decision is Decision.REBUILT else wording.ACCEPTED
        return reply.format(number=number), True

    async def _check(self, content: bytes, attachment: Attachment) -> ScanOutcome | None:
        """Вердикт или `None`: сканер недоступен или не успел.

        Коллбэка нет: сервер бота ничего не слушает. Результат забирается
        опросом, и «не успел» — не повод принять файл непроверенным.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._scan_timeout
        try:
            outcome = await self._scanner.scan(content, attachment.name, attachment.mime)
            while outcome.pending:
                if loop.time() > deadline:
                    logger.warning(
                        "проверка не уложилась в ожидание", extra={"scan_id": outcome.scan_id}
                    )
                    return None
                await asyncio.sleep(self._poll_interval)
                fresh = await self._scanner.result(outcome.scan_id)
                if fresh is not None:
                    outcome = fresh
        except VulnscanError as exc:
            logger.warning("сканер недоступен", extra={"reason": str(exc)[:200]})
            return None
        return outcome

    async def _save(self, submission: Submission) -> str | None:
        for attempt in range(1, CARD_ATTEMPTS + 1):
            try:
                return await self._cards.put(submission)
            except Exception as exc:
                logger.warning(
                    "карточка не сохранилась",
                    extra={
                        "scan_id": submission.scan_id,
                        "attempt": attempt,
                        "reason": type(exc).__name__,
                    },
                )
                if attempt < CARD_ATTEMPTS:
                    await asyncio.sleep(0.5 * 2 ** (attempt - 1))
        # Копия уже в хранилище — её положил сканер, — а карточки нет.
        # По `scan_id` из этой записи её и найдут.
        logger.error("обращение без карточки", extra={"scan_id": submission.scan_id})
        return None

    async def _say(self, chat_id: int, text: str) -> None:
        try:
            await self._chat.send(chat_id, text)
        except TelegramError as exc:
            logger.warning("сообщение не отправлено", extra={"reason": str(exc)[:200]})
