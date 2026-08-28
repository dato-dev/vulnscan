"""Однократная доставка ответа пользователю.

Одному скану могут соответствовать несколько сигналов: вебхук, его повтор при
ретрае и завершившийся опрос. Пользователь должен получить один ответ на
сообщение — поэтому право ответить разыгрывается атомарно.

Но и наоборот: одному скану могут соответствовать несколько сообщений. Сервис
дедуплицирует по содержимому, и два одинаковых файла получают общий
идентификатор. Ждущих под ним столько, сколько раз файл прислали, и ответить
надо каждому.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PendingScan:
    chat_id: int
    filename: str
    started_at: float


@dataclass(slots=True)
class AnsweredScan:
    """Что мы уже сказали пользователю.

    Нужно, чтобы понять, ухудшила ли углублённая проверка вердикт. Без этого
    второй ответ либо не отправишь вовсе, либо отправишь всегда — и то и другое
    неверно.
    """

    waiters: list[PendingScan]
    verdict: str
    answered_at: float


@dataclass(slots=True)
class _Waiting:
    scans: list[PendingScan] = field(default_factory=list)
    started_at: float = 0.0


class DeliveryLedger:
    """Кто ждёт ответа и кому уже ответили.

    Хранится в памяти процесса: перезапуск бота теряет ожидающие сканы. Это
    осознанный размен — вынос в Redis связал бы бота с инфраструктурой сканера
    ради редкого случая. Подстраховкой служит опрос: он идёт параллельно и
    отвечает, если вебхук не пришёл.
    """

    def __init__(self, ttl_s: float = 900.0, max_entries: int = 5000) -> None:
        self._ttl = ttl_s
        self._max = max_entries
        self._pending: dict[str, _Waiting] = {}
        self._answered: dict[str, AnsweredScan] = {}
        self._notified: set[str] = set()
        self._lock = threading.Lock()

    def register(self, scan_id: str, chat_id: int, filename: str) -> None:
        """Добавляет ждущего. Повторная регистрация НЕ вытесняет предыдущую.

        Иначе пользователь, приславший один файл дважды, получил бы один ответ:
        сервис вернул бы общий идентификатор, а вторая запись затёрла бы первую.
        """
        with self._lock:
            self._evict()
            waiting = self._pending.setdefault(scan_id, _Waiting(started_at=time.monotonic()))
            waiting.scans.append(PendingScan(chat_id, filename, time.monotonic()))

    def claim(self, scan_id: str) -> list[PendingScan]:
        """Забирает право ответить всем ждущим. Пустой список — уже ответили.

        Проверка и захват под одним замком: иначе вебхук и опрос, пришедшие
        одновременно, оба сочли бы себя первыми.
        """
        with self._lock:
            if scan_id in self._answered:
                return []
            waiting = self._pending.pop(scan_id, None)
            if waiting is None or not waiting.scans:
                return []
            self._answered[scan_id] = AnsweredScan(
                waiters=list(waiting.scans), verdict="", answered_at=time.monotonic()
            )
            # Ограничиваем там же, где растём: иначе поток запросов уводит
            # размер за предел между регистрациями.
            self._trim()
            return waiting.scans

    def record_verdict(self, scan_id: str, verdict: str) -> None:
        """Запоминает, что именно мы сказали пользователю."""
        with self._lock:
            answered = self._answered.get(scan_id)
            if answered is not None:
                answered.verdict = verdict

    def answered(self, scan_id: str) -> AnsweredScan | None:
        with self._lock:
            return self._answered.get(scan_id)

    def claim_followup(self, scan_id: str) -> list[PendingScan]:
        """Право отправить уточнение по уже отвеченному скану.

        Углублённый вердикт доставляется не менее одного раза, и повтор не
        должен пугать пользователя дважды.
        """
        with self._lock:
            if scan_id in self._notified:
                return []
            answered = self._answered.get(scan_id)
            if answered is None:
                return []
            self._notified.add(scan_id)
            while len(self._notified) > self._max:
                self._notified.pop()
            return answered.waiters

    def already_answered(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._answered

    def _evict(self) -> None:
        now = time.monotonic()
        for key, waiting in list(self._pending.items()):
            if now - waiting.started_at > self._ttl:
                self._pending.pop(key, None)
        for key, answered in list(self._answered.items()):
            if now - answered.answered_at > self._ttl:
                self._answered.pop(key, None)
        self._trim()

    def _trim(self) -> None:
        """Защита от роста, если поток запросов обгоняет истечение по времени."""
        while len(self._answered) > self._max:
            self._answered.pop(next(iter(self._answered)), None)
        while len(self._pending) > self._max:
            self._pending.pop(next(iter(self._pending)), None)
