"""Состояние формы: сначала ФИО, потом файл.

Чистая логика без сети — всё, что решает «что ответить», проверяется без
Telegram и без сканера.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import StrEnum


class Step(StrEnum):
    NAME = "name"
    FILE = "file"
    CHECKING = "checking"
    """Файл ушёл на проверку. Второй файл до ответа не принимаем: иначе у
    одного ФИО окажутся два обращения, и какое из них настоящее — неясно."""


NAME_PART = re.compile(r"^[A-Za-zА-Яа-яЁё]+(?:[-'’][A-Za-zА-Яа-яЁё]+)*$")
MAX_NAME_LENGTH = 120


def parse_full_name(text: str) -> str | None:
    """ФИО или `None`. От двух до четырёх слов из букв, дефисов и апострофов.

    Строгость не ради красоты: это поле уходит в карточку, которую читают
    люди и чужие скрипты. Ссылка, эмодзи или команда вместо имени — почти
    всегда ошибка, а не странное имя.
    """
    words = text.split()
    if not 2 <= len(words) <= 4 or len(" ".join(words)) > MAX_NAME_LENGTH:
        return None
    if not all(NAME_PART.fullmatch(word) for word in words):
        return None
    return " ".join(word[:1].upper() + word[1:] for word in words)


@dataclass(slots=True)
class Conversation:
    step: Step = Step.NAME
    full_name: str = ""
    touched: float = field(default_factory=time.monotonic)


class Forms:
    """Начатые формы в памяти процесса.

    Не в базе и не на диске намеренно: ФИО — персональные данные, и у бота
    на отдельном сервере нет причины их хранить. Цена — перезапуск бота
    обрывает начатые формы, человек начинает заново.
    """

    def __init__(self, ttl_s: float) -> None:
        self._ttl = ttl_s
        self._items: dict[int, Conversation] = {}

    def get(self, chat_id: int) -> Conversation:
        self._expire()
        conversation = self._items.setdefault(chat_id, Conversation())
        conversation.touched = time.monotonic()
        return conversation

    def reset(self, chat_id: int) -> Conversation:
        self._items[chat_id] = Conversation()
        return self._items[chat_id]

    def forget(self, chat_id: int) -> None:
        self._items.pop(chat_id, None)

    def _expire(self) -> None:
        deadline = time.monotonic() - self._ttl
        for chat_id in [c for c, item in self._items.items() if item.touched < deadline]:
            # Идущую проверку не выбрасываем: её исход ещё придёт.
            if self._items[chat_id].step is not Step.CHECKING:
                del self._items[chat_id]

    def __len__(self) -> int:
        return len(self._items)
