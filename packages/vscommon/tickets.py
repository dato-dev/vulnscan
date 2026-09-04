"""Одноразовые талоны на загрузку файла (M12.1).

Зачем. Секрет тенанта нельзя отдать в браузер: он там становится публичным.
Значит браузеру нужен предмет, которым можно загрузить **один** файл и больше
ничего — ни прочитать результат, ни скачать обезвреженную копию, ни загрузить
второй файл.

Талон и есть такой предмет. Бэкенд сайта просит его подписанным запросом, отдаёт
в браузер, браузер грузит файл прямо нам. Сервер сайта байтов файла не видит —
ради этого всё и затевалось.

Что удерживает талон от превращения в ключ:

- он одноразовый — гашение атомарное, гонка двух загрузок не даёт двух проверок;
- он живёт минуты, а не часы;
- в нём записан предел размера, и он проверяется до чтения тела;
- он привязан к тенанту, и подменить тенанта им нельзя;
- он не даёт ничего, кроме загрузки.

Хранится в Redis: талон переживает перезапуск gateway, но не переживает срок
жизни. Хранить его в памяти процесса нельзя — при нескольких репликах браузер
пришёл бы с талоном не туда, где его выдали.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

TICKET_BYTES = 32
"""Длина случайной части. 256 бит — перебор бессмысленнее, чем поиск ключа."""

DEFAULT_TTL_S = 300
"""Пять минут: посетитель успевает выбрать файл, украденный талон — протухает."""

MAX_TTL_S = 900
"""Верхняя граница. Запрошенный больший срок урезается, а не отклоняется:
интегратор не должен ломаться из-за того, что попросил слишком много."""


@dataclass(frozen=True, slots=True)
class Ticket:
    """Выданный талон. Секретом является только `token`."""

    token: str
    tenant: str
    key_id: str
    max_bytes: int
    origin: str = ""
    """Origin, с которого талон выдан, если выдавался публичному ключу сайта.

    Пусто — талон выдан бэкендом по подписанному запросу, и origin ни при чём.
    """


class TicketStore:
    """Выдача и гашение талонов.

    Гашение — единственное место, где важна атомарность: два параллельных
    запроса с одним талоном должны дать одну успешную загрузку и один отказ.
    Поэтому используется `GETDEL`, а не пара «прочитать, потом удалить»: между
    ними помещается второй запрос.
    """

    def __init__(self, redis: Any, ttl_s: int = DEFAULT_TTL_S) -> None:
        self._redis = redis
        self._ttl = min(ttl_s, MAX_TTL_S)

    @staticmethod
    def _key(token: str) -> str:
        return f"ticket:{token}"

    async def issue(
        self, tenant: str, key_id: str, max_bytes: int, origin: str = ""
    ) -> tuple[Ticket, int]:
        """Выдаёт талон. Возвращает его и срок жизни в секундах."""
        token = secrets.token_urlsafe(TICKET_BYTES)
        ticket = Ticket(
            token=token, tenant=tenant, key_id=key_id, max_bytes=max_bytes, origin=origin
        )
        # Разделитель — перевод строки: ни один из компонентов его не содержит
        # (tenant и key_id проверяются при выпуске ключа, origin — при
        # проверке списка). JSON здесь был бы лишней зависимостью на горячем
        # пути, а разбор чужого JSON — лишней поверхностью.
        payload = f"{tenant}\n{key_id}\n{max_bytes}\n{origin}"
        await self._redis.set(self._key(token), payload, ex=self._ttl)
        return ticket, self._ttl

    async def redeem(self, token: str) -> Ticket | None:
        """Гасит талон и возвращает его содержимое. `None` — недействителен.

        Недействителен означает любое из: не существовал, истёк, уже погашен.
        Различать эти случаи в ответе клиенту не нужно и вредно — подробность
        подсказывала бы подбирающему, насколько он близок.
        """
        if not token:
            return None

        raw = await self._redis.getdel(self._key(token))
        if raw is None:
            return None

        value = raw.decode() if isinstance(raw, bytes) else str(raw)
        parts = value.split("\n")
        if len(parts) != 4:
            # Запись испорчена. Это не повод пропускать загрузку.
            return None

        tenant, key_id, max_bytes, origin = parts
        try:
            limit = int(max_bytes)
        except ValueError:
            return None

        return Ticket(
            token=token, tenant=tenant, key_id=key_id, max_bytes=limit, origin=origin
        )


class StatusTicketStore:
    """Талон на наблюдение за одним сканом (M12.7).

    Появился из дыры в потоке виджета. Загрузка большого файла отвечает `202`:
    вердикта ещё нет. Прочитать его фрейм не может — чтение результата требует
    подписи, а подписать публичным ключом нельзя, и это правильно. В итоге
    посетитель видел «вложение ещё проверяется» и не узнавал, чем кончилось,
    никогда.

    Отдавать браузеру ключ ради этого нельзя, а разрешить чтение по одному
    лишь `scan_id` — значит позволить читать чужие вердикты тому, кто их
    идентификаторы увидит. Поэтому третий предмет: талон, привязанный к
    конкретному скану и ни к чему больше.

    Отличий от талона на загрузку два, и оба намеренные.

    **Многоразовый.** Опрос — это несколько запросов подряд; одноразовость
    сделала бы его невозможным. Ограничивает не счётчик, а срок жизни.

    **Живёт дольше.** Талон на загрузку ждёт, пока посетитель выберет файл;
    этот — пока закончится проверка, включая углублённую.
    """

    def __init__(self, redis: Any, ttl_s: int = 600) -> None:
        self._redis = redis
        self._ttl = ttl_s

    @staticmethod
    def _key(token: str) -> str:
        return f"status-ticket:{token}"

    async def issue(self, scan_id: str, tenant: str) -> tuple[str, int]:
        """Выдаёт талон на наблюдение. Возвращает токен и срок жизни."""
        token = secrets.token_urlsafe(TICKET_BYTES)
        await self._redis.set(self._key(token), f"{scan_id}\n{tenant}", ex=self._ttl)
        return token, self._ttl

    async def resolve(self, token: str) -> tuple[str, str] | None:
        """Скан и тенант по талону. `None` — недействителен.

        Не гасит: талон предъявляется несколько раз подряд, в этом его смысл.
        """
        if not token:
            return None

        raw = await self._redis.get(self._key(token))
        if raw is None:
            return None

        value = raw.decode() if isinstance(raw, bytes) else str(raw)
        parts = value.split("\n")
        if len(parts) != 2:
            return None

        scan_id, tenant = parts
        return (scan_id, tenant) if scan_id else None
