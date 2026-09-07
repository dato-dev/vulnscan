"""Куда уезжает обезвреженная копия (M14).

Разделение здесь одно и оно несущее: **адрес — это политика, учётные данные —
секрет**, и лежат они в разных местах.

Адрес приёмника описан в `policies.json` рядом с порогами. Этот файл читают
gateway, воркер и deepscan — то есть в том числе процесс, который разбирает
враждебные файлы. Знание «мы пишем в такой-то бакет» ему безвредно.

Учётные данные там лежать не могут по той же причине: ключ доступа к чужому
хранилищу в файле, доступном воркеру, означает, что дыра в парсере даёт запись
в инфраструктуру клиента. Поэтому в политике стоит **ссылка** —
`credentials_id`, — а сами ключи разрешает notifier из своего файла, воркеру
не видного. Полный доступ к политикам после этого даёт знание, куда мы пишем,
но не возможность туда написать.

Второе решение — строгость разбора. `TenantPolicy` неизвестные поля
игнорирует, и это правильно: так клиент не подсунет себе `on_timeout:
fail-open`. Но для приёмника мягкость означала бы, что опечатка в имени поля
превращается в «доставка не настроена», а дальше файлы просто не появляются в
ящике. Поэтому блок `delivery` разбирается с `extra="forbid"`, а неудача
разбора — это состояние «настроена и сломана», отличное от «не настроена».
Различать их обязательно: первое чинят, второе — нормальная работа.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

MIN_SECRET_LEN = 16
"""Ключ короче этого не принимается: чужое хранилище — не место для опечатки."""


class Delivery(BaseModel):
    """Приёмник обезвреженных копий. Задаётся политикой, не запросом.

    Клиент не может назвать приёмник в запросе, и это не удобство, а защита:
    «просканируй и положи вот сюда» — готовый примитив записи куда угодно и
    канал вывода данных наружу. Ровно тот же довод, по которому адреса
    коллбэков проверяются по списку ключа (`vscommon/callbacks.py`).
    """

    model_config = ConfigDict(extra="forbid")

    backend: Literal["s3"] = "s3"
    """Пока только S3. SMB — отдельным решением (M14.6), NFS — не в нашем
    периметре (M14.7): это монтирование, а не клиент."""

    endpoint: str = ""
    """Адрес хранилища. Пусто — тот же, что у нашего S3 (для стенда)."""

    bucket: str = Field(min_length=1)
    prefix: str = ""
    """Префикс ключа. Свой на тенанта — так компрометация одной учётки не даёт
    писать в чужие каталоги (M14.4)."""

    region: str = ""

    credentials_id: str = Field(min_length=1)
    """Ссылка на учётные данные, а не сами данные. См. модуль целиком."""

    def key_for(self, name: str) -> str:
        """Полный ключ объекта в приёмнике.

        Разделитель добавляется здесь, а не в настройке: префикс без косой
        черты — обычная опечатка, и её последствие (`vulnscanfile.pdf` вместо
        `vulnscan/file.pdf`) выглядит как работающая доставка не туда.
        """
        prefix = self.prefix.strip("/")
        return f"{prefix}/{name}" if prefix else name


class DeliveryCredentials(BaseModel):
    """Чем аутентифицироваться в чужом хранилище. Живёт только у notifier."""

    model_config = ConfigDict(extra="forbid")

    access_key: str = Field(min_length=1)
    secret_key: str = Field(min_length=MIN_SECRET_LEN)

    def __repr__(self) -> str:
        """Секрет не должен попасть в лог через случайный `repr` объекта."""
        return f"DeliveryCredentials(access_key={self.access_key!r}, secret_key=<скрыт>)"

    __str__ = __repr__


class DeliveryError(ValueError):
    """Блок `delivery` есть, но разобрать его не удалось."""


def parse_delivery(payload: Any) -> Delivery:
    """Строгий разбор блока. Ошибка — исключение, а не `None`.

    Возврат `None` при неудаче означал бы «приёмника нет», а это другое
    состояние: приёмника нет — штатная работа, приёмник сломан — авария,
    которую надо чинить. Смешав их, мы получили бы молчаливую потерю доставки
    от одной опечатки.
    """
    if not isinstance(payload, dict):
        raise DeliveryError("ожидается объект с описанием приёмника")
    try:
        return Delivery.model_validate(payload)
    except ValueError as exc:
        raise DeliveryError(str(exc)) from exc


class CredentialsRegistry:
    """Учётные данные приёмников. Читает только notifier.

    Устроен как `KeyRegistry` и по той же причине: файл с секретами не должен
    монтироваться туда, где он не нужен. Недоступный файл — это отказ
    доставки, а не работа без аутентификации.
    """

    def __init__(self, entries: dict[str, DeliveryCredentials], degraded: bool = False) -> None:
        self._entries = entries
        self.degraded = degraded
        """Файл задан, но не прочитан. Доставка при этом не выполняется вовсе:
        писать в чужое хранилище «как получится» нельзя."""

    def get(self, credentials_id: str) -> DeliveryCredentials | None:
        return self._entries.get(credentials_id)

    def __len__(self) -> int:
        return len(self._entries)

    @classmethod
    def load(cls, path: str | None) -> CredentialsRegistry:
        if not path:
            # Приёмников нет — обычное состояние установки, и жаловаться не на
            # что. Отсутствие доставки становится ошибкой только там, где
            # тенанту её настроили: см. `TenantPolicy.delivery`.
            return cls({})

        file = Path(path)
        if not file.is_file():
            logger.error(
                "файл учётных данных приёмников не найден, доставка отключена",
                extra={"path": str(file), "is_dir": file.is_dir()},
            )
            return cls({}, degraded=True)

        try:
            raw = json.loads(file.read_text())
        except Exception:
            logger.exception("файл учётных данных приёмников не читается")
            return cls({}, degraded=True)

        entries: dict[str, DeliveryCredentials] = {}
        for name, payload in raw.items():
            if name.startswith("_"):
                # Комментарии в JSON: тот же приём, что и в реестре ключей.
                continue
            try:
                entries[name] = DeliveryCredentials.model_validate(payload)
            except ValueError:
                # Одна негодная запись не закрывает доставку остальным. В лог
                # идёт имя, но не содержимое: тут секреты.
                logger.exception("негодная учётная запись приёмника", extra={"id": name})

        logger.info("учётные данные приёмников загружены", extra={"count": len(entries)})
        return cls(entries)
