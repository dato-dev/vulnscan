"""Проверка адресов коллбэка.

`callback_url` приходит из запроса клиента. Без проверки воркер отправляет
запрос куда скажут — то есть сканер становится посредником для обращений во
внутреннюю сеть: метаданные облака, Redis, MinIO, собственный gateway. Это
работает и на одиночном стенде, а не только при удалённом клиенте.

Список разрешённых хостов задаётся ключом тенанта. Пустой список означает
«коллбэки запрещены», а не «разрешено всё»: умолчание, открывающее доступ, —
это дыра, а не удобство.
"""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = frozenset({"http", "https"})

NEVER_ALLOWED_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)
"""Адреса метаданных облака. Запрещены даже если их вписали в список.

Легитимного повода слать туда результат проверки не существует, а цена ошибки
в конфигурации — выдача ключей от всей инфраструктуры.
"""


class CallbackRejectedError(ValueError):
    """Адрес не принят. Сообщение пригодно для ответа клиенту."""


def validate_callback(url: str, allowed_hosts: tuple[str, ...]) -> str:
    """Возвращает адрес, если он допустим. Иначе бросает `CallbackRejectedError`.

    Проверка выполняется на приёме запроса, а не при доставке: отвергнуть
    нужно до того, как файл принят и проверен, иначе работа уже сделана, а
    результат девать некуда.
    """
    parts = urlsplit(url)

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise CallbackRejectedError("допустимы только схемы http и https")

    if parts.username or parts.password:
        # Учётные данные в URL утекут в логи доставки и в историю.
        raise CallbackRejectedError("учётные данные в адресе не допускаются")

    host = (parts.hostname or "").lower()
    if not host:
        raise CallbackRejectedError("в адресе не указан хост")

    if host in NEVER_ALLOWED_HOSTS or _is_metadata_address(host):
        logger.error("попытка направить коллбэк на адрес метаданных", extra={"host": host})
        raise CallbackRejectedError("адрес запрещён")

    if not allowed_hosts:
        raise CallbackRejectedError("для этого ключа коллбэки не разрешены")

    if host not in allowed_hosts:
        # Хост в сообщение не подставляем: ответ уходит клиенту, и подсказывать
        # ему, что именно разрешено, незачем.
        logger.warning("адрес коллбэка вне списка разрешённых", extra={"host": host})
        raise CallbackRejectedError("адрес коллбэка не разрешён для этого ключа")

    return url


def _is_metadata_address(host: str) -> bool:
    """Link-local диапазон целиком: 169.254.0.0/16 и fe80::/10."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_link_local
