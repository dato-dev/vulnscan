"""Клиент сервиса проверки вложений.

Установка и три строки кода:

    from vulnscan_client import VulnscanClient

    async with VulnscanClient(base_url=..., key_id=..., secret=...) as client:
        outcome = await client.scan(content, filename="скан.pdf")
        if outcome.blocked:
            ...

Библиотека берёт на себя подпись, повторы и разбор вердикта — то есть ровно те
места, где чужая команда ошибётся молча и решит, что виноват сервис.
"""

from .client import (
    CallbackVerificationError,
    ScanOutcome,
    VulnscanClient,
    VulnscanError,
    verify_callback,
)

__all__ = [
    "CallbackVerificationError",
    "ScanOutcome",
    "VulnscanClient",
    "VulnscanError",
    "verify_callback",
]
__version__ = "0.1.0"
