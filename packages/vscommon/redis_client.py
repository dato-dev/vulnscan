"""Единая точка создания клиента Redis.

Отдельный модуль нужен из-за блокирующих команд. `XREADGROUP ... BLOCK` держит
соединение открытым, ничего не отвечая, и клиент с коротким таймаутом чтения
считает это отказом. Воркер из-за этого падал ровно через `block_ms` после
старта — на любой архитектуре.
"""

from __future__ import annotations

import logging

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

BLOCKING_READ_MARGIN_S = 30
"""Запас поверх самой долгой блокирующей команды."""


def create_redis(url: str, *, blocking: bool = False) -> Redis:
    """Клиент Redis.

    `blocking=True` — для потребителей, использующих `BLOCK`: таймаут чтения
    снимается, иначе он обрывает штатное ожидание.
    """
    return Redis.from_url(
        url,
        decode_responses=True,
        socket_timeout=None if blocking else 10.0,
        socket_connect_timeout=5.0,
        socket_keepalive=True,
        health_check_interval=30,
    )
