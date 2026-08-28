"""Классификация ошибок обработки: ретраить или закрывать сразу.

Разделение принципиально для fail-closed без усиления отказа:
транзиторный сбой S3 должен привести к повторной попытке, а детерминированный
краш парсера на конкретном файле — нет, иначе один документ кочует по воркерам.
"""

from __future__ import annotations

import logging
from enum import StrEnum

logger = logging.getLogger(__name__)


class ErrorKind(StrEnum):
    INFRA = "infra"
    """Транзиторно: сеть, хранилище, брокер. Повтор осмыслен."""

    CONTENT = "content"
    """Вызвано самим файлом. Повтор даст тот же результат."""


_INFRA_MODULES = (
    "redis",
    # Телеметрия ходит по сети. Её транзиторный сбой — инфраструктурный, и
    # принимать его за порчу файла нельзя: задача закрылась бы без повтора.
    "asyncpg",
    "opentelemetry",
    "prometheus_client",
    "grpc",
    "botocore",
    "boto3",
    "urllib3",
    "httpx",
    "httpcore",
    "socket",
    "ssl",
)

_INFRA_TYPES: tuple[type[BaseException], ...] = (
    ConnectionError,
    TimeoutError,
    BrokenPipeError,
    InterruptedError,
)

_CONTENT_TYPES: tuple[type[BaseException], ...] = (
    MemoryError,
    RecursionError,
    UnicodeError,
)
"""Их вызывает обрабатываемый файл, а не окружение."""


def classify(exc: BaseException) -> ErrorKind:
    """Определяет природу ошибки.

    Проверка по модулю исключения, а не по импортированным типам: это
    избавляет общий пакет от зависимости на boto3, redis и httpx.
    """
    if isinstance(exc, _CONTENT_TYPES):
        return ErrorKind.CONTENT
    if isinstance(exc, _INFRA_TYPES):
        return ErrorKind.INFRA

    root = type(exc).__module__.split(".", 1)[0]
    if root in _INFRA_MODULES:
        return ErrorKind.INFRA

    # По умолчанию считаем ошибку контентной. Это безопаснее: повторить
    # инфраструктурный сбой мы всегда сможем следующей загрузкой файла,
    # а бесконечная перевыдача «ядовитого» документа кладёт очередь.
    return ErrorKind.CONTENT
