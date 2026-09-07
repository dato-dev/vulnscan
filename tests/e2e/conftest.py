"""Сквозной прогон: настоящий стек, настоящее S3-хранилище (M13.0).

Заглушки описывают то, как мы **думаем**, что устроен стык. Все дефекты
доставки за последнюю неделю жили именно там: отсутствующая зависимость в
образе, политика, названная по идентификатору ключа, ссылка на несуществующую
учётку, поле, которого нет в выкаченном образе. Ни один из них не ловится
подделкой `boto3` — она проверяет наши представления о нём.

Здесь подделок нет: поднимается стек, файл уходит подписанным запросом, а
результат ищется в бакете, у которого учётная запись сервиса имеет права
**только на запись**.

Запуск:
    make test-e2e

Без поднятого стенда тесты пропускаются, а не падают: обычный прогон обязан
работать без Docker.
"""

from __future__ import annotations

from typing import Any

import pytest
from stand import (
    READER_KEY,
    READER_SECRET,
    SINK_ENDPOINT,
    SINK_REGION,
    SKIP_REASON,
    ready,
)


@pytest.fixture(scope="session", autouse=True)
def stand() -> None:
    if not ready():
        pytest.skip(SKIP_REASON, allow_module_level=True)


@pytest.fixture(scope="session")
def sink() -> Any:
    """Клиент «чужого» хранилища — с правами администратора.

    Читаем мы им только в тестах: у самого сервиса учётка другая, и права у
    неё только на запись. Смешивать их нельзя, иначе прогон подтверждал бы
    работу с правами, которых в бою не будет.
    """
    boto3 = pytest.importorskip("boto3", reason="boto3 нужен для чтения приёмника")
    return boto3.client(
        "s3",
        endpoint_url=SINK_ENDPOINT,
        aws_access_key_id=READER_KEY,
        aws_secret_access_key=READER_SECRET,
        region_name=SINK_REGION,
    )
