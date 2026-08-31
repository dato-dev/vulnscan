"""Интеграционные тесты: настоящие Redis и PostgreSQL.

Обычный набор намеренно герметичен (см. CLAUDE.md): заглушки быстрые и не
требуют ничего снаружи. Но три ошибки в цепочке хранения истории спрятались
ровно там, где заглушка вела себя иначе, чем настоящий сервис, — поэтому здесь
подделок нет.

Запуск:
    docker compose -f tests/integration/docker-compose.yml up -d
    make test-integration

Без поднятых зависимостей тесты пропускаются, а не падают: отсутствие Docker
не должно ломать обычный прогон.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

REDIS_URL = os.environ.get("ITEST_REDIS_URL", "redis://localhost:16379/0")
POSTGRES_DSN = os.environ.get(
    "ITEST_POSTGRES_DSN", "postgresql://vulnscan:vulnscan@localhost:15432/vulnscan_test"
)

SKIP_REASON = (
    "нет зависимостей для интеграционных тестов — поднимите их: "
    "docker compose -f tests/integration/docker-compose.yml up -d"
)


async def _redis_ready() -> bool:
    from vscommon.redis_client import create_redis

    try:
        client = create_redis(REDIS_URL)
        await client.ping()
        await client.aclose()
    except Exception:
        return False
    return True


async def _postgres_ready() -> bool:
    import asyncpg

    try:
        conn = await asyncpg.connect(POSTGRES_DSN, timeout=3)
        await conn.close()
    except Exception:
        return False
    return True


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Пропускает весь набор, если зависимостей нет.

    Проверка одна на прогон, а не на тест: поднимать соединение к каждому
    тесту ради того же ответа — трата секунд на пустом месте.
    """
    integration = [i for i in items if "integration" in str(i.fspath)]
    if not integration:
        return

    ready = asyncio.run(_redis_ready()) and asyncio.run(_postgres_ready())
    if ready:
        return

    skip = pytest.mark.skip(reason=SKIP_REASON)
    for item in integration:
        item.add_marker(skip)


@pytest_asyncio.fixture
async def redis() -> AsyncIterator[object]:
    """Чистый Redis на каждый тест: остатки чужих потоков ломают ожидания."""
    from vscommon.redis_client import create_redis

    client = create_redis(REDIS_URL, blocking=True)
    await client.flushall()
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture
async def database() -> AsyncIterator[object]:
    """Пустая база на каждый тест. Схема накатывается миграцией — той же,
    что и в бою: расхождение схемы теста и схемы прода обесценивает проверку."""
    from writerapp.db import Database

    db = Database(POSTGRES_DSN)
    await db.connect()
    await db.migrate()
    async with db.pool.acquire() as conn:
        await conn.execute("TRUNCATE files, scans, findings, artifacts CASCADE")
    try:
        yield db
    finally:
        await db.close()
