"""Доступ к PostgreSQL. Единственное место в системе, где он есть.

Воркер в базу не ходит: это процесс, который разбирает враждебные файлы, и
сетевой доступ к хранилищу истории из него — лишняя дверь. Результаты доезжают
сюда через поток Redis.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import asyncpg

from vscommon.models import ScanRecord

logger = logging.getLogger(__name__)

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


class Database:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool[Any] | None = None

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=8)
        logger.info("подключение к PostgreSQL установлено")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool[Any]:
        if self._pool is None:
            raise RuntimeError("нет подключения к базе")
        return self._pool

    async def migrate(self) -> None:
        """Прогоняет миграции по порядку имён.

        Каждая написана идемпотентно (`IF NOT EXISTS`), поэтому повторный
        запуск безопасен — отдельная таблица версий здесь была бы лишней
        сущностью при трёх файлах.
        """
        for path in sorted(MIGRATIONS.glob("*.sql")):
            async with self.pool.acquire() as conn:
                await conn.execute(path.read_text())
            logger.info("миграция применена", extra={"file": path.name})

    async def store(self, records: list[ScanRecord]) -> int:
        """Записывает пачку результатов одной транзакцией.

        Пачкой, а не по одному: запись истории не должна становиться
        узким местом конвейера.
        """
        if not records:
            return 0

        async with self.pool.acquire() as conn, conn.transaction():
            for record in records:
                await self._store_one(conn, record)
        return len(records)

    async def _store_one(self, conn: asyncpg.Connection[Any], record: ScanRecord) -> None:
        result = record.result
        await conn.execute(
            """
            INSERT INTO files (sha256, size, detected_mime)
            VALUES ($1, $2, $3)
            ON CONFLICT (sha256) DO UPDATE SET last_seen = now()
            """,
            result.sha256,
            record.size,
            record.detected_mime,
        )

        # Повторная доставка из потока — норма (at-least-once), поэтому запись
        # скана идемпотентна по его идентификатору.
        await conn.execute(
            """
            INSERT INTO scans (
                id, sha256, tenant, status, verdict, score,
                rules_version, av_db_version, policy_version,
                elapsed_ms, parent_scan_id, deep, shadow
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                verdict = EXCLUDED.verdict,
                score = EXCLUDED.score,
                elapsed_ms = EXCLUDED.elapsed_ms
            """,
            _uuid(result.scan_id),
            result.sha256,
            record.tenant,
            result.status.value,
            result.verdict.value,
            result.score,
            record.rules_version,
            record.av_db_version,
            result.policy_version,
            result.elapsed_ms,
            _uuid(result.parent_scan_id) if result.parent_scan_id else None,
            result.deep,
            result.shadow,
        )

        for finding in result.findings:
            await conn.execute(
                """
                INSERT INTO findings (scan_id, stage, code, severity, score, detail)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (scan_id, stage, code) DO NOTHING
                """,
                _uuid(result.scan_id),
                finding.stage,
                finding.code,
                getattr(finding.severity, "value", None),
                finding.score,
                # Деталь может содержать фрагмент разбора, поэтому подрезается.
                (finding.detail or "")[:512] or None,
            )

        artifact = result.sanitized
        if artifact is not None:
            await conn.execute(
                """
                INSERT INTO artifacts (scan_id, profile, bucket, key, sanitized_sha256, expires_at)
                VALUES ($1, $2, $3, $4, $5, to_timestamp($6))
                ON CONFLICT (scan_id) DO NOTHING
                """,
                _uuid(result.scan_id),
                artifact.profile.value,
                artifact.ref.bucket,
                artifact.ref.key,
                artifact.sanitized_sha256,
                artifact.expires_at,
            )

    async def prune(self, days: int) -> int:
        """Удаляет историю старше срока. Ноль — не удалять."""
        if days <= 0:
            return 0
        async with self.pool.acquire() as conn:
            deleted: str = await conn.execute(
                "DELETE FROM scans WHERE created_at < now() - ($1::int * interval '1 day')",
                days,
            )
        count = int(deleted.rsplit(" ", 1)[-1]) if deleted.startswith("DELETE") else 0
        if count:
            logger.info("история подчищена", extra={"удалено": count, "старше_дней": days})
        return count


def _uuid(scan_id: str) -> str:
    """`scan_id` — это hex без дефисов; PostgreSQL ждёт каноничный вид."""
    if len(scan_id) == 32 and "-" not in scan_id:
        return f"{scan_id[:8]}-{scan_id[8:12]}-{scan_id[12:16]}-{scan_id[16:20]}-{scan_id[20:]}"
    return scan_id
