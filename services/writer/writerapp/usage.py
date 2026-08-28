"""Раздельный учёт по тенантам (ROADMAP M8.8).

Метрики Prometheus для этого не годятся: у них ограниченная ретенция и они
агрегаты. Счёт и разбор жалобы требуют записей — а они лежат в PostgreSQL,
и запрашивать их может только тот, у кого есть доступ к базе.

Запуск:
    python -m writerapp.usage --days 30
    python -m writerapp.usage --tenant команда-а --days 7
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass

from vscommon.logging import setup_logging

from .config import settings
from .db import Database

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TenantUsage:
    tenant: str
    scans: int
    verdicts: dict[str, int]
    total_ms: int
    bytes_scanned: int

    @property
    def average_ms(self) -> float:
        return self.total_ms / self.scans if self.scans else 0.0


USAGE_SQL = """
SELECT
    coalesce(s.tenant, '(без тенанта)') AS tenant,
    s.verdict,
    count(*)                            AS scans,
    coalesce(sum(s.elapsed_ms), 0)      AS total_ms,
    coalesce(sum(f.size), 0)            AS bytes_scanned
FROM scans s
JOIN files f ON f.sha256 = s.sha256
WHERE s.created_at >= now() - ($1::int * interval '1 day')
  AND ($2::text IS NULL OR s.tenant = $2)
GROUP BY 1, 2
ORDER BY 1, 2
"""


async def collect(db: Database, days: int, tenant: str | None) -> list[TenantUsage]:
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(USAGE_SQL, days, tenant)

    grouped: dict[str, dict[str, object]] = {}
    for row in rows:
        entry = grouped.setdefault(
            row["tenant"], {"verdicts": {}, "scans": 0, "total_ms": 0, "bytes": 0}
        )
        entry["verdicts"][row["verdict"]] = row["scans"]  # type: ignore[index]
        entry["scans"] = int(entry["scans"]) + row["scans"]  # type: ignore[arg-type]
        entry["total_ms"] = int(entry["total_ms"]) + row["total_ms"]  # type: ignore[arg-type]
        entry["bytes"] = int(entry["bytes"]) + row["bytes_scanned"]  # type: ignore[arg-type]

    return [
        TenantUsage(
            tenant=name,
            scans=int(data["scans"]),  # type: ignore[arg-type]
            verdicts=dict(data["verdicts"]),  # type: ignore[arg-type]
            total_ms=int(data["total_ms"]),  # type: ignore[arg-type]
            bytes_scanned=int(data["bytes"]),  # type: ignore[arg-type]
        )
        for name, data in sorted(grouped.items())
    ]


def render(usage: list[TenantUsage], days: int) -> str:
    if not usage:
        return f"За последние {days} дн. проверок не было."

    lines = [f"Использование за последние {days} дн.\n"]
    for item in usage:
        verdicts = ", ".join(f"{k}: {v}" for k, v in sorted(item.verdicts.items()))
        lines.append(
            f"  {item.tenant}\n"
            f"    проверок:   {item.scans}\n"
            f"    объём:      {item.bytes_scanned / 1024 / 1024:.1f} МБ\n"
            f"    в среднем:  {item.average_ms:.0f} мс\n"
            f"    вердикты:   {verdicts}"
        )
    return "\n".join(lines)


async def run(days: int, tenant: str | None) -> int:
    db = Database(settings.postgres_dsn)
    await db.connect()
    try:
        print(render(await collect(db, days, tenant), days))
    finally:
        await db.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Учёт использования по тенантам")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--tenant", default=None, help="только один тенант")
    args = parser.parse_args()

    setup_logging(settings.service_name, "WARNING", "console")
    return asyncio.run(run(args.days, args.tenant))


if __name__ == "__main__":
    raise SystemExit(main())
