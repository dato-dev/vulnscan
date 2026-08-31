"""Сквозная цепочка истории: поток → writer → PostgreSQL.

Здесь ловится то, что не ловят заглушки. Три ошибки подряд жили именно на
стыках: опечатка в имени поля, отсутствие записи на пути кэша и накопление
пачки в памяти. Каждая по отдельности выглядела как «таблица пустая».
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from vscommon.models import (
    CdrProfile,
    Finding,
    ObjectRef,
    SanitizedArtifact,
    ScanFacts,
    ScanRecord,
    ScanResult,
    ScanStatus,
    Severity,
    Verdict,
)
from vscommon.queue import ResultStream

STREAM = "scan.results"
GROUP = "writers"


def _record(scan_id: str, *, verdict: Verdict = Verdict.SUSPICIOUS, **kw: object) -> ScanRecord:
    result = ScanResult(
        scan_id=scan_id,
        sha256="ab" * 32,
        status=ScanStatus.DONE,
        verdict=verdict,
        score=65,
        findings=[
            Finding(
                stage="structure",
                code="PDF_DAMAGED",
                severity=Severity.MEDIUM,
                score=25,
                detail="xref восстановлен",
            )
        ],
        facts=ScanFacts(detected_mime="application/pdf"),
        elapsed_ms=1631,
        **kw,
    )
    return ScanRecord(
        result=result,
        tenant="telegram-bot",
        size=410102,
        detected_mime=result.facts.detected_mime if result.facts else None,
        rules_version="rules-1",
        av_db_version="ClamAV 1.4.6/28101",
    )


async def _rows(db: object, table: str) -> list[dict[str, object]]:
    async with db.pool.acquire() as conn:  # type: ignore[attr-defined]
        return [dict(r) for r in await conn.fetch(f"SELECT * FROM {table}")]


@pytest.mark.asyncio
async def test_record_travels_from_stream_to_database(redis: object, database: object) -> None:
    """Базовая цепочка целиком, без единой заглушки."""
    stream = ResultStream(redis, STREAM, GROUP)  # type: ignore[arg-type]
    await stream.ensure_group()
    await stream.publish(_record("a" * 32))

    async for entry_id, record in stream.consume("t", block_ms=500):
        await database.store([record])  # type: ignore[attr-defined]
        await stream.ack(entry_id)
        break

    scans = await _rows(database, "scans")
    files = await _rows(database, "files")
    findings = await _rows(database, "findings")

    assert len(scans) == 1
    assert scans[0]["tenant"] == "telegram-bot"
    assert scans[0]["verdict"] == "suspicious"
    assert scans[0]["elapsed_ms"] == 1631
    # Тип, определённый по содержимому. Опечатка в имени этого поля и была
    # первой из трёх ошибок — заглушка её не поймала.
    assert files[0]["detected_mime"] == "application/pdf"
    assert findings[0]["code"] == "PDF_DAMAGED"


@pytest.mark.asyncio
async def test_single_record_reaches_database_without_full_batch(
    redis: object, database: object
) -> None:
    """Одна запись не должна ждать, пока наберётся пачка.

    Регрессия: writer сбрасывал накопленное только при заполнении (32 записи)
    или на остановке. При небольшом потоке история лежала в памяти часами —
    ровно то, что вы увидели на боевом стенде.
    """
    from writerapp.main import Writer

    stream = ResultStream(redis, STREAM, GROUP)  # type: ignore[arg-type]
    await stream.ensure_group()
    await stream.publish(_record("b" * 32))

    writer = Writer.__new__(Writer)
    writer._redis = redis  # type: ignore[attr-defined]
    writer._stream = stream  # type: ignore[attr-defined]
    writer._db = database  # type: ignore[attr-defined]
    writer._stopping = asyncio.Event()  # type: ignore[attr-defined]
    writer._batch = []  # type: ignore[attr-defined]
    writer._lock = asyncio.Lock()  # type: ignore[attr-defined]

    task = asyncio.create_task(writer.start())
    try:
        await asyncio.sleep(4)
        # Проверяем, ПОКА writer работает. На остановке срабатывает финальный
        # сброс, и запись доехала бы в обход сломанного периодического — тест
        # проходил бы по неверной причине, а это хуже отсутствия теста.
        written = await _rows(database, "scans")
    finally:
        writer._stopping.set()  # type: ignore[attr-defined]
        task.cancel()
        with contextlib.suppress(BaseException):
            await task

    assert len(written) == 1, "одна запись обязана дойти без ожидания полной пачки"


@pytest.mark.asyncio
async def test_repeated_delivery_does_not_duplicate(redis: object, database: object) -> None:
    """Поток доставляет как минимум один раз — запись обязана быть идемпотентной."""
    stream = ResultStream(redis, STREAM, GROUP)  # type: ignore[arg-type]
    await stream.ensure_group()
    record = _record("c" * 32)

    await database.store([record])  # type: ignore[attr-defined]
    await database.store([record])  # type: ignore[attr-defined]

    assert len(await _rows(database, "scans")) == 1
    assert len(await _rows(database, "findings")) == 1


@pytest.mark.asyncio
async def test_deep_scan_links_to_its_parent(redis: object, database: object) -> None:
    """Углублённая проверка — отдельная строка со ссылкой на быструю.

    С прежним `scan_id` задача не запустилась бы вовсе, а результат быстрой
    проверки был бы затёрт; ссылка проверяется внешним ключом схемы.
    """
    parent = _record("d" * 32)
    child = _record("e" * 32, deep=True, parent_scan_id="d" * 32)

    await database.store([parent, child])  # type: ignore[attr-defined]

    scans = {r["deep"]: r for r in await _rows(database, "scans")}
    assert scans[True]["parent_scan_id"] is not None
    assert str(scans[True]["parent_scan_id"]).replace("-", "") == "d" * 32


@pytest.mark.asyncio
async def test_artifact_is_stored(redis: object, database: object) -> None:
    record = _record(
        "f" * 32,
        sanitized=SanitizedArtifact(
            ref=ObjectRef(bucket="vulnscan-clean", key="ab/scan.pdf", size=1024),
            profile=CdrProfile.STANDARD,
            original_sha256="ab" * 32,
            sanitized_sha256="cd" * 32,
        ),
    )
    await database.store([record])  # type: ignore[attr-defined]

    artifacts = await _rows(database, "artifacts")
    assert artifacts[0]["bucket"] == "vulnscan-clean"
    assert artifacts[0]["profile"] == "standard"


@pytest.mark.asyncio
async def test_filename_is_absent_from_every_table(redis: object, database: object) -> None:
    """Имя файла не хранится нигде. Гарантия структурная, но пусть будет и живая."""
    await database.store([_record("1" * 32)])  # type: ignore[attr-defined]

    async with database.pool.acquire() as conn:  # type: ignore[attr-defined]
        columns = await conn.fetch(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public'"
        )

    names = {r["column_name"] for r in columns}
    assert not {"filename", "file_name", "original_name"} & names


@pytest.mark.asyncio
async def test_unacked_records_survive_writer_restart(redis: object, database: object) -> None:
    """Неподтверждённое остаётся в потоке.

    Это и спасло ваши пять записей: writer их не записал, но и не потерял.
    """
    stream = ResultStream(redis, STREAM, GROUP)  # type: ignore[arg-type]
    await stream.ensure_group()
    await stream.publish(_record("2" * 32))

    # Прочитали и «упали» до подтверждения.
    async for _ in stream.consume("умер", block_ms=500):
        break

    assert await stream.pending_count() == 1, "запись должна ждать повторной доставки"
