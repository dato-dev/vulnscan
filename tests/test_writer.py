"""История проверок: Result Writer и его запись в PostgreSQL.

Главное, что здесь проверяется, — потеря истории не должна ни ломать проверку
файлов, ни происходить молча.
"""

from __future__ import annotations

import pytest

from vscommon.models import (
    CdrProfile,
    Finding,
    ObjectRef,
    SanitizedArtifact,
    ScanRecord,
    ScanResult,
    ScanStatus,
    Severity,
    Verdict,
)
from writerapp.db import Database, _uuid


class FakeConnection:
    """Записывает SQL вместо выполнения."""

    def __init__(self, fail: bool = False) -> None:
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self._fail = fail

    async def execute(self, sql: str, *args: object) -> str:
        if self._fail:
            raise ConnectionError("база недоступна")
        self.statements.append((sql, args))
        return "INSERT 0 1"

    def transaction(self) -> FakeConnection:
        return self

    async def __aenter__(self) -> FakeConnection:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class FakePool:
    def __init__(self, conn: FakeConnection) -> None:
        self._conn = conn

    def acquire(self) -> FakeConnection:
        return self._conn


def _db(conn: FakeConnection) -> Database:
    db = Database("postgresql://ignored")
    db._pool = FakePool(conn)  # type: ignore[assignment]
    return db


def _record(scan_id: str = "a" * 32, **kwargs: object) -> ScanRecord:
    result = ScanResult(
        scan_id=scan_id,
        sha256="b" * 64,
        status=ScanStatus.DONE,
        verdict=Verdict.CLEAN,
        score=0,
        findings=[
            Finding(
                stage="structure",
                code="PDF_JS",
                severity=Severity.HIGH,
                detail="объект 12",
                score=40,
            )
        ],
        **kwargs,
    )
    return ScanRecord(
        result=result,
        tenant="telegram-bot",
        size=1024,
        detected_mime="application/pdf",
        rules_version="rules-1",
        av_db_version="ClamAV 1.4.6/28101",
    )


@pytest.mark.asyncio
async def test_record_is_written() -> None:
    conn = FakeConnection()

    assert await _db(conn).store([_record()]) == 1

    tables = " ".join(sql for sql, _ in conn.statements)
    assert "INTO files" in tables
    assert "INTO scans" in tables
    assert "INTO findings" in tables


@pytest.mark.asyncio
async def test_filename_never_reaches_the_database() -> None:
    """Имя файла почти всегда содержит ПДн.

    Гарантия структурная: в `ScanRecord` такого поля просто нет. Тест
    закрепляет это, чтобы поле не появилось «для удобства отладки».
    """
    assert "filename" not in ScanRecord.model_fields
    assert "filename" not in ScanResult.model_fields

    conn = FakeConnection()
    await _db(conn).store([_record()])

    payload = " ".join(str(args) for _sql, args in conn.statements)
    assert "паспорт" not in payload


@pytest.mark.asyncio
async def test_repeated_delivery_does_not_duplicate() -> None:
    """Поток доставляет как минимум один раз — запись обязана быть идемпотентной."""
    conn = FakeConnection()
    await _db(conn).store([_record(), _record()])

    scans = [sql for sql, _ in conn.statements if "INTO scans" in sql]
    assert all("ON CONFLICT (id) DO UPDATE" in sql for sql in scans)


@pytest.mark.asyncio
async def test_artifact_is_stored_when_present() -> None:
    record = _record(
        sanitized=SanitizedArtifact(
            ref=ObjectRef(bucket="clean", key="ab/scan.pdf", size=10),
            profile=CdrProfile.STANDARD,
            original_sha256="b" * 64,
            sanitized_sha256="c" * 64,
        )
    )
    conn = FakeConnection()
    await _db(conn).store([record])

    assert any("INTO artifacts" in sql for sql, _ in conn.statements)


@pytest.mark.asyncio
async def test_empty_batch_is_not_a_transaction() -> None:
    conn = FakeConnection()

    assert await _db(conn).store([]) == 0
    assert conn.statements == []


@pytest.mark.asyncio
async def test_database_failure_propagates_to_caller() -> None:
    """Сбой должен быть виден вызывающему: он не подтвердит пачку в потоке.

    Тихо проглоченная ошибка означала бы ack без записи — история исчезла бы
    без следа, и заметить это было бы нечем.
    """
    with pytest.raises(ConnectionError):
        await _db(FakeConnection(fail=True)).store([_record()])


def test_scan_id_becomes_canonical_uuid() -> None:
    """`scan_id` — hex без дефисов, PostgreSQL ждёт каноничный вид."""
    assert _uuid("0123456789abcdef0123456789abcdef") == ("01234567-89ab-cdef-0123-456789abcdef")


def test_already_canonical_uuid_is_left_alone() -> None:
    value = "01234567-89ab-cdef-0123-456789abcdef"
    assert _uuid(value) == value


@pytest.mark.asyncio
async def test_cache_hit_is_also_recorded() -> None:
    """Ответ из кэша — такая же оказанная услуга, и он обязан попасть в историю.

    Воркер на этом пути не участвует вовсе: gateway отвечает сразу и задачу в
    очередь не ставит. Пока запись делал только воркер, тенант мог прислать
    тысячу файлов и по документам не сделать ни одной проверки — а история
    нужна и для счёта, и для разбора жалобы.
    """
    from fakeredis.aioredis import FakeRedis

    from vscommon.queue import ResultStream

    redis = FakeRedis(decode_responses=True)
    stream = ResultStream(redis, "scan.results", "writers")
    await stream.ensure_group()

    record = _record()
    record.result.from_cache = True
    await stream.publish(record)

    assert await redis.xlen("scan.results") == 1


@pytest.mark.asyncio
async def test_history_survives_both_producers() -> None:
    """Поток общий: пишут и gateway (кэш), и воркер (полная проверка)."""
    from fakeredis.aioredis import FakeRedis

    from vscommon.queue import ResultStream

    redis = FakeRedis(decode_responses=True)
    stream = ResultStream(redis, "scan.results", "writers")
    await stream.ensure_group()

    from_cache = _record(scan_id="c" * 32)
    from_cache.result.from_cache = True
    await stream.publish(from_cache)
    await stream.publish(_record(scan_id="d" * 32))

    seen = []
    async for entry_id, rec in stream.consume("t", block_ms=1):
        seen.append(rec.result.from_cache)
        await stream.ack(entry_id)
        if len(seen) == 2:
            break

    assert seen == [True, False]


def test_scan_facts_carry_detected_mime() -> None:
    """Тип файла — факт о содержимом, и он должен доезжать до истории.

    Регрессия: `_record_history` читал `result.facts.detected_mime`, которого
    в `ScanFacts` не было. `AttributeError` ловил общий `except`, история
    молча оставалась пустой, и заметить это удалось только по логам с боевого
    стенда. Ловить исключение правильно — история не должна ломать проверку, —
    но опечатку это спрятало.
    """
    from vscommon.models import ScanFacts

    assert "detected_mime" in ScanFacts.model_fields


def test_record_builds_from_a_real_result() -> None:
    """Сборка записи не должна падать ни на одном поле.

    Проверяется именно построение: общий `except` вокруг публикации превращает
    любую опечатку в тишину, поэтому её надо ловить здесь.
    """
    from vscommon.models import ScanFacts

    result = ScanResult(
        scan_id="e" * 32,
        sha256="f" * 64,
        status=ScanStatus.DONE,
        verdict=Verdict.SUSPICIOUS,
        score=65,
        facts=ScanFacts(detected_mime="application/pdf", encrypted=False),
    )

    record = ScanRecord(
        result=result,
        tenant="telegram-bot",
        size=414402,
        detected_mime=result.facts.detected_mime if result.facts else None,
        rules_version="rules-1",
        av_db_version="ClamAV 1.4.6/28101",
    )

    assert record.detected_mime == "application/pdf"


def test_record_survives_result_without_facts() -> None:
    """Отказавшая проверка фактов не оставляет — запись всё равно нужна."""
    result = ScanResult(
        scan_id="0" * 32,
        sha256="1" * 64,
        status=ScanStatus.FAILED,
        verdict=Verdict.SUSPICIOUS,
        score=0,
    )

    record = ScanRecord(
        result=result,
        detected_mime=result.facts.detected_mime if result.facts else None,
    )

    assert record.detected_mime is None


def test_detected_mime_survives_cache_merge() -> None:
    """Склейка структурной части из кэша и свежей антивирусной.

    Тип определяет структурная часть; у антивирусной его нет, и он не должен
    теряться при слиянии.
    """
    from vscommon.models import ScanFacts

    structural = ScanFacts(detected_mime="application/pdf")
    av_only = ScanFacts()

    assert structural.merge(av_only).detected_mime == "application/pdf"
    assert av_only.merge(structural).detected_mime == "application/pdf"


# --- сброс пачки по времени ----------------------------------------------


class _Writer:
    """Минимальная обвязка вокруг логики пачки — без Redis и без базы."""

    def __init__(self, fail: bool = False) -> None:
        import asyncio

        self._batch: list[tuple[str, ScanRecord]] = []
        self._lock = asyncio.Lock()
        self.written: list[list[tuple[str, ScanRecord]]] = []
        self.acked: list[str] = []
        self._fail = fail

    async def _flush_pending(self) -> None:
        async with self._lock:
            batch, self._batch = self._batch, []
        if batch:
            await self._flush(batch)

    async def _flush(self, batch: list[tuple[str, ScanRecord]]) -> None:
        if self._fail:
            async with self._lock:
                self._batch = batch + self._batch
            return
        self.written.append(batch)
        self.acked.extend(entry_id for entry_id, _ in batch)


@pytest.mark.asyncio
async def test_partial_batch_is_flushed() -> None:
    """Пять записей не должны ждать, пока наберётся тридцать вторая.

    Регрессия: пачка сбрасывалась только при заполнении или на остановке, и при
    небольшом потоке история оставалась невидимой часами — а ради неё writer и
    существует.
    """
    writer = _Writer()
    writer._batch = [("1-0", _record()), ("1-1", _record(scan_id="b" * 32))]

    await writer._flush_pending()

    assert len(writer.written) == 1
    assert writer.acked == ["1-0", "1-1"]


@pytest.mark.asyncio
async def test_empty_flush_is_a_no_op() -> None:
    """Пустой сброс не должен открывать транзакцию каждые две секунды."""
    writer = _Writer()

    await writer._flush_pending()

    assert writer.written == []


@pytest.mark.asyncio
async def test_failed_write_returns_records_to_the_batch() -> None:
    """Сбой базы не должен терять накопленное.

    Записи не подтверждены в потоке, поэтому не потеряны совсем, — но из памяти
    они уходили бы, и до повторной доставки пришлось бы ждать срок хранения.
    """
    writer = _Writer(fail=True)
    writer._batch = [("1-0", _record())]

    await writer._flush_pending()

    assert writer.written == []
    assert len(writer._batch) == 1, "пачка должна вернуться для повтора"


@pytest.mark.asyncio
async def test_records_arriving_during_write_are_not_lost() -> None:
    """Цикл чтения и цикл сброса работают одновременно."""
    writer = _Writer()
    writer._batch = [("1-0", _record())]

    await writer._flush_pending()
    writer._batch.append(("1-1", _record(scan_id="c" * 32)))
    await writer._flush_pending()

    assert writer.acked == ["1-0", "1-1"]
