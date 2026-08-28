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
