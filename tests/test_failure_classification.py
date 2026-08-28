"""M1.3: инфраструктурный сбой ретраим, краш на файле — нет."""

from __future__ import annotations

import time

import pytest
from fakeredis import aioredis

from vscommon.errors import ErrorKind, classify
from vscommon.journal import Attempt, AttemptJournal
from worker_app.failure import RISKY_STAGES, crashed_on_content, should_retry


class FakeRedisConnectionError(ConnectionError):
    """Подделка redis.exceptions.ConnectionError по модулю-владельцу."""


FakeRedisConnectionError.__module__ = "redis.exceptions"


class FakeBotoError(Exception):
    pass


FakeBotoError.__module__ = "botocore.exceptions"


# --- классификация исключений ---


@pytest.mark.parametrize(
    "exc",
    [
        FakeRedisConnectionError("redis недоступен"),
        FakeBotoError("S3 не отвечает"),
        ConnectionError("сеть"),
        TimeoutError("таймаут"),
    ],
)
def test_infra_errors_are_retryable(exc: BaseException) -> None:
    assert classify(exc) is ErrorKind.INFRA
    assert should_retry(exc)


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("битая структура"),
        MemoryError("файл съел память"),
        RecursionError("глубокая вложенность"),
        RuntimeError("парсер сдался"),
    ],
)
def test_content_errors_are_not_retried(exc: BaseException) -> None:
    assert classify(exc) is ErrorKind.CONTENT
    assert not should_retry(exc)


def test_unknown_error_defaults_to_content() -> None:
    """Дефолт безопасный: лучше закрыть задачу, чем крутить её по воркерам."""

    class НезнакомаяError(Exception):
        pass

    assert classify(НезнакомаяError()) is ErrorKind.CONTENT


# --- обнаружение жёсткого краша по журналу ---


def _attempt(stage: str, attempt: int = 1) -> Attempt:
    return Attempt(scan_id="s", attempt=attempt, stage=stage, started_at=time.time())


@pytest.mark.parametrize("stage", sorted(RISKY_STAGES))
def test_crash_inside_parsing_is_content(stage: str) -> None:
    """Критерий M1.3: закрываем после первой попытки, а не после N."""
    assert crashed_on_content(_attempt(stage), max_crashes=1)


def test_crash_before_parsing_is_infra() -> None:
    """Оборвались на загрузке файла — виновато окружение, повтор осмыслен."""
    assert not crashed_on_content(_attempt("fetch"), max_crashes=1)


def test_clamav_is_not_risky() -> None:
    """clamd разбирает файл в своём процессе и уронить воркер не может."""
    assert "clamav" not in RISKY_STAGES
    assert not crashed_on_content(_attempt("clamav"), max_crashes=1)


def test_tolerance_can_be_raised() -> None:
    """Там, где воркеров вытесняет планировщик, первый обрыв можно простить."""
    assert not crashed_on_content(_attempt("structure", attempt=1), max_crashes=2)
    assert crashed_on_content(_attempt("structure", attempt=2), max_crashes=2)


# --- журнал попыток ---


@pytest.fixture()
async def journal():
    redis = aioredis.FakeRedis(decode_responses=True)
    yield AttemptJournal(redis, ttl_s=60)
    await redis.aclose()


async def test_journal_survives_until_finished(journal) -> None:
    await journal.begin("scan-1", attempt=1)
    await journal.mark("scan-1", attempt=1, stage="structure")

    survived = await journal.load("scan-1")

    assert survived is not None
    assert survived.stage == "structure"
    assert survived.attempt == 1


async def test_journal_cleared_on_normal_completion(journal) -> None:
    """Штатное завершение — в том числе с исключением Python — снимает отметку."""
    await journal.begin("scan-1", attempt=1)
    await journal.finish("scan-1")

    assert await journal.load("scan-1") is None


async def test_no_journal_entry_means_first_attempt(journal) -> None:
    assert await journal.load("никогда-не-сканировался") is None


async def test_journal_ignores_corrupted_entry(journal) -> None:
    await journal._redis.set("attempt:scan-1", "{не json")

    assert await journal.load("scan-1") is None
