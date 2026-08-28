"""M2.5: обновление баз антивируса не обесценивает структурный разбор."""

from __future__ import annotations

import pytest
from fakeredis import aioredis

from vscommon.cache import AvCache, StructuralCache, assemble, weights_key_for
from vscommon.models import (
    CachedAv,
    CachedStructural,
    CdrProfile,
    Finding,
    ObjectRef,
    SanitizedArtifact,
    ScanFacts,
    Severity,
    TenantPolicy,
    Verdict,
)
from vscommon.scoring import verdict_of
from vscommon.weights import WeightTable

SHA = "a" * 64
RULES = "r1-w1"


@pytest.fixture()
async def redis():
    client = aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture()
async def tiers(redis):
    return StructuralCache(redis, ttl_s=3600), AvCache(redis, ttl_s=600)


def _finding(code: str, stage: str, score: int) -> Finding:
    return Finding(stage=stage, code=code, severity=Severity.MEDIUM, score=score)


def _structural(rules_version: str = RULES, score: int = 20) -> CachedStructural:
    return CachedStructural(
        sha256=SHA,
        profile=CdrProfile.STANDARD,
        facts=ScanFacts(findings=[_finding("PDF_GOTOR", "structure", score)]),
        engines={"pdf": {"pages": 1}},
        sanitized=SanitizedArtifact(
            ref=ObjectRef(bucket="clean", key="a/aaa.pdf"),
            profile=CdrProfile.STANDARD,
            original_sha256=SHA,
            sanitized_sha256="b" * 64,
        ),
        rules_version=rules_version,
    )


def _av(version: str, score: int = 0) -> CachedAv:
    findings = [_finding("AV_SIGNATURE_MATCH", "clamav", score)] if score else []
    return CachedAv(sha256=SHA, facts=ScanFacts(findings=findings), av_db_version=version)


# --- главный критерий ---


async def test_av_db_update_keeps_structural_hit(tiers) -> None:
    """Критерий M2.5: после freshclam структурный кэш продолжает попадать."""
    structural, av = tiers
    await structural.put(_structural(), weights_key_for(TenantPolicy()))
    await av.put(_av("27100"))

    # базы обновились
    assert await av.get(SHA, "27101") is None
    still_there = await structural.get(SHA, "standard", RULES, "default")

    assert still_there is not None
    assert still_there.sanitized is not None


async def test_rules_change_invalidates_structural(tiers) -> None:
    structural, _ = tiers
    await structural.put(_structural(rules_version="r1-w1"), "default")

    assert await structural.get(SHA, "standard", "r2-w1", "default") is None


async def test_profile_separates_entries(tiers) -> None:
    structural, _ = tiers
    await structural.put(_structural(), "default")

    assert await structural.get(SHA, "strict", RULES, "default") is None


async def test_corrupted_entry_ignored(tiers, redis) -> None:
    structural, _ = tiers
    key = StructuralCache._key(SHA, "standard", RULES, "default")
    await redis.set(key, "{не json")

    assert await structural.get(SHA, "standard", RULES, "default") is None


# --- корректность между тенантами ---


def test_verdict_recomputed_per_tenant() -> None:
    """Раньше кэш хранил готовый вердикт, и тенанты с разными порогами
    получали чужой ответ."""
    entry = _structural(score=45)
    av = _av("27100")

    relaxed = assemble(entry, av, TenantPolicy())
    strict = assemble(entry, av, TenantPolicy(block_threshold=40, suspicious_threshold=10))

    assert relaxed.verdict is Verdict.SUSPICIOUS
    assert strict.verdict is Verdict.MALICIOUS
    assert relaxed.from_cache and strict.from_cache


def test_tenant_with_own_weights_gets_own_entry() -> None:
    """Признаки хранятся с посчитанными баллами — переопределение весов разводит записи."""
    plain = TenantPolicy(tenant="team-a")
    custom = TenantPolicy(tenant="team-legal", weight_overrides={"PDF_GOTOR": 90})

    assert weights_key_for(plain) == "default"
    assert weights_key_for(custom) == "team-legal"


def test_weights_change_changes_fingerprint() -> None:
    table = WeightTable()

    assert table.fingerprint() != table.with_overrides({"PDF_JS": 99}).fingerprint()


# --- сборка ответа ---


def test_assemble_merges_both_halves() -> None:
    result = assemble(_structural(), _av("27100", score=100), TenantPolicy())

    codes = {f.code for f in result.findings}
    assert codes == {"PDF_GOTOR", "AV_SIGNATURE_MATCH"}
    assert result.verdict is Verdict.MALICIOUS


def test_malicious_verdict_withholds_artifact() -> None:
    """Обезвреженная копия вредоносного файла клиенту не отдаётся."""
    result = assemble(_structural(), _av("27100", score=100), TenantPolicy())

    assert result.verdict is Verdict.MALICIOUS
    assert result.sanitized is None


def test_clean_verdict_keeps_artifact() -> None:
    result = assemble(_structural(score=0), _av("27100"), TenantPolicy())

    assert result.verdict is Verdict.CLEAN
    assert result.sanitized is not None


def test_merge_does_not_duplicate_codes() -> None:
    """Один код — один признак, в том числе при склейке половин."""
    left = ScanFacts(findings=[_finding("STAGE_FAILED", "structure", 10)])
    right = ScanFacts(findings=[_finding("STAGE_FAILED", "clamav", 10)])

    merged = left.merge(right)

    assert len(merged.findings) == 1


def test_merge_preserves_failed_coverage() -> None:
    """Упавший антивирус из свежей половины обязан дойти до вердикта."""
    left = ScanFacts()
    right = ScanFacts(failed_stages={"clamav"})

    merged = left.merge(right)

    assert merged.failed_stages == {"clamav"}
    assert verdict_of(merged, TenantPolicy())[0] is not Verdict.CLEAN


def test_stream_size_measured_before_upload(tmp_path) -> None:
    """Размер снимается до заливки: boto3 закрывает поток, и tell() падает."""
    import io

    from vscommon.storage import _stream_size

    stream = io.BytesIO(b"x" * 4096)
    stream.seek(1000)

    assert _stream_size(stream) == 4096
    assert stream.tell() == 0, "курсор обязан вернуться в начало для заливки"


def test_cache_hit_gets_fresh_scan_id() -> None:
    """Ответ из кэша не переиспользует чужой scan_id: он адресует этот запрос."""
    entry, av = _structural(), _av("27100")

    first = assemble(entry, av, TenantPolicy())
    second = assemble(entry, av, TenantPolicy())

    assert first.scan_id != second.scan_id
    assert first.sanitized is not None, "артефакт нужен для выдачи по scan_id"


def test_request_derived_codes_are_not_cacheable() -> None:
    """MIME_MISMATCH описывает заявление клиента, а не содержимое файла.

    В кэше по содержимому ему не место: неверная метка одного отправителя
    досталась бы вердикту другого.
    """
    from vscommon.models import REQUEST_DERIVED_CODES

    assert "MIME_MISMATCH" in REQUEST_DERIVED_CODES
    assert "EXT_MISMATCH" in REQUEST_DERIVED_CODES
    # А вот это свойства самого файла — их кэшировать можно и нужно.
    assert "PDF_LAUNCH" not in REQUEST_DERIVED_CODES
    assert "POLYGLOT_ARCHIVE" not in REQUEST_DERIVED_CODES
    assert "TYPE_SIGNATURE_OFFSET" not in REQUEST_DERIVED_CODES
