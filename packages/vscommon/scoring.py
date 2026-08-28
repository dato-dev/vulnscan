"""Risk Engine: признаки → балл → вердикт.

Чистая функция над данными, а не сервис (см. architecture §1). Живёт в общем
пакете, потому что вердикт считают оба: воркер после проверки и gateway при
попадании в кэш — там же, где применяется политика конкретного тенанта.
"""

from __future__ import annotations

import logging

from vscommon.models import (
    UNSCANNABLE_VERDICTS,
    FailMode,
    Finding,
    ScanFacts,
    TenantPolicy,
    Verdict,
)
from vscommon.weights import family_of

logger = logging.getLogger(__name__)

ESSENTIAL_STAGES = frozenset({"filetype", "structure", "clamav"})
"""Стадии, без которых файл нельзя считать проверенным.

`yara` сюда не входит намеренно: это наши собственные правила поверх
сигнатурного детекта. Их отсутствие сужает покрытие, но роль поиска известных
угроз остаётся за `clamav`. Если из ESSENTIAL убрать `clamav`, лежащий демон
снова начнёт молча выдавать `clean` — так и было до M1.7.
"""


__all__ = [
    "ESSENTIAL_STAGES",
    "ScanFacts",
    "apply_failure",
    "coverage_incomplete",
    "is_unscannable",
    "score_of",
    "should_stop_early",
    "verdict_of",
    "verdict_on_failure",
]


def score_of(findings: list[Finding]) -> int:
    """Балл по признакам.

    Внутри семейства коррелированных признаков считается только сильнейший:
    три проверки, увидевшие одну поломку, не должны давать тройной вес.
    Один критический признак блокирует сам по себе.
    """
    if any(f.score >= 100 for f in findings):
        return 100

    strongest: dict[str, int] = {}
    for finding in findings:
        family = family_of(finding.code)
        strongest[family] = max(strongest.get(family, 0), finding.score)
    return min(100, sum(strongest.values()))


def coverage_incomplete(facts: ScanFacts) -> bool:
    """Хотя бы одна обязательная стадия не отработала."""
    return bool(facts.failed_stages & ESSENTIAL_STAGES)


def verdict_of(facts: ScanFacts, policy: TenantPolicy) -> tuple[Verdict, int]:
    score = score_of(facts.findings)

    if score >= policy.block_threshold:
        return Verdict.MALICIOUS, score
    if facts.encrypted:
        # Зашифрованный файл просканировать нельзя — это не clean.
        return Verdict.ENCRYPTED, max(score, policy.suspicious_threshold)
    if not facts.supported:
        # То же и для неизвестного формата: балл поднимаем до порога, иначе
        # клиент с пороговой политикой увидит «почти чисто» у непроверенного.
        return Verdict.UNSUPPORTED, max(score, policy.suspicious_threshold)
    if score >= policy.suspicious_threshold:
        return Verdict.SUSPICIOUS, score

    if coverage_incomplete(facts):
        # Ничего не нашли — но и не искали толком. Балл за упавшую стадию тонет
        # под порогом, поэтому решает не он, а факт неполного покрытия.
        degraded = apply_failure(Verdict.CLEAN, policy)
        if degraded is not Verdict.CLEAN:
            return degraded, max(score, policy.suspicious_threshold)
        return degraded, score

    return Verdict.CLEAN, score


def verdict_on_failure(policy: TenantPolicy) -> Verdict:
    """Режим отказа — серверная настройка тенанта, не параметр запроса."""
    match policy.fail_mode:
        case FailMode.FAIL_OPEN:
            return Verdict.CLEAN
        case FailMode.FAIL_CLOSED:
            return Verdict.MALICIOUS
        case _:
            return Verdict.SUSPICIOUS


def apply_failure(current: Verdict, policy: TenantPolicy) -> Verdict:
    """Сбой обработки не имеет права смягчить уже полученный вердикт.

    Если проверка что-то нашла — это остаётся. Режим отказа применяется только
    там, где иначе вышло бы `clean` при незавершённой работе.
    """
    if current is Verdict.CLEAN:
        return verdict_on_failure(policy)
    return current


def is_unscannable(verdict: Verdict) -> bool:
    return verdict in UNSCANNABLE_VERDICTS


def should_stop_early(facts: ScanFacts, policy: TenantPolicy) -> bool:
    """Ранний выход: дорогие стадии не нужны, если файл уже блокируется.

    В теневом режиме не срабатывает. Там мы разбираемся, почему файл попал под
    блокировку, и знать, согласился ли антивирус со структурным анализом,
    важнее сэкономленных миллисекунд.
    """
    if policy.shadow_mode:
        return False
    return score_of(facts.findings) >= policy.block_threshold
