"""Углублённая проверка: то, что не помещается в горячий путь.

Быстрая проверка живёт в бюджете сотен миллисекунд и ради этого срезает углы:
выходит раньше времени, ограничивает распаковку, не пересобирает то, что уже
решено блокировать. Углублённая никуда не спешит и делает всё это целиком.

Отправка сюда — не приговор файлу: пользователь уже получил быстрый ответ.
Второй вердикт приходит позже и может его уточнить.
"""

from __future__ import annotations

import logging
import secrets
import uuid

from vscommon.models import CdrProfile, ScanJob, ScanResult, TenantPolicy, Verdict

logger = logging.getLogger(__name__)

GREY_ZONE = "серая зона: быстрая проверка не дала однозначного ответа"
SAMPLED = "выборка чистых: измеряем пропуски"
UNSCANNABLE_RETRY = "быстрая проверка не смогла разобрать файл"

REASON_CODES = {
    GREY_ZONE: "grey_zone",
    SAMPLED: "sampled",
    UNSCANNABLE_RETRY: "unscannable",
}
"""Причина в метку метрики — коротким кодом, а не текстом.

Человеческая формулировка уезжает в лог и в коллбэк, где её читает человек.
В метке она была бы длинной строкой из закрытого списка — работало бы, но
переписывание фразы молча создавало бы новый ряд, а старый оставался в
Prometheus на весь срок хранения и выглядел бы как исчезнувшая причина.
"""


def reason_code(reason: str) -> str:
    """Код причины для метки. Незнакомая причина не создаёт новый ряд."""
    return REASON_CODES.get(reason, "other")


def deep_reason(result: ScanResult, policy: TenantPolicy, sample_rate: float) -> str:
    """Зачем отправлять файл на углублённую проверку. Пустая строка — незачем.

    Заблокированные сюда не идут: решение принято, а тратить на них дорогую
    проверку незачем. Чистые идут только выборкой.
    """
    if result.verdict is Verdict.MALICIOUS:
        return ""
    if result.verdict is Verdict.SUSPICIOUS:
        return GREY_ZONE
    if result.verdict is Verdict.UNSUPPORTED or result.status.value == "failed":
        return UNSCANNABLE_RETRY
    if result.verdict is Verdict.CLEAN and sample_rate > 0 and _sampled(sample_rate):
        return SAMPLED
    return ""


def _sampled(rate: float) -> bool:
    """Криптостойкий бросок: предсказуемая выборка позволяла бы подгадать,
    какой файл углублённо не проверят."""
    return secrets.randbelow(1_000_000) < int(rate * 1_000_000)


def deep_job(job: ScanJob, reason: str) -> ScanJob:
    """Задача для углублённой очереди.

    Кэш не переносится: смысл в том, чтобы разобрать файл заново и целиком.
    Профиль всегда `strict` — пересобранная растеризацией копия проверяет,
    что документ вообще поддаётся безопасной пересборке.

    Политика остаётся прежней. Поведение углублённой проверки задаётся флагом
    `deep`, а не подменой режима: включить здесь теневой режим было бы соблазном,
    но его вердикты попали бы в статистику ложных срабатываний и испортили её.
    """
    return job.model_copy(
        update={
            # Свой идентификатор обязателен. С прежним углублённая проверка не
            # запустилась бы вовсе: воркер пропускает задачи, у которых уже
            # есть терминальный статус, — а он есть, быстрая только что
            # завершилась. И её результат был бы затёрт вторым.
            "scan_id": uuid.uuid4().hex,
            "parent_scan_id": job.scan_id,
            "deep": True,
            "deep_reason": reason,
            "cached": None,
            "profile": CdrProfile.STRICT,
        }
    )
