"""Адаптер Risk Engine к контексту стадий.

Сам движок живёт в `vscommon.scoring`: вердикт считает и воркер, и gateway
при попадании в кэш. Здесь только переход от `ScanContext` к `ScanFacts`.
"""

from __future__ import annotations

import logging

from vscommon.models import TenantPolicy, Verdict
from vscommon.scoring import (
    ESSENTIAL_STAGES,
    apply_failure,
    coverage_incomplete,
    score_of,
    verdict_on_failure,
)
from vscommon.scoring import should_stop_early as _should_stop_early
from vscommon.scoring import verdict_of as _verdict_of

from .stages.base import ScanContext

logger = logging.getLogger(__name__)

__all__ = [
    "ESSENTIAL_STAGES",
    "apply_failure",
    "coverage_incomplete",
    "score_of",
    "should_stop_early",
    "verdict_of",
    "verdict_on_failure",
]


def verdict_of(ctx: ScanContext, policy: TenantPolicy) -> tuple[Verdict, int]:
    return _verdict_of(ctx.facts(), policy)


def should_stop_early(ctx: ScanContext, policy: TenantPolicy) -> bool:
    return _should_stop_early(ctx.facts(), policy)
