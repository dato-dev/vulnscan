"""Разбор ZIP для стадии `structure` (M6.1).

Здесь — только опись: что с архивом не так и какие записи проверять.
Сами записи проверяет конвейер после стадий, полным проходом на каждую
(`Pipeline._expand`), и признаки вложений переносит на архив.
"""

from __future__ import annotations

import logging

from ..archive import (
    ArchiveError,
    BudgetExceededError,
    Inventory,
    UnpackBudget,
    inspect,
    open_archive,
)
from .base import ScanContext

logger = logging.getLogger(__name__)


def budget_for(ctx: ScanContext) -> UnpackBudget:
    """Бюджет дерева. У корня создаётся здесь, вложения получают готовый."""
    if ctx.budget is None:
        ctx.budget = UnpackBudget(root_size=ctx.path.stat().st_size)
    return ctx.budget


def report(ctx: ScanContext, stage: str, inventory: Inventory) -> None:
    for code, detail in inventory.problems:
        ctx.add(stage, code, detail)
    if inventory.encrypted:
        ctx.encrypted = True
    if inventory.incomplete:
        mark_incomplete(ctx, stage, "; ".join(sorted(set(inventory.incomplete))))


def mark_incomplete(ctx: ScanContext, stage: str, reason: str) -> None:
    """Проверено не всё. Такой архив — непроверенный, а не чистый."""
    ctx.supported = False
    ctx.add(stage, "ARCHIVE_INCOMPLETE", reason)


def analyse(ctx: ScanContext, stage: str) -> None:
    budget = budget_for(ctx)
    try:
        with open_archive(ctx.path) as zf:
            inventory = inspect(zf, budget, ctx.depth)
    except BudgetExceededError as exc:
        mark_incomplete(ctx, stage, str(exc))
        return
    except ArchiveError as exc:
        # Не открылся — значит, и не проверен: содержимое неизвестно.
        ctx.supported = False
        ctx.add(stage, "ARCHIVE_MALFORMED", str(exc))
        return

    report(ctx, stage, inventory)
    ctx.members = inventory.members
    ctx.engines.setdefault("archive", {})["members"] = len(inventory.members)
    logger.debug(
        "опись архива",
        extra={"stage": stage, "members": len(inventory.members), "depth": ctx.depth},
    )
