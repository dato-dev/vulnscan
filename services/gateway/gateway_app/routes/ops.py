"""Служебные ручки: разбор dead-letter. Подпись обязательна всегда."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import ValidationError

from vscommon.allowlist import AllowlistEntry, audit_line, entry_from_request
from vscommon.models import DeadLetter

from ..auth import require_signed_ops

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ops", tags=["ops"], dependencies=[Depends(require_signed_ops)])


@router.get("/dlq", response_model=list[DeadLetter])
async def list_dead_letters(
    request: Request, limit: int = Query(default=50, ge=1, le=500)
) -> list[DeadLetter]:
    """Файлы, которые не удалось проверить. Новые первыми.

    Содержимого здесь нет — только ссылка на объект в карантине.
    """
    entries = await request.app.state.vs.dlq.recent(count=limit)
    logger.info("запрошен разбор dead-letter", extra={"returned": len(entries)})
    return entries


@router.get("/shadow")
async def shadow_report(request: Request) -> dict[str, object]:
    """Что сервис заблокировал бы, если бы блокировал.

    Единственный способ увидеть цену включения блокировок до того, как они
    коснутся людей. Содержимого файлов здесь нет — только усечённые хэши.
    """
    report = await request.app.state.vs.shadow.report()
    logger.info(
        "запрошен отчёт теневого режима",
        extra={"total": report.total, "would_block": report.would_block},
    )
    return {
        "since": report.since,
        "total": report.total,
        "would_block": report.would_block,
        "would_block_ratio": report.would_block_ratio,
        "by_verdict": report.by_verdict,
        "top_codes": [{"code": c, "count": n} for c, n in report.top_codes],
        "recent_blocks": report.recent_blocks,
    }


@router.get("/allowlist", response_model=list[AllowlistEntry])
async def list_allowlist(request: Request) -> list[AllowlistEntry]:
    """Действующие записи, ближайшие к истечению — первыми."""
    return await request.app.state.vs.allowlist.entries()


@router.post("/allowlist", response_model=AllowlistEntry, status_code=status.HTTP_201_CREATED)
async def add_to_allowlist(
    request: Request,
    body: bytes = Depends(require_signed_ops),
    ttl_days: int | None = Query(default=None, ge=1, le=365),
) -> AllowlistEntry:
    """Снять блокировку с конкретного файла без выката релиза.

    Автор и причина обязательны: список — механизм ослабления проверки, и
    через полгода должно быть понятно, кто и зачем внёс запись. Срок жизни
    ограничен — вечная запись превращается в дыру, о которой все забыли.
    """
    try:
        entry = entry_from_request(json.loads(body))
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"нужны sha256, reason (от 8 символов) и author: {exc}",
        ) from exc

    if len(entry.sha256) != 64 or not all(c in "0123456789abcdef" for c in entry.sha256.lower()):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "ожидается sha256 в hex")

    entry.sha256 = entry.sha256.lower()
    stored = await request.app.state.vs.allowlist.add(entry, ttl_days)
    logger.warning("в список доверенных внесена запись: %s", audit_line(stored))
    return stored


@router.delete("/allowlist/{sha256}")
async def remove_from_allowlist(
    request: Request, sha256: str, author: str = Query(min_length=2)
) -> dict[str, bool]:
    removed = await request.app.state.vs.allowlist.remove(sha256.lower(), author)
    if not removed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "записи нет")
    return {"removed": True}


@router.get("/dlq/size")
async def dead_letter_size(request: Request) -> dict[str, int]:
    return {"size": await request.app.state.vs.dlq.size()}
