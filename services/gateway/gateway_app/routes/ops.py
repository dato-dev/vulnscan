"""Служебные ручки: разбор dead-letter, список доверенных, теневой режим.

Подпись обязательна всегда, но одной подписи мало (M7.7). Каждая ручка здесь
отдаёт данные **тенанта вызывающего**, и только административный ключ видит
всех. Раньше хватало любой подписи: клиент читал `scan_id` и ключи объектов
соседей, их авторов и причины разрешений — а `POST /allowlist` принимал
`tenant: "*"`, то есть позволял снять блокировку с файла сразу для всех.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import ValidationError

from vscommon.allowlist import ANY_TENANT, AllowlistEntry, audit_line, entry_from_request
from vscommon.models import DeadLetter
from vscommon.rules_control import DisabledRule
from vscommon.rules_control import audit_line as rule_audit_line
from vscommon.rules_control import entry_from_request as rule_from_request
from vscommon.shadow import ALL_TENANTS

from ..auth import ops_scope, require_signed_ops

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/ops", tags=["ops"], dependencies=[Depends(require_signed_ops)])


def _admin_only(scope: str | None) -> None:
    """`404`, а не `403`: подтверждать существование ручки незачем.

    `ops_scope` возвращает `None` только административному ключу — на этом и
    держится проверка. Отдельного «а он точно админ» здесь нет намеренно: два
    места, решающих одно, расходятся.
    """
    if scope is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "не найдено")


@router.get("/dlq", response_model=list[DeadLetter])
async def list_dead_letters(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    scope: str | None = Depends(ops_scope),
) -> list[DeadLetter]:
    """Файлы, которые не удалось проверить. Новые первыми.

    Содержимого здесь нет — только ссылка на объект в карантине. Но ссылка на
    объект и есть то, чего соседу видеть нельзя: по ней читается файл.
    """
    entries = await request.app.state.vs.dlq.recent(count=limit, tenant=scope)
    logger.info(
        "запрошен разбор dead-letter",
        extra={"returned": len(entries), "scope": scope or ALL_TENANTS},
    )
    return entries


@router.get("/shadow")
async def shadow_report(
    request: Request, scope: str | None = Depends(ops_scope)
) -> dict[str, object]:
    """Что сервис заблокировал бы, если бы блокировал.

    Единственный способ увидеть цену включения блокировок до того, как они
    коснутся людей. Содержимого файлов здесь нет — только усечённые хэши, но
    и они чужие: учёт ведётся по тенанту.

    Доля «заблокировали бы» на общем счётчике вообще не имела смысла. Теневой
    режим включают по одному тенанту, значит общая доля описывала поток тех, у
    кого он включён, а выдавалась за долю спрашивающего.
    """
    report = await request.app.state.vs.shadow.report(scope or ALL_TENANTS)
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
async def list_allowlist(
    request: Request, scope: str | None = Depends(ops_scope)
) -> list[AllowlistEntry]:
    """Действующие записи, ближайшие к истечению — первыми.

    Свои и общие. Чужие — нет: в записи есть автор и причина, то есть рассказ
    о том, какие документы соседу приходится разрешать вручную.
    """
    return await request.app.state.vs.allowlist.entries(tenant=scope)


@router.post("/allowlist", response_model=AllowlistEntry, status_code=status.HTTP_201_CREATED)
async def add_to_allowlist(
    request: Request,
    body: bytes = Depends(require_signed_ops),
    ttl_days: int | None = Query(default=None, ge=1, le=365),
    scope: str | None = Depends(ops_scope),
) -> AllowlistEntry:
    """Снять блокировку с конкретного файла без выката релиза.

    Автор и причина обязательны: список — механизм ослабления проверки, и
    через полгода должно быть понятно, кто и зачем внёс запись. Срок жизни
    ограничен — вечная запись превращается в дыру, о которой все забыли.

    Тенант записи назначает сервер, а не тело запроса. `"*"` — «для всех» —
    может выписать только администратор: иначе любой клиент разрешал бы файл
    соседям, причём в списке это выглядело бы законной записью с автором и
    причиной.
    """
    try:
        payload = json.loads(body)
        entry = entry_from_request(payload)
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"нужны sha256, reason (от 8 символов) и author: {exc}",
        ) from exc

    if len(entry.sha256) != 64 or not all(c in "0123456789abcdef" for c in entry.sha256.lower()):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "ожидается sha256 в hex")

    asked_for = payload.get("tenant") if isinstance(payload, dict) else None
    if scope is not None:
        if asked_for is None:
            # Тенант не назван — берём из ключа. Это не догадка: обычным
            # ключом иначе как «себе» записать и нельзя.
            entry.tenant = scope
        elif asked_for != scope:
            # Молча сузить нельзя: попросивший `*` решил бы, что разрешил файл
            # всем, и вернулся бы к разбору только когда сосед снова упрётся.
            logger.warning(
                "попытка внести разрешение чужому тенанту",
                extra={"кому": asked_for, "кем": scope},
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"этим ключом можно вносить записи только для тенанта {scope!r}",
            )

    entry.sha256 = entry.sha256.lower()
    stored = await request.app.state.vs.allowlist.add(entry, ttl_days)
    logger.warning("в список доверенных внесена запись: %s", audit_line(stored))
    return stored


@router.delete("/allowlist/{sha256}")
async def remove_from_allowlist(
    request: Request,
    sha256: str,
    author: str = Query(min_length=2),
    tenant: str | None = Query(default=None),
    scope: str | None = Depends(ops_scope),
) -> dict[str, bool]:
    """Удаляет запись одного тенанта.

    Обычный ключ удаляет только свою: снятое соседом разрешение он не
    восстановит, а документ у соседа снова начнёт блокироваться — и выглядеть
    это будет как новое ложное срабатывание.
    """
    target = scope if scope is not None else (tenant or ANY_TENANT)
    removed = await request.app.state.vs.allowlist.remove(sha256.lower(), author, target)
    if not removed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "записи нет")
    return {"removed": True}


@router.get("/dlq/size")
async def dead_letter_size(
    request: Request, scope: str | None = Depends(ops_scope)
) -> dict[str, int]:
    """Размер очереди разбора. Величина общая, поэтому только администратору.

    Отдать её тенанту значило бы рассказать о потоке отказов у соседей; а
    считать её по одному тенанту — перебрать весь поток на каждый запрос.
    """
    _admin_only(scope)
    return {"size": await request.app.state.vs.dlq.size()}


@router.get("/rules/canary")
async def canary_report(
    request: Request, scope: str | None = Depends(ops_scope)
) -> dict[str, object]:
    """Что набор-кандидат сделал бы, если бы действовал (M7.2).

    Решение о выкатке принимается по `candidate_only`: это файлы, которые
    кандидат пометил бы, а действующий набор нет, то есть будущие ложные
    срабатывания. `active_only` — обратная сторона: детект, который выкатка
    потеряет.

    Содержимого файлов здесь нет — только усечённые хэши, по которым исходник
    ищется в карантине.
    """
    _admin_only(scope)
    report = await request.app.state.vs.canary.report()
    return {
        "since": report.since,
        "disagreements": report.disagreements,
        "candidate_only": [{"rule": r, "count": n} for r, n in report.candidate_only],
        "active_only": [{"rule": r, "count": n} for r, n in report.active_only],
        "samples": report.samples,
    }


@router.delete("/rules/canary")
async def reset_canary(request: Request, scope: str | None = Depends(ops_scope)) -> dict[str, bool]:
    """Обнулить наблюдение. Зовётся при смене кандидата.

    Иначе отчёт складывал бы расхождения двух разных наборов и отвечал бы на
    вопрос, которого никто не задавал.
    """
    _admin_only(scope)
    await request.app.state.vs.canary.reset()
    return {"reset": True}


@router.get("/rules/disabled", response_model=list[DisabledRule])
async def list_disabled_rules(
    request: Request, scope: str | None = Depends(ops_scope)
) -> list[DisabledRule]:
    """Правила, выключенные вручную: кто, когда и зачем (M7.2).

    Ручка административная — как и само выключение. Набор правил общий для
    установки, и тенанту решать за соседей нечего.
    """
    _admin_only(scope)
    return await request.app.state.vs.rule_control.entries()


@router.post("/rules/disabled", response_model=DisabledRule, status_code=status.HTTP_201_CREATED)
async def disable_rule(
    request: Request,
    body: bytes = Depends(require_signed_ops),
    scope: str | None = Depends(ops_scope),
) -> DisabledRule:
    """Выключить правило немедленно, не трогая файлы и не выкатывая релиз.

    Действует на ближайшей перезагрузке конфигурации воркера
    (`RELOAD_INTERVAL_S`, по умолчанию 30 с) — это и есть окно отката. Файлы
    правил при этом остаются как есть: их приводят в порядок отдельно.

    Автор и причина обязательны. Это механизм ослабления проверки, и через
    полгода должно быть понятно, кто и зачем его применил.
    """
    _admin_only(scope)
    try:
        entry = rule_from_request(json.loads(body))
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"нужны rule, reason (от 8 символов) и author: {exc}",
        ) from exc

    stored = await request.app.state.vs.rule_control.disable(entry)
    logger.warning("правило выключено: %s", rule_audit_line(stored))
    return stored


@router.delete("/rules/disabled/{rule}")
async def enable_rule(
    request: Request,
    rule: str,
    author: str = Query(min_length=2),
    scope: str | None = Depends(ops_scope),
) -> dict[str, bool]:
    """Вернуть правило в работу."""
    _admin_only(scope)
    if not await request.app.state.vs.rule_control.enable(rule, author):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "правило не выключено")
    return {"enabled": True}
