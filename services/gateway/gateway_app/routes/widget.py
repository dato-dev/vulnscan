"""Раздача виджета: загрузчик и документ фрейма (M12.7)."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from vscommon.keys import origin_allowed

from ..widget.contract import VERSION
from ..widget.theme import build as build_theme

logger = logging.getLogger(__name__)

# Версия в пути, а не в параметре запроса. Раздаём мы, ломаем тоже мы, и у
# сайта нет способа откатиться: значит совместимые правки едут на том же
# адресе, а несовместимые получают новый (M12.8).
router = APIRouter(prefix=f"/widget/{VERSION}", tags=["widget"])

ASSETS = Path(__file__).parent.parent / "widget"

_LOADER_CACHE = "public, max-age=300"
"""Пять минут. Долгий кэш означал бы, что исправление в загрузчике доходит до
чужих страниц неделями, а короткий — лишний запрос на каждый показ формы.
"""


def _asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


@router.get("/loader.js")
async def loader() -> Response:
    """Скрипт, который сайт вставляет к себе.

    Отдаётся всем: в нём нет ничего секретного, а знать, кому его отдавать, мы
    на этом этапе не можем — ключ появляется только в разметке страницы.
    """
    return Response(
        _asset("loader.js"),
        media_type="application/javascript; charset=utf-8",
        headers={
            "Cache-Control": _LOADER_CACHE,
            # Чтобы при разборе «у нас всё сломалось» не гадать, какая версия
            # у сайта в кэше. Диагностика, а не механизм.
            "X-Vulnscan-Widget": VERSION,
        },
    )


@router.get("/frame")
async def frame(request: Request, key: str = "", origin: str = "") -> Response:
    """Документ фрейма. Отдаётся только сайту, чей публичный ключ предъявлен.

    Здесь стоит главная защита от встраивания на чужую страницу —
    `frame-ancestors`. Именно она, а не проверка параметров: параметры ставит
    тот, кто нас встраивает, а `frame-ancestors` исполняет браузер, и обойти
    его встраивающий не может.
    """
    registry = request.app.state.vs.keys
    site_key = registry.get(key) if key else None

    if site_key is None or not site_key.public or not site_key.origins:
        logger.warning("фрейм запрошен с негодным ключом сайта", extra={"key_id": key})
        raise HTTPException(status.HTTP_404_NOT_FOUND, "не найдено")

    if origin and not origin_allowed(site_key, origin):
        # Параметр не совпал со списком ключа. Само по себе это не защита —
        # его ставит встраивающая сторона, — но отвечать на заведомо
        # неправильный запрос незачем.
        logger.warning("фрейм запрошен с чужим origin", extra={"key_id": key})
        raise HTTPException(status.HTTP_404_NOT_FOUND, "не найдено")

    ancestors = " ".join(site_key.origins)

    # Поведение при несостоявшейся проверке приходит СЮДА, а не выбирается
    # скриптом: страницу правит кто угодно, а этот документ отдаём мы (M12.9).
    policy = request.app.state.vs.policies.for_tenant(site_key.tenant)
    document = _asset("frame.html").replace(
        "__ON_UNAVAILABLE__", policy.widget_on_unavailable
    )
    # Оформление: только известные переменные и только проверенные значения.
    # Чужой CSS внутри нашего документа — это чужой код на нашем origin.
    document = document.replace(
        "__THEME__", build_theme(dict(request.query_params))
    )

    return Response(
        document,
        media_type="text/html; charset=utf-8",
        headers={
            # Кто имеет право нас встроить. Список из ключа, не из запроса.
            "Content-Security-Policy": (
                f"frame-ancestors {ancestors}; "
                # Скрипт внутри документа, внешних источников нет вовсе.
                "default-src 'none'; "
                "script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; "
                "connect-src 'self'; "
                "form-action 'none'"
            ),
            # Старый заголовок для браузеров, не знающих frame-ancestors.
            # `DENY` здесь нельзя: он запретил бы встраивание вообще, то есть
            # ровно то, ради чего документ существует.
            "X-Frame-Options": "ALLOWALL",
            # Документ зависит от ключа: общий кэш отдал бы фрейм одного сайта
            # другому вместе с его списком origin.
            "Cache-Control": "private, max-age=60",
            "Vary": "Origin",
            "X-Vulnscan-Widget": VERSION,
        },
    )


@router.get("/status")
async def status_by_ticket(request: Request, ticket: str = "") -> Response:
    """Состояние проверки по талону наблюдения (M12.7).

    Ручка для фрейма и только для него. Возвращает минимум: закончилась ли
    проверка и годится ли файл. Ни признаков, ни балла, ни имени файла —
    браузеру они не нужны, а всё лишнее здесь пришлось бы объяснять.

    Талон привязан к одному скану. Поэтому предъявитель не может ни узнать
    вердикт чужого файла, ни перебрать идентификаторы: без талона ручка не
    отвечает вовсе.
    """
    token = ticket.strip()
    if not token:
        # Отказ до обращения к хранилищу: искать нечего, а лишний поход в
        # Redis на каждый запрос без талона — способ платить за чужой перебор.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "не найдено")

    state = request.app.state.vs
    resolved = await state.status_tickets.resolve(token)
    if resolved is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "не найдено")

    scan_id, tenant = resolved
    if not await state.ownership.allows(scan_id, tenant):
        # Владение перепроверяется, хотя талон выдавали мы: между выдачей и
        # опросом скан мог истечь, а «не знаем чей» не может означать «отдать
        # спросившему».
        raise HTTPException(status.HTTP_404_NOT_FOUND, "не найдено")

    result = await state.results.load_status(scan_id)
    if result is None:
        # Проверка ещё идёт: записи о завершении нет.
        return JSONResponse({"status": "scanning", "done": False})

    verdict = result.verdict.value if result.verdict else ""
    return JSONResponse(
        {
            "status": result.status.value,
            "done": True,
            "scan_id": scan_id,
            # Три состояния вместо вердикта целиком. Решение всё равно
            # принимает бэкенд сайта своим ключом (M12.6), а браузеру нужно
            # ровно одно: что показать посетителю.
            "outcome": (
                "blocked"
                if verdict == "malicious"
                else "checked"
                if verdict == "clean"
                else "unchecked"
            ),
        }
    )
