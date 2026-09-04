"""CORS для загрузки из браузера (M12.4).

Своя реализация вместо `CORSMiddleware` — не от любви к велосипедам. Готовая
берёт список разрешённых источников один раз при создании приложения, а у нас
он живёт в реестре ключей и перезагружается на живом сервисе: добавили сайту
origin — он должен заработать без рестарта, как и отзыв ключа.

Что здесь важно понимать про preflight.

Браузер шлёт `OPTIONS` **без** наших заголовков: ни ключа сайта, ни талона в
нём нет — только `Origin` и список заголовков, которые собирается прислать.
Значит на preflight нельзя проверить, что этот origin разрешён именно ЭТОМУ
ключу. Проверяется более слабое: что origin вообще известен хоть одному
действующему публичному ключу. Полная проверка — на самом запросе, в
`require_site_key`.

Ослаблением это не является. Разрешённый preflight не отдаёт данных и не даёт
прав: настоящий запрос всё равно пройдёт аутентификацию. А вот отвечать
согласием кому попало не стоит — незачем сообщать, что мы вообще принимаем
браузерные загрузки.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.responses import PlainTextResponse

logger = logging.getLogger(__name__)

CORS_PATHS = frozenset({"/v1/tickets", "/v1/scan"})
"""Ручки, доступные из браузера.

Список закрытый и короткий намеренно. Всё остальное — чтение результатов,
скачивание обезвреженной копии, административные ручки — требует секретного
ключа, а секретному ключу в браузере не место. Разрешив им CORS «на всякий
случай», мы бы приглашали держать секрет в странице.

Сравнение **точное**, а не по префиксу. Первая версия использовала
`startswith`, и `/v1/scan` открывал заодно `/v1/scan/{id}` и
`/v1/scan/{id}/clean` — то есть ровно чтение результатов и выдачу файла. Путь
с параметром выглядит продолжением, а является другой ручкой.
"""

ALLOWED_HEADERS = ("x-vulnscan-key", "x-vulnscan-ticket", "idempotency-key", "content-type")
"""Что браузеру позволено прислать. Список положительный: незнакомый заголовок
не разрешается, а не пропускается.
"""

MAX_AGE_S = 600
"""Сколько браузер может помнить разрешение. Десять минут: preflight на каждую
загрузку — лишний круг задержки, а сутки означали бы, что снятый origin
продолжает работать у тех, кто уже заходил.
"""


def _origins_of_public_keys(request: Request) -> set[str]:
    """Все origin действующих публичных ключей.

    Реестр читается на каждый запрос, а не кэшируется: он перезагружается на
    живом сервисе, и кэш здесь означал бы, что отозванный ключ ещё какое-то
    время принимается — ровно то, ради чего горячая перезагрузка и делалась.
    """
    state = getattr(request.app.state, "vs", None)
    registry = getattr(state, "keys", None)
    if registry is None or registry.degraded:
        return set()

    return {
        origin.strip().rstrip("/").lower()
        for key in registry.all_keys()
        if key.public and not key.disabled
        for origin in key.origins
    }


def _is_allowed(request: Request, origin: str) -> bool:
    candidate = origin.strip().rstrip("/").lower()
    if not candidate or candidate == "null":
        return False
    return candidate in _origins_of_public_keys(request)


def _preflight(request: Request, origin: str) -> Response:
    """Ответ на `OPTIONS`."""
    requested = request.headers.get("access-control-request-headers", "")
    granted = [
        name.strip()
        for name in requested.split(",")
        if name.strip().lower() in ALLOWED_HEADERS
    ]

    return PlainTextResponse(
        "",
        status_code=204,
        headers={
            # Конкретный origin, а не `*`: со звёздочкой ответ прочитала бы
            # любая страница, а с талоном в ответе это уже не мелочь.
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": ", ".join(granted),
            "Access-Control-Max-Age": str(MAX_AGE_S),
            # Без `Vary` промежуточный кэш отдал бы одному сайту разрешение,
            # выданное другому.
            "Vary": "Origin",
        },
    )


async def cors_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    origin = request.headers.get("origin", "")
    if not origin or request.url.path.rstrip("/") not in CORS_PATHS:
        return await call_next(request)

    allowed = _is_allowed(request, origin)

    if request.method == "OPTIONS" and "access-control-request-method" in request.headers:
        if not allowed:
            logger.warning("preflight с незарегистрированного origin отклонён")
            # Ответ без заголовков CORS — браузер и так заблокирует запрос.
            # Отдельный код состояния ничего не добавил бы: до кода браузер
            # доходит только затем, чтобы сообщить об ошибке в консоль.
            return PlainTextResponse("", status_code=403)
        return _preflight(request, origin)

    response = await call_next(request)
    if allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response
