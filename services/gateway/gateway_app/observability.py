"""Метрики и серверный спан HTTP-запросов gateway.

Отдельным middleware, а не внутри обработчиков: так в счёт попадают и те
запросы, что отвергнуты до обработчика — ограничением частоты или проверкой
подписи. Именно они интереснее всего при разборе инцидента.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

from vscommon.metrics import metrics
from vscommon.telemetry import TRACEPARENT_HEADER, continue_trace

logger = logging.getLogger(__name__)

_UNKNOWN_ROUTE = "unmatched"


def route_label(request: Request) -> str:
    """Шаблон маршрута, а не фактический путь.

    `/v1/scan/{scan_id}` даёт один ряд метрик, сырой путь — по ряду на скан.
    Неизвестный маршрут схлопывается: иначе перебор несуществующих адресов
    сам по себе раздувал бы Prometheus.
    """
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return str(path) if path else _UNKNOWN_ROUTE


async def metrics_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        # Необработанное исключение — тоже исход запроса, и он должен быть виден.
        _observe(request, "500", time.perf_counter() - started)
        raise
    _observe(request, str(response.status_code), time.perf_counter() - started)
    return response


def _observe(request: Request, status: str, elapsed_s: float) -> None:
    current = metrics()
    route = route_label(request)
    method = request.method
    current.http_requests.labels(method=method, route=route, status=status).inc()
    current.http_seconds.labels(method=method, route=route).observe(elapsed_s)


async def tracing_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Серверный спан запроса. Единственное место, где принимается чужой контекст.

    До этого спанов у gateway было ровно два — приём файла и продолжение в
    воркере, — и открывались они уже после чтения тела, хэширования и заливки в
    S3. То есть самая долгая часть приёма в трейс не попадала вовсе, а
    `/v1/ops/*`, `/v1/admin/*` и виджет не попадали никак: заведение тенанта и
    отзыв ключа — как раз те редкие операции, о которых потом спрашивают
    «когда это произошло».

    Контекст от клиента принимается здесь и только здесь. Дальше по стеку идут
    обычные вложенные спаны: `continue_trace` в середине обработки создал бы не
    потомка, а брата — он ставит родителя явно, из заголовка, и дерево
    разъезжалось бы ровно там, где его собирались смотреть.
    """
    # Имя спана — шаблон маршрута, но до `call_next` маршрут ещё не выбран:
    # его проставляет роутер. Поэтому спан открывается под временным именем и
    # переименовывается, когда шаблон известен. Сырой путь в имени недопустим
    # по той же причине, что и в метке: `/v1/scan/abc123` — имя на каждый скан.
    with continue_trace(
        request.headers.get(TRACEPARENT_HEADER),
        f"HTTP {request.method}",
        http_method=request.method,
    ) as span:
        try:
            response = await call_next(request)
        except Exception:
            span.update_name(f"{request.method} {route_label(request)}")
            span.set_attribute("http_route", route_label(request))
            raise
        span.update_name(f"{request.method} {route_label(request)}")
        span.set_attribute("http_route", route_label(request))
        span.set_attribute("http_status_code", response.status_code)
        return response
