"""Метрики HTTP-запросов gateway.

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
