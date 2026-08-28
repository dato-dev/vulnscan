"""Health- и readiness-пробы."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response, status

from vscommon.metrics import metrics_enabled
from vscommon.metrics import render as render_metrics

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ops"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request, response: Response) -> dict[str, object]:
    """Готовность = доступен Redis. Без очереди принимать файлы бессмысленно."""
    state = request.app.state.vs
    try:
        await state.redis.ping()
    except Exception:
        logger.exception("readiness: redis недоступен")
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"ready": False, "redis": False}
    # Остановившееся обновление баз выглядит как работающее: clamd доволен тем,
    # что нашёл при старте. Неделя без обновления — это не предупреждение, а
    # отказ: `clean` по таким сигнатурам ничего не значит.
    av_age = await state.av_database_age()
    if not av_age.usable:
        logger.error(
            "базы антивируса непригодны, сервис не готов",
            extra={"возраст_ч": av_age.hours, "состояние": av_age.state.value},
        )
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "ready": av_age.usable,
        "redis": True,
        "av_db": {"state": av_age.state.value, "age_h": av_age.hours},
        "engine": await state.engine_version(),
        "libmagic": await state.libmagic_state(),
        "config": "degraded" if state.policies.degraded else "ok",
        "dlq_size": await state.dlq.size(),
        # Молча выключенная телеметрия не должна выглядеть работающей.
        "tracing": bool(getattr(request.app.state, "tracing", False)),
        "metrics": metrics_enabled(),
    }


@router.get("/metrics")
async def metrics() -> Response:
    """Метрики процесса gateway.

    Ручка не ограничивается по частоте и не требует подписи: она не создаёт
    нагрузки и не раскрывает содержимого файлов. Наружу не публикуется —
    скрейпит её Prometheus из внутренней сети.
    """
    payload, content_type = render_metrics()
    return Response(payload, media_type=content_type)
