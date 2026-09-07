"""Ограничение частоты запросов до чтения тела.

Проверка выполняется в middleware намеренно: тенант из тела стал бы известен
только после того, как файл прочитан и буферизован — то есть после того, как
нагрузка уже принята.

Ведро выбирается по **идентификатору ключа**, а не по заголовку с именем
тенанта. Заголовок клиент выставляет сам: сменив его, он получал свежий
счётчик и обходил собственную квоту. Идентификатор ключа так подделать нельзя —
незнакомый попадает в общее строгое ведро, а подпись всё равно проверяется
дальше, в аутентификации.
"""

from __future__ import annotations

import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from vscommon.keys import KEY_ID_HEADER
from vscommon.metrics import metrics

logger = logging.getLogger(__name__)

TENANT_HEADER = "X-Vulnscan-Tenant"
DEFAULT_TENANT = "default"

THROTTLED_PREFIXES = ("/v1/scan",)
"""Служебные и health-ручки не ограничиваем: они не создают нагрузки."""


UNKNOWN_BUCKET = "unknown-key"
"""Общее ведро для запросов с незнакомым ключом.

Строгое и одно на всех: перебор идентификаторов не должен давать по свежему
счётчику на каждую попытку.
"""


def tenant_of(request: Request) -> str:
    """Заголовок с именем тенанта. На политику и вердикт НЕ влияет.

    Оставлен для совместимости и логов; тенант определяется ключом.
    """
    return request.headers.get(TENANT_HEADER, "").strip() or DEFAULT_TENANT


def _bucket_of(request: Request, state: object) -> tuple[str, object]:
    """Ведро частоты и политика, по которой считается лимит.

    Подпись здесь не проверяется — это дорого делать до отказа по частоте, да
    и незачем: подделанный идентификатор попадёт в общее ведро, а на самом
    запросе всё равно споткнётся об аутентификацию.
    """
    key_id = request.headers.get(KEY_ID_HEADER, "").strip()
    key = state.keys.get(key_id) if key_id else None  # type: ignore[attr-defined]
    if key is None:
        return UNKNOWN_BUCKET, state.policies.for_tenant(None)  # type: ignore[attr-defined]
    return key.tenant, state.policies.for_tenant(key.tenant)  # type: ignore[attr-defined]


async def throttle_middleware(request: Request, call_next):
    state = getattr(request.app.state, "vs", None)
    if state is None or not _throttled(request):
        return await call_next(request)

    bucket, policy = _bucket_of(request, state)
    decision = await state.rate_limiter.check(bucket, policy.rate_limit_per_min)

    if not decision.allowed:
        logger.warning(
            "частота запросов превышена",
            extra={"ведро": bucket, "observed": int(decision.observed)},
        )
        metrics().rejections.labels(reason="rate_limit").inc()
        return _too_many(decision.retry_after_s)

    return await call_next(request)


def _throttled(request: Request) -> bool:
    return request.method == "POST" and request.url.path.startswith(THROTTLED_PREFIXES)


def _too_many(retry_after_s: int, detail: str = "превышена частота запросов") -> Response:
    return JSONResponse(
        {"detail": detail},
        status_code=429,
        headers={"Retry-After": str(retry_after_s)},
    )
