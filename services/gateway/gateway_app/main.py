"""Точка входа gateway."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vscommon.keys import KeyRegistry
from vscommon.logging import setup_logging
from vscommon.metrics import setup_metrics
from vscommon.telemetry import setup_tracing, shutdown_tracing

from .config import settings
from .observability import metrics_middleware
from .routes import admin, health, ops, scan
from .state import build_state
from .throttle import throttle_middleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(settings.service_name, settings.log_level, settings.log_format)
    # Телеметрия поднимается после логов и до состояния: её отказ должен быть
    # виден в логах, а не проглочен.
    # Список тенантов для меток берётся из реестра ключей, а не из отдельной
    # переменной: два списка неизбежно разъезжаются, и метрики тихо схлопывают
    # настоящего тенанта в `other`.
    setup_metrics(known_tenants=KeyRegistry.load(settings.keys_file).tenants)
    app.state.tracing = setup_tracing(
        settings.service_name,
        enabled=settings.otel_enabled,
        endpoint=settings.otel_endpoint,
        sample_ratio=settings.otel_sample_ratio,
    )
    if not settings.require_signature:
        # Послабление для разработки. Наружу такой сервис выставлять нельзя:
        # загружать файлы сможет кто угодно, а тенант возьмётся из умолчания.
        logger.error(
            "ПОДПИСЬ НЕ ТРЕБУЕТСЯ: режим только для разработки, "
            "наружу такой сервис выставлять нельзя"
        )

    logger.info("старт gateway", extra={"port": settings.port})
    app.state.vs = await build_state()
    # Ключи и политики перечитываются на живом сервисе: отзыв ключа и заведение
    # тенанта не должны требовать окна обслуживания.
    await app.state.vs.reload_keys()
    reload_task = asyncio.create_task(_reload_loop(app))
    try:
        yield
    finally:
        logger.info("остановка gateway")
        reload_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reload_task
        await app.state.vs.close()
        shutdown_tracing()


app = FastAPI(
    title="vulnscantg",
    version="0.1.0",
    description="CDR и детект вредоносного содержимого во вложениях чат-бота",
    lifespan=lifespan,
)
# Порядок важен: метрики снаружи, чтобы в них попали и отвергнутые запросы.
app.middleware("http")(throttle_middleware)
app.middleware("http")(metrics_middleware)
app.include_router(health.router)
app.include_router(scan.router)
app.include_router(ops.router)
app.include_router(admin.router)


async def _reload_loop(app: FastAPI) -> None:
    """Подхватывает изменения ключей и политик без перезапуска."""
    while True:
        await asyncio.sleep(settings.config_reload_interval_s)
        try:
            await app.state.vs.reload_keys()
            await app.state.vs.reload_policies()
        except Exception:
            logger.exception("сбой при перезагрузке конфигурации")
