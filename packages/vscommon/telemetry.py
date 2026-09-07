"""Трассировка OpenTelemetry. Единственное место, где настраивается OTEL.

Библиотечные модули только берут `span(...)` и ничего не конфигурируют — по той
же схеме, что и с `logging`.

Наблюдаемость не имеет права влиять на вердикт, поэтому:

- отсутствующий SDK не ломает сервис, а выключает трассировку;
- недоступный коллектор не задерживает стадию: экспорт батчами, в своём потоке;
- атрибуты спана фильтруются так же строго, как поля логов, — это те же данные,
  вынесенные наружу, и раздел «что запрещено писать в логи» действует дословно.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final

from .version import VERSION

logger = logging.getLogger(__name__)

try:  # pragma: no cover — зависит от окружения, обе ветки проверяются тестами
    from opentelemetry import trace as _otel_trace
    from opentelemetry.context import Context
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    SDK_AVAILABLE = False

_enabled = False
_provider: Any = None

TRACEPARENT_HEADER: Final = "traceparent"

_TRACEPARENT_RE: Final = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")
"""Строгая форма W3C. Разбирать вольно нельзя — значение приходит извне."""

FORBIDDEN_ATTRS: Final = frozenset(
    {
        "filename",
        "file_name",
        "name",
        "sha256",
        "callback_url",
        "url",
        "signature",
        "authorization",
        "api_key",
        "token",
        "secret",
        "exif",
        "text",
        "content",
        "body",
    }
)
"""Ключи, которые в спан не попадают ни при каких условиях.

Спан уезжает во внешнюю систему, где живёт дольше и виден шире, чем лог.
Сервис обрабатывает сканы паспортов и договоров: имя файла содержит ПДн,
полный sha256 — идентификатор документа, URL коллбэка — параметры с секретами.
Для отладки конкретного файла есть `scan_id` и артефакты в хранилище.
"""

_MAX_ATTR_LEN: Final = 256


class _NoopSpan:
    """Заглушка с интерфейсом спана. Позволяет не городить `if` на вызовах."""

    def set_attribute(self, key: str, value: object) -> None:
        return None

    def update_name(self, name: str) -> None:
        return None

    def record_exception(self, exc: BaseException) -> None:
        return None

    def set_status(self, *args: object, **kwargs: object) -> None:
        return None

    def is_recording(self) -> bool:
        return False


def setup_tracing(
    service: str,
    *,
    enabled: bool = True,
    endpoint: str = "",
    sample_ratio: float = 1.0,
    version: str = VERSION,
) -> bool:
    """Настраивает экспорт трассировок. Вызывается один раз на старте процесса.

    Возвращает, включилась ли трассировка: это попадает в `/readyz`, чтобы
    молча выключенная телеметрия не выглядела как работающая.
    """
    global _enabled, _provider

    if not enabled:
        logger.info("трассировка выключена конфигурацией")
        return False
    if not SDK_AVAILABLE:
        # По той же логике, что и с недоступным парсером: деградируем и
        # сообщаем, а не падаем.
        logger.warning("SDK OpenTelemetry недоступен, трассировка выключена")
        return False
    if not endpoint:
        logger.warning("не задан адрес коллектора, трассировка выключена")
        return False

    resource = Resource.create({"service.name": service, "service.version": version})
    provider = TracerProvider(
        resource=resource,
        sampler=ParentBased(TraceIdRatioBased(sample_ratio)),
    )
    # Батчами и в своём потоке: стадия не должна ждать коллектор.
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    _otel_trace.set_tracer_provider(provider)
    _provider = provider
    _enabled = True
    logger.info(
        "трассировка включена",
        extra={"service": service, "sample_ratio": sample_ratio},
    )
    return True


def shutdown_tracing(timeout_ms: int = 5_000) -> None:
    """Досылает накопленные спаны на остановке процесса."""
    global _enabled, _provider
    if _provider is None:
        return
    try:
        _provider.shutdown()
    except Exception:
        logger.warning("не удалось корректно закрыть экспорт трассировок")
    finally:
        _provider = None
        _enabled = False


def tracing_enabled() -> bool:
    return _enabled


def safe_attributes(raw: dict[str, object]) -> dict[str, object]:
    """Отбрасывает запрещённые ключи и подрезает длину значений.

    Фильтр здесь, а не на вызывающей стороне, намеренно: полагаться на
    внимательность в двадцати местах нельзя, а забытый `filename=` в атрибутах
    вынесет ПДн во внешнюю систему.
    """
    clean: dict[str, object] = {}
    for key, value in raw.items():
        if key.lower() in FORBIDDEN_ATTRS or value is None:
            continue
        if isinstance(value, str) and len(value) > _MAX_ATTR_LEN:
            value = value[:_MAX_ATTR_LEN]
        clean[key] = value
    return clean


@contextmanager
def span(name: str, **attributes: object) -> Iterator[Any]:
    """Спан вокруг блока. Без SDK — пустышка с тем же интерфейсом.

    Исключение помечает спан ошибкой и летит дальше: телеметрия ничего не
    проглатывает.
    """
    if not _enabled:
        yield _NoopSpan()
        return

    tracer = _otel_trace.get_tracer("vscommon")
    with tracer.start_as_current_span(name) as current:
        for key, value in safe_attributes(attributes).items():
            current.set_attribute(key, value)  # type: ignore[arg-type]
        try:
            yield current
        except Exception as exc:
            current.record_exception(exc)
            current.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            raise


def current_traceparent() -> str | None:
    """Текущий контекст в форме W3C — для передачи через очередь.

    Заголовком его не передать: gateway и воркер разнесены во времени и по
    хостам, между ними Redis Stream. Значение едет полем в задаче.
    """
    if not _enabled:
        return None
    carrier: dict[str, str] = {}
    TraceContextTextMapPropagator().inject(carrier)
    return carrier.get(TRACEPARENT_HEADER)


def valid_traceparent(value: str | None) -> bool:
    return bool(value) and bool(_TRACEPARENT_RE.match(value or ""))


@contextmanager
def continue_trace(traceparent: str | None, name: str, **attributes: object) -> Iterator[Any]:
    """Продолжает трассировку, начатую в другом процессе.

    Негодное значение не принимается: чужой или битый контекст склеил бы наш
    скан с посторонним трейсом. В этом случае начинаем новый корень, а не
    отказываемся работать — телеметрия не повод терять задачу.
    """
    if not _enabled:
        yield _NoopSpan()
        return

    parent: Context | None = None
    if valid_traceparent(traceparent):
        parent = TraceContextTextMapPropagator().extract({TRACEPARENT_HEADER: traceparent or ""})
    elif traceparent:
        logger.debug("получен негодный traceparent, начинаю новый трейс")

    tracer = _otel_trace.get_tracer("vscommon")
    with tracer.start_as_current_span(name, context=parent) as current:
        for key, value in safe_attributes(attributes).items():
            current.set_attribute(key, value)  # type: ignore[arg-type]
        try:
            yield current
        except Exception as exc:
            current.record_exception(exc)
            current.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            raise


def current_ids() -> tuple[str, str] | None:
    """`trace_id` и `span_id` текущего спана — для связки логов с трейсами."""
    if not _enabled:
        return None
    ctx = _otel_trace.get_current_span().get_span_context()
    if not ctx.is_valid:
        return None
    return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
