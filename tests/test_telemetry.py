"""Тесты наблюдаемости.

Главное, что здесь проверяется, — телеметрия не влияет на вердикт и не выносит
наружу того, что запрещено писать в логи.
"""

from __future__ import annotations

import logging

import pytest

from gateway_app.observability import route_label
from vscommon import telemetry
from vscommon.logging import ContextFilter, log_context
from vscommon.metrics import (
    OTHER_TENANT,
    Metrics,
    metrics,
    render,
    setup_metrics,
    tenant_label,
)
from vscommon.telemetry import (
    continue_trace,
    current_traceparent,
    safe_attributes,
    span,
    valid_traceparent,
)

GOOD_TRACEPARENT = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"


# --- фильтр атрибутов ---------------------------------------------------


@pytest.mark.parametrize(
    "key",
    ["filename", "file_name", "sha256", "callback_url", "signature", "token", "exif", "text"],
)
def test_forbidden_attributes_never_reach_span(key: str) -> None:
    """Спан уезжает во внешнюю систему и живёт там дольше лога.

    Сервис обрабатывает сканы паспортов: имя файла — ПДн, URL коллбэка несёт
    параметры и подпись. Полагаться на внимательность в двадцати местах вызова
    нельзя, поэтому фильтр стоит в самом `span`.
    """
    assert key not in safe_attributes({key: "секрет", "stage": "pdf"})


def test_allowed_attributes_survive() -> None:
    attrs = safe_attributes({"stage": "pdf", "size": 1024, "profile": "strict"})
    assert attrs == {"stage": "pdf", "size": 1024, "profile": "strict"}


def test_long_attribute_is_truncated() -> None:
    """Атрибут не должен утаскивать в трейс фрагмент документа."""
    value = safe_attributes({"detail": "я" * 5000})["detail"]
    assert isinstance(value, str) and len(value) == 256


def test_none_attribute_is_dropped() -> None:
    assert safe_attributes({"tenant": None}) == {}


# --- контекст трассировки ------------------------------------------------


def test_valid_traceparent() -> None:
    assert valid_traceparent(GOOD_TRACEPARENT)


@pytest.mark.parametrize(
    "value",
    ["", None, "мусор", "00-short-b" * 2, "01-" + "a" * 32 + "-" + "b" * 16 + "-01"],
)
def test_garbage_traceparent_is_rejected(value: str | None) -> None:
    """Значение приходит из очереди — разбирать его вольно нельзя."""
    assert not valid_traceparent(value)


def test_continue_trace_survives_garbage() -> None:
    """Негодный контекст не повод терять задачу.

    Телеметрия не имеет права влиять на обработку: битый `traceparent`
    начинает новый корень, а не роняет скан.
    """
    with continue_trace("совершенный мусор", "scan.process") as sp:
        assert sp is not None


def test_traceparent_is_none_when_tracing_disabled() -> None:
    assert not telemetry.tracing_enabled()
    assert current_traceparent() is None


def test_span_is_noop_without_setup() -> None:
    """Вызовы безопасны до и без инициализации — иначе их пришлось бы обвешивать `if`."""
    with span("stage", stage="pdf") as sp:
        sp.set_attribute("ok", True)
        assert sp.is_recording() is False


def test_span_lets_exception_through() -> None:
    """Телеметрия ничего не проглатывает."""
    with pytest.raises(ValueError), span("stage"):
        raise ValueError("сбой стадии")


# --- метки метрик --------------------------------------------------------


def test_unknown_tenant_collapses() -> None:
    """Тенант приходит в теле запроса.

    Без приведения к известному списку любой клиент мог бы наплодить рядов
    метрик, просто присылая новые значения, — это способ положить Prometheus
    чужим запросом.
    """
    setup_metrics(known_tenants=("telegram-bot",))
    assert tenant_label("telegram-bot") == "telegram-bot"
    assert tenant_label("выдуманный-" + "x" * 100) == OTHER_TENANT
    assert tenant_label(None) == "default"


def test_metrics_render_is_prometheus_text() -> None:
    setup_metrics()
    metrics().scans.labels(verdict="clean", tenant="default", mode="both").inc()
    payload, content_type = render()

    assert b"vs_scans_total" in payload
    assert "text/plain" in content_type


def test_stage_observation_is_recorded() -> None:
    setup_metrics()
    metrics().observe_stage("clamav", 0.012, ok=True)
    payload, _ = render()

    assert b"vs_stage_duration_seconds" in payload


def test_cache_levels_counted_separately() -> None:
    """M4.6: без раздельного учёта не увидеть, что после обновления баз
    проседает только антивирусный уровень."""
    setup_metrics()
    metrics().observe_cache("structural", hit=True)
    metrics().observe_cache("av", hit=False)
    payload, _ = render()

    assert b'level="structural"' in payload
    assert b'level="av"' in payload


def test_registries_are_isolated() -> None:
    """Свой реестр на набор: иначе повторная инициализация падала бы на
    дублирующейся регистрации метрики."""
    first, second = Metrics(), Metrics()
    assert first.registry is not second.registry


# --- связка логов с трейсами --------------------------------------------


def test_log_record_has_no_trace_ids_without_tracing() -> None:
    """Выключенная трассировка не должна подмешивать пустые поля в логи."""
    record = logging.LogRecord("t", logging.INFO, "", 0, "сообщение", None, None)
    with log_context(scan_id="abc"):
        ContextFilter().filter(record)

    assert record.scan_id == "abc"
    assert not hasattr(record, "trace_id")


# --- классификация ошибок ------------------------------------------------


def test_telemetry_failure_is_infrastructural() -> None:
    """Сбой экспортёра нельзя принять за порчу файла.

    Иначе транзиторная недоступность коллектора закрыла бы задачу без повтора.
    """
    from vscommon.errors import ErrorKind, classify

    exc = ConnectionError("коллектор недоступен")
    exc.__traceback__ = None
    assert classify(exc) is ErrorKind.INFRA


# --- включённая трассировка ----------------------------------------------
#
# Всё выше проверяет выключенный путь. Здесь поднимается настоящий провайдер
# со сбором спанов в память: без этого мы бы знали только то, что заглушки
# не падают.


@pytest.fixture
def tracing() -> object:
    """Настоящий провайдер OTEL с экспортом в память."""
    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    export = pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    exporter = export.InMemorySpanExporter()
    provider = sdk.TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    previous = otel_trace._TRACER_PROVIDER
    otel_trace._TRACER_PROVIDER = provider
    telemetry._enabled = True
    try:
        yield exporter
    finally:
        telemetry._enabled = False
        otel_trace._TRACER_PROVIDER = previous


def test_span_is_actually_recorded(tracing) -> None:
    with span("stage", stage="clamav", size=1024):
        pass

    spans = tracing.get_finished_spans()
    assert [s.name for s in spans] == ["stage"]
    assert spans[0].attributes["stage"] == "clamav"


def test_forbidden_attribute_absent_from_recorded_span(tracing) -> None:
    """Проверка не на фильтре, а на том, что реально уехало в экспортёр."""
    with span("scan.accept", filename="паспорт.pdf", sha256="ab" * 32, tenant="default"):
        pass

    attributes = tracing.get_finished_spans()[0].attributes
    assert "filename" not in attributes
    assert "sha256" not in attributes
    assert attributes["tenant"] == "default"


def test_failed_span_is_marked_and_reraises(tracing) -> None:
    with pytest.raises(RuntimeError), span("stage", stage="pdf"):
        raise RuntimeError("парсер упал")

    recorded = tracing.get_finished_spans()[0]
    assert recorded.status.status_code.name == "ERROR"
    assert recorded.events, "исключение должно попасть в спан событием"


def test_trace_survives_the_queue(tracing) -> None:
    """M4.10: между gateway и воркером Redis Stream.

    Без переноса контекста полем в задаче дерево спанов рвалось бы ровно
    посередине — приём файла в одном трейсе, обработка в другом.
    """
    with span("scan.accept"):
        carried = current_traceparent()

    assert carried is not None

    with continue_trace(carried, "scan.process"):
        pass

    accept, process = tracing.get_finished_spans()
    assert accept.context.trace_id == process.context.trace_id
    assert process.parent.span_id == accept.context.span_id


def test_foreign_traceparent_starts_its_own_trace(tracing) -> None:
    """Чужой контекст не должен склеивать наш скан с посторонним трейсом."""
    with span("scan.accept"):
        ours = current_traceparent()

    with continue_trace("00-" + "f" * 32 + "-" + "e" * 16 + "-01", "scan.process"):
        pass

    accept, process = tracing.get_finished_spans()
    assert ours is not None
    # Контекст формально годный, поэтому он принимается — но это ЧУЖОЙ трейс,
    # и с нашим он не сливается.
    assert process.context.trace_id != accept.context.trace_id


def test_logs_carry_trace_ids_when_tracing_is_on(tracing) -> None:
    """M4.13: без этого из спана в Tempo не перейти в логи в Loki."""
    record = logging.LogRecord("t", logging.INFO, "", 0, "сообщение", None, None)

    with span("scan.process"):
        ContextFilter().filter(record)

    assert len(record.trace_id) == 32
    assert len(record.span_id) == 16
    assert int(record.trace_id, 16) != 0


# --- метки HTTP-метрик ---------------------------------------------------


def test_route_label_uses_template_not_path() -> None:
    """Сырой путь дал бы по ряду метрик на каждый скан.

    `/v1/scan/{scan_id}` — один ряд; `/v1/scan/8f3a…` — столько рядов, сколько
    файлов прошло через сервис.
    """
    from types import SimpleNamespace

    request = SimpleNamespace(scope={"route": SimpleNamespace(path="/v1/scan/{scan_id}")})
    assert route_label(request) == "/v1/scan/{scan_id}"


def test_unmatched_route_collapses() -> None:
    """Перебор несуществующих адресов не должен раздувать Prometheus."""
    from types import SimpleNamespace

    assert route_label(SimpleNamespace(scope={})) == "unmatched"
