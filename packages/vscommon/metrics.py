"""Метрики Prometheus. Единственное место, где объявляются счётчики.

Как и с трассировкой: отсутствующий SDK выключает метрики, но не сервис.

Отдельная забота здесь — кардинальность. Метка, значение которой приходит
снаружи, — это способ положить Prometheus чужим запросом, поэтому в метки не
попадают ни `sha256`, ни `scan_id`, ни имя файла, а тенант приводится к
известному списку.
"""

from __future__ import annotations

import logging
from typing import Any, Final

logger = logging.getLogger(__name__)

try:  # pragma: no cover — обе ветки проверяются тестами
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
    from prometheus_client import start_http_server as _start_http_server
    from prometheus_client.exposition import CONTENT_TYPE_LATEST

    SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    SDK_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

OTHER_TENANT: Final = "other"
"""Метка для незнакомого тенанта.

Тенант приходит в теле запроса. Без приведения к списку известных любой клиент
мог бы создать сколько угодно рядов метрик, просто присылая новые значения.
"""

_known_tenants: set[str] = set()

CACHED_FULL: Final = "full"
CACHED_STRUCTURAL: Final = "structural"
CACHED_NONE: Final = "none"
"""Значения метки `cached` у `vs_verdict_duration_seconds`.

Было два значения, `true` и `false`, и означали они не то, что читалось. `true`
стояло на переиспользовании структурного кэша с повторным прогоном антивируса,
а полный кэш-хит — единственный случай, который слово «cached» описывает без
оговорок, — до метрики не доходил вовсе. То есть оба значения описывали разные
виды **непопадания** в кэш.

Три значения, потому что это три разные цены ответа: `full` — вердикт собран из
кэша целиком, `structural` — разбор переиспользован, антивирус прогнан заново,
`none` — полный проход.
"""


class _NoopMetric:
    """Интерфейс метрики без самой метрики."""

    def labels(self, *args: object, **kwargs: object) -> _NoopMetric:
        return self

    def inc(self, amount: float = 1.0) -> None:
        return None

    def observe(self, amount: float) -> None:
        return None

    def set(self, value: float) -> None:
        return None


def _counter(registry: Any, name: str, doc: str, labels: tuple[str, ...]) -> Any:
    if not SDK_AVAILABLE:
        return _NoopMetric()
    return Counter(name, doc, labels, registry=registry)


def _gauge(registry: Any, name: str, doc: str, labels: tuple[str, ...]) -> Any:
    if not SDK_AVAILABLE:
        return _NoopMetric()
    return Gauge(name, doc, labels, registry=registry)


def _histogram(
    registry: Any, name: str, doc: str, labels: tuple[str, ...], buckets: tuple[float, ...]
) -> Any:
    if not SDK_AVAILABLE:
        return _NoopMetric()
    return Histogram(name, doc, labels, buckets=buckets, registry=registry)


# Цель по времени до вердикта — p95 ≤ 0.7 с, поэтому корзины сгущены вокруг неё.
_VERDICT_BUCKETS: Final = (0.01, 0.05, 0.1, 0.25, 0.5, 0.7, 1.0, 2.0, 5.0, 10.0)
# Стадии измеряются миллисекундами: самая дешёвая — доли миллисекунды.
_STAGE_BUCKETS: Final = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0)
_HTTP_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
# Отставание истории меряется в секундах и минутах: сброс пачки идёт раз в
# две секунды, а всё, что больше минуты, — уже накопление в памяти.
_LAG_BUCKETS: Final = (0.5, 1.0, 2.0, 5.0, 15.0, 60.0, 300.0)
# Размер входа: от расписки в килобайт до предельных 16 МБ. Границы кратны
# двум, потому что время разбора растёт с размером не линейно, а ступенями —
# по числу объектов и страниц.
_SIZE_BUCKETS: Final = (
    16_384.0,
    65_536.0,
    262_144.0,
    1_048_576.0,
    4_194_304.0,
    8_388_608.0,
    16_777_216.0,
)
# Обращения к хранилищу: сеть, а не вычисление. Хвост длиннее, чем у HTTP, —
# заливка шестнадцати мегабайт в норме занимает секунды, и корзина, в которой
# она сливается с зависшим соединением, ничего не объясняет.
_STORAGE_BUCKETS: Final = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0)


class Metrics:
    """Набор метрик процесса. Создаётся один раз на старте."""

    def __init__(self, registry: Any = None) -> None:
        if SDK_AVAILABLE and registry is None:
            registry = CollectorRegistry()
        self.registry = registry

        self.scans = _counter(
            registry, "vs_scans_total", "Завершённые сканы", ("verdict", "tenant", "mode")
        )
        self.verdict_seconds = _histogram(
            registry,
            "vs_verdict_duration_seconds",
            "Время до вердикта целиком",
            ("profile", "cached"),
            _VERDICT_BUCKETS,
        )
        self.stage_seconds = _histogram(
            registry,
            "vs_stage_duration_seconds",
            "Длительность стадии конвейера",
            ("stage", "ok"),
            _STAGE_BUCKETS,
        )
        self.stage_failures = _counter(
            registry,
            "vs_stage_failures_total",
            "Отказы стадий",
            ("stage", "reason"),
        )
        self.cdr_seconds = _histogram(
            registry,
            "vs_cdr_duration_seconds",
            "Длительность пересборки",
            ("profile", "ok"),
            _STAGE_BUCKETS,
        )
        # M4.6: уровни кэша считаются раздельно — иначе не увидеть, что после
        # обновления баз проседает только антивирусный уровень.
        self.cache_lookups = _counter(
            registry,
            "vs_cache_lookups_total",
            "Обращения к кэшу по уровням",
            ("level", "outcome"),
        )
        self.queue_depth = _gauge(
            registry, "vs_queue_depth", "Необработанных задач в потоке", ("stream",)
        )
        self.dlq_size = _gauge(registry, "vs_dlq_size", "Размер очереди разбора", ())
        self.inflight = _gauge(registry, "vs_inflight_scans", "Сканов в работе", ())
        self.http_requests = _counter(
            registry,
            "vs_http_requests_total",
            "HTTP-запросы к gateway",
            ("method", "route", "status"),
        )
        self.http_seconds = _histogram(
            registry,
            "vs_http_duration_seconds",
            "Длительность HTTP-запроса",
            ("method", "route"),
            _HTTP_BUCKETS,
        )
        self.callbacks = _counter(
            registry, "vs_callbacks_total", "Отправленные коллбэки", ("outcome",)
        )
        self.deliveries = _counter(
            registry, "vs_bot_deliveries_total", "Ответы пользователю", ("source", "verdict")
        )
        self.rules_age = _gauge(
            registry, "vs_rules_age_seconds", "Возраст загруженной конфигурации", ("kind",)
        )
        # M10.3. Дальше — метрики на то, что деградирует молча: каждая заведена
        # под конкретный способ сломаться, который в логах виден одной строкой,
        # а снаружи не виден никак.

        # Правила не скомпилировались — остаются прежние. Это правильное
        # поведение (кривое правило не должно останавливать проверку) и ровно
        # поэтому незаметное: воркер продолжает работать на старом наборе.
        self.config_reloads = _counter(
            registry,
            "vs_config_reloads_total",
            "Попытки перезагрузить конфигурацию на живом сервисе",
            ("kind", "outcome"),
        )
        # Ноль правил — это работающая стадия, которая ничего не находит.
        # Отличить её от «файлы чистые» по вердиктам невозможно.
        self.rules_loaded = _gauge(
            registry, "vs_rules_loaded", "Загружено единиц конфигурации", ("kind",)
        )
        # M7.2. Выключенное вручную правило — временная мера, которая живёт
        # ровно до тех пор, пока её видно. По вердиктам она неотличима от
        # правила, которому не попадаются подходящие файлы.
        self.rules_disabled = _gauge(registry, "vs_rules_disabled", "Правил выключено вручную", ())
        # M14.5. Выгрузка копии в хранилище клиента. Без счётчика недоступный
        # приёмник неотличим от «файлов на проверку нет»: и там, и там ящик
        # пуст, а смотрит в него клиент, а не мы.
        self.copies_delivered = _counter(
            registry,
            "vs_deliveries_total",
            "Выгрузки обезвреженной копии в хранилище клиента",
            ("outcome",),
        )
        # M7.2. Канареечный набор работает вхолостую, поэтому по вердиктам его
        # не видно вовсе — только здесь. `candidate_only` это будущие ложные
        # срабатывания, `active_only` — детект, который выкатка потеряет.
        self.canary_runs = _counter(
            registry,
            "vs_rules_canary_total",
            "Прогоны набора-кандидата: совпал с действующим или разошёлся",
            ("outcome",),
        )
        # M10.11. Размер входа отдельно от времени: без него уехавший p95
        # неотличим от «стало приходить больше тяжёлых файлов». Метка profile
        # рядом, потому что растеризация зависит от размера сильнее прочих.
        self.input_bytes = _histogram(
            registry,
            "vs_input_bytes",
            "Размер принятого файла",
            ("profile",),
            _SIZE_BUCKETS,
        )
        # M10.2. Деградация как число, а не как поле в `/readyz`: ручку никто
        # не опрашивает регулярно, а деградированный режим — это состояние,
        # которое надо видеть на графике рядом с вердиктами. Ноль или единица
        # на компонент; ряд обязан существовать всегда, иначе «всё хорошо»
        # неотличимо от «никто не проверял».
        self.degraded = _gauge(
            registry, "vs_degraded", "Компонент работает в урезанном режиме", ("component",)
        )
        # Отставание истории: запись сделана, но ещё не в базе. Накопление в
        # памяти выглядит как работающий сервис — до перезапуска.
        self.history_lag = _histogram(
            registry,
            "vs_history_lag_seconds",
            "От завершения скана до записи в историю",
            (),
            _LAG_BUCKETS,
        )
        # Сброс пачки в базу — своей метрикой, а не меткой `stage="writer"` у
        # отказов стадий. Writer стадией не является, и чужая метка не просто
        # пачкала панель конвейера: на отказы стадий стоит алерт с разбивкой по
        # `stage`, и недоступная база поднимала «Стадия writer падает» с
        # описанием про вердикты — то есть уводила дежурного в конвейер.
        self.history_writes = _counter(
            registry,
            "vs_history_writes_total",
            "Сбросы пачки истории в базу",
            ("outcome",),
        )
        self.retention_runs = _counter(
            registry,
            "vs_retention_runs_total",
            "Проходы чистки истории",
            ("outcome",),
        )
        # M10.17. Дальше — то, что было видно только в логах: события редкие,
        # каждое пишется одной строкой, и «строк стало больше» замечает лишь
        # тот, кто в этот момент читает логи.

        # Подхват задач мёртвого воркера. Единственный ранний признак цикла
        # «воркер падает на файле — задача перевыдаётся другому воркеру».
        # `vs_dlq_size` показывает только остаток и только после того, как лимит
        # доставок исчерпан, то есть уже post factum.
        self.reclaimed_jobs = _counter(
            registry,
            "vs_jobs_reclaimed_total",
            "Задачи, подхваченные из pending-списка группы",
            ("outcome",),
        )
        # Отправка на углублённую проверку. Метка `reason` отвечает, чем занята
        # дорогая роль: разбором серой зоны, повторами неразобранного или
        # выборкой чистых.
        self.deep_scans = _counter(
            registry,
            "vs_deep_scans_total",
            "Файлы, отправленные на углублённую проверку",
            ("reason",),
        )
        # Ради чего всё это и делается. Выборка чистых заведена «измеряем
        # пропуски», но само измерение наружу не выходило: файл проверялся
        # дважды, а сравнение двух вердиктов не оседало нигде. `stricter` —
        # пропуск быстрой проверки, `looser` — её ложное срабатывание.
        self.deep_changes = _counter(
            registry,
            "vs_deep_verdict_changes_total",
            "Расхождение углублённой проверки с быстрой",
            ("change",),
        )
        # Отказы на входе по причинам. В `vs_http_requests_total` все они —
        # один и тот же `429`, а действия оператора у них разные: поднять
        # предел частоты, поднять параллелизм или объяснить клиенту квоту.
        self.rejections = _counter(
            registry,
            "vs_rejections_total",
            "Запросы, отвергнутые до обработки",
            ("reason",),
        )
        # Хранилище: единственный сетевой вызов в горячем пути, который не было
        # видно ни в метриках, ни в трейсах. Медленный S3 без него проявляется
        # размазанным ростом времени до вердикта без указания на причину.
        self.storage_seconds = _histogram(
            registry,
            "vs_storage_duration_seconds",
            "Длительность обращения к объектному хранилищу",
            ("op", "ok"),
            _STORAGE_BUCKETS,
        )
        # Теневой режим считался только в Redis и был виден лишь тому, кто
        # спросит через админский API. Доля «заблокировали бы» — величина, по
        # которой принимают решение включить блокировки, и её место на графике
        # рядом с вердиктами.
        self.shadow_records = _counter(
            registry,
            "vs_shadow_records_total",
            "Сканы в теневом режиме: заблокировали бы или нет",
            ("tenant", "would_block"),
        )

    def observe_stage(self, stage: str, elapsed_s: float, ok: bool) -> None:
        self.stage_seconds.labels(stage=stage, ok=str(ok).lower()).observe(elapsed_s)

    def report_degraded(self, component: str, degraded: bool) -> None:
        """Ставит признак урезанного режима.

        Отдельным методом, а не `.labels(...).set(...)` по месту: вызовов
        несколько, и каждый — это выбор «единица или ноль», в котором легко
        ошибиться знаком. Ноль тоже выставляется всегда: ряд, появляющийся
        только при поломке, не отличить от неработающего экспорта.
        """
        self.degraded.labels(component=component).set(1.0 if degraded else 0.0)

    def observe_cache(self, level: str, hit: bool) -> None:
        self.cache_lookups.labels(level=level, outcome="hit" if hit else "miss").inc()


_metrics: Metrics | None = None


def setup_metrics(known_tenants: tuple[str, ...] = ()) -> Metrics:
    """Создаёт набор метрик процесса. Вызывается один раз на старте."""
    global _metrics, _known_tenants
    _known_tenants = set(known_tenants)
    _metrics = Metrics()
    if not SDK_AVAILABLE:
        logger.warning("SDK Prometheus недоступен, метрики выключены")
    return _metrics


def metrics() -> Metrics:
    """Текущий набор. До `setup_metrics` — пустышки, чтобы вызовы были безопасны."""
    global _metrics
    if _metrics is None:
        _metrics = Metrics()
    return _metrics


def metrics_enabled() -> bool:
    return SDK_AVAILABLE and _metrics is not None and _metrics.registry is not None


def tenant_label(tenant: str | None) -> str:
    """Приводит тенанта к известному списку. Незнакомый схлопывается в `other`."""
    if not tenant:
        return "default"
    return tenant if tenant in _known_tenants else OTHER_TENANT


def render() -> tuple[bytes, str]:
    """Тело ответа `/metrics` и его content-type."""
    current = metrics()
    if not SDK_AVAILABLE or current.registry is None:
        return b"# metrics disabled\n", CONTENT_TYPE_LATEST
    payload: bytes = generate_latest(current.registry)
    return payload, CONTENT_TYPE_LATEST


def serve(port: int) -> bool:
    """Поднимает эндпоинт для тех, кто не является HTTP-сервисом.

    Воркер — цикл-потребитель, своей ручки у него нет, а pushgateway здесь не
    подходит: метрики не событийные, их нужно скрейпить с каждой реплики.
    Эндпоинт слушает во внутренней сети — наружу он не выставляется.
    """
    current = metrics()
    if not SDK_AVAILABLE or current.registry is None:
        return False
    try:
        _start_http_server(port, registry=current.registry)
    except OSError:
        logger.exception("не удалось поднять эндпоинт метрик", extra={"port": port})
        return False
    logger.info("эндпоинт метрик поднят", extra={"port": port})
    return True
