from __future__ import annotations

from vscommon.config import CommonSettings


class WorkerSettings(CommonSettings):
    service_name: str = "worker"
    consumer_name: str = "worker-1"
    concurrency: int = 4

    callbacks_stream: str = "scan.callbacks"
    callbacks_group: str = "notifiers"
    """Очередь доставки. Отправляет notifier, воркер только ставит задание."""

    results_stream: str = "scan.results"
    results_group: str = "writers"
    """Поток истории. Читает его Result Writer, воркер только публикует."""

    worker_mode: str = "fast"
    """`fast` — горячий путь, `deep` — углублённая проверка из своей очереди.

    Один образ, две роли: разделение по сервисам, а не по сборкам.
    """

    deep_enabled: bool = True
    """Отправлять ли файлы на углублённую проверку."""

    deep_sample_rate: float = 0.0
    """Доля чистых файлов, уходящих на углублённую проверку.

    Нужна не для защиты конкретного файла, а чтобы измерить пропуски: без
    выборки мы знаем только то, что нашли, и ничего — о том, что упустили.
    """

    work_dir: str = "/dev/shm/vulnscan"
    """tmpfs: недоверенные файлы не должны оседать на диске."""

    clamd_host: str = "clamd"
    clamd_port: int = 3310
    clamd_enabled: bool = True

    yara_rules_dir: str = "/app/rules/yara"
    yara_enabled: bool = True

    reload_interval_s: float = 30.0
    """Как часто проверять правила и веса на изменение.

    Задаёт окно, в течение которого воркеры могут работать на разных версиях
    правил. Уменьшать имеет смысл вместе с канареечной выкаткой (M7.2).
    """

    callback_timeout_s: float = 5.0
    callback_retries: int = 3

    heartbeat_ttl_s: int = 30
    """Отметка «задача в работе». Исчезла — владелец мёртв."""

    reclaim_interval_s: float = 15.0
    reclaim_min_idle_s: float = 30.0
    """Нижняя граница простоя: защита от подхвата только что выданной задачи."""

    reclaim_batch: int = 64
    max_deliveries: int = 3
    """Больше этого числа доставок — задача признаётся неперевариваемой."""

    max_parser_crashes: int = 1
    """Сколько жёстких обрывов внутри разбора терпим, прежде чем закрыть файл."""

    attempt_ttl_s: int = 3600
    """Время жизни отметки о попытке в журнале."""


settings = WorkerSettings()
