"""Конфигурация из переменных окружения. Единственный способ настройки."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class CommonSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    log_level: str = "INFO"
    log_format: str = "console"

    redis_url: str = "redis://redis:6379/0"
    jobs_stream: str = "scan.jobs"
    jobs_group: str = "scanners"
    deep_stream: str = "scan.deep"
    results_stream: str = "scan.results"
    results_group: str = "writers"
    """Поток истории. Пишут в него gateway и воркер, читает Result Writer."""

    dlq_stream: str = "scan.dlq"
    dlq_maxlen: int = 10_000

    storage_backend: str = "s3"
    s3_endpoint: str = "http://minio:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_region: str = "us-east-1"
    raw_bucket: str = "vulnscan-raw"
    clean_bucket: str = "vulnscan-clean"
    local_storage_dir: str = "/var/lib/vulnscan"

    verdict_ttl_s: int = 7 * 24 * 3600
    artifact_ttl_s: int = 24 * 3600
    dlq_status_ttl_s: int = 7 * 24 * 3600
    """Статус задачи из dead-letter живёт долго: его смотрит человек."""

    av_cache_ttl_s: int = 24 * 3600
    """AV-кэш самоинвалидируется версией баз; TTL только ограничивает память."""

    allowlist_ttl_days: int = 30
    """Срок записи в списке доверенных. Вечных записей быть не должно."""

    inflight_ttl_s: int = 300
    """Срок заявки на проверку файла. Должен покрывать самый долгий проход."""

    raw_retention_days: int = 1
    """Карантин: исходные файлы. Сутки — на разбор инцидента и не больше.

    Здесь лежат присланные пользователями документы со всеми их данными.
    """

    clean_retention_days: int = 1
    """Обезвреженные копии. Клиент забирает их сразу; хранение — на случай
    повторного запроса и разбора жалоб."""

    keep_malicious_samples: bool = False
    """Хранить ли вредоносные семплы дольше карантина.

    По умолчанию НЕТ. Соблазн собрать коллекцию понятен, но вредоносный PDF —
    это всё ещё чей-то документ с персональными данными, и хранить его дольше
    остальных нужно осознанно и с согласованной политикой, а не по умолчанию.
    """

    av_db_stale_after_h: float = 24.0
    """Сутки без обновления баз — предупреждение в /readyz."""

    av_db_expired_after_h: float = 7 * 24.0
    """Неделя — сервис объявляет себя неготовым.

    Проверка с сигнатурами такой давности — это не проверка. Тот же принцип,
    что и с недоступным clamd: молчаливый `clean` хуже честного отказа.
    """

    otel_enabled: bool = False
    """Трассировка. Выключена по умолчанию: без коллектора включать нечего."""

    otel_endpoint: str = ""
    """Полный адрес приёмника OTLP/HTTP, например http://collector:4318/v1/traces.

    Коллектор живёт во внутренней сети и сам выносит данные наружу: у воркера
    сетевого выхода нет, и телеметрия не повод его открывать.
    """

    otel_sample_ratio: float = 1.0
    """Доля трассируемых сканов. На проде снижается, на отладке — единица."""

    metrics_enabled: bool = True
    """Метрики Prometheus. Дёшевы и не требуют внешнего адреса."""

    metrics_port: int = 9100
    """Порт эндпоинта метрик для сервисов без своего HTTP (воркер, бот)."""

    known_tenants: str = ""
    """Список тенантов через запятую — только для меток метрик.

    Тенант приходит в теле запроса; без приведения к известному списку любой
    клиент мог бы наплодить рядов метрик, просто присылая новые значения.
    """

    hmac_secret: str = "change-me-in-production"
    """Ключ для подписи входящих запросов и исходящих коллбэков."""

    policy_file: str | None = None
    """JSON с переопределениями политик по тенантам."""

    weights_file: str | None = None
    """JSON с весами признаков. Переопределяет встроенные значения.

    Правка весов и порогов — это правка конфигурации, а не пересборка образа.
    """

    default_fail_mode: str = "suspicious"
    """fail-closed | suspicious | fail-open. Клиент это поле не переопределяет."""

    default_block_threshold: int = 80
    default_suspicious_threshold: int = 30
    default_cdr_profile: str = "standard"

    default_shadow_mode: bool = False
    """Проверять, но не действовать по вердикту. Только на время обкатки."""
