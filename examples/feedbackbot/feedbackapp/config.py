"""Настройки бота-формы. Только из окружения, секреты — `SecretStr`."""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class FeedbackSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    service_name: str = "feedbackbot"
    log_level: str = "INFO"
    log_format: str = "json"

    telegram_token: SecretStr = SecretStr("")
    telegram_api: str = "https://api.telegram.org"
    telegram_proxy: SecretStr | None = None
    """Прокси только для Telegram. Задаётся здесь, а не `HTTPS_PROXY`: через
    переменную окружения туда же ушли бы и запросы к сканеру с подписями.
    `SecretStr`, потому что в адресе прокси обычно логин и пароль."""

    poll_timeout_s: int = 25
    """Long polling: сервер бота ничего не слушает снаружи — ни вебхука
    Telegram, ни коллбэка сканера."""

    scanner_url: str = ""
    """Адрес сканера за Gateway API, например `https://scan.example.ru`."""

    scanner_key_id: str = "feedback-bot-1"
    scanner_secret: SecretStr = SecretStr("")
    scanner_ca_file: str = ""
    """Сертификат своего центра, если TLS на входе выпущен не публичным."""

    wait_ms: int = 5000
    scan_timeout_s: float = 180.0
    """Сколько ждать вердикта, опрашивая сканер, прежде чем извиниться."""

    poll_interval_s: float = 2.0

    max_file_mb: int = 20
    """Предел скачивания через Bot API."""

    max_parallel_checks: int = 4
    """Сколько файлов одновременно в работе. Файл целиком лежит в памяти бота."""

    form_ttl_s: int = 3600
    """Сколько помнить начатую форму. ФИО живёт в памяти только это время."""

    s3_endpoint: str = "https://storage.yandexcloud.net"
    s3_region: str = "ru-central1"
    s3_bucket: str = ""
    s3_prefix: str = "cards/"
    s3_access_key_id: SecretStr = SecretStr("")
    s3_secret_access_key: SecretStr = SecretStr("")


settings = FeedbackSettings()
