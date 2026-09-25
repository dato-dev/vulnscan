from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class BotSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    service_name: str = "bot"
    log_level: str = "INFO"
    log_format: str = "console"

    telegram_token: str = ""
    """Берётся только из окружения. В репозиторий токен не попадает."""

    telegram_api: str = "https://api.telegram.org"
    scanner_url: str = "http://gateway:8080"
    tenant: str = "telegram-bot"

    otel_enabled: bool = False
    """Трассировка. Бот — начало цепочки, его спан становится корнем трейса."""

    otel_endpoint: str = ""
    otel_sample_ratio: float = 1.0

    metrics_enabled: bool = True
    metrics_port: int = 9102
    """Свой порт: бот не HTTP-сервис в общем случае, ручки для скрейпа нет."""

    key_id: str = "telegram-bot-1"
    """Идентификатор ключа доступа. Должен совпадать с записью в keys.json."""

    hmac_secret: str = "change-me-in-production"
    """Общий со сканером ключ: им подписаны коллбэки."""

    webhook_url: str = ""
    """Адрес, на который сканер шлёт результат. Пусто — работаем только опросом.

    Публичный адрес не нужен: сканер обращается по внутренней сети.
    """

    webhook_port: int = 8090

    wait_ms: int = 2000
    """Сколько ждём синхронного ответа сканера, прежде чем перейти к опросу."""

    poll_timeout_s: int = 25
    """Long polling Telegram: держим соединение, а не долбим getUpdates."""

    scan_timeout_s: float = 120.0
    request_timeout_s: float = 60.0

    max_file_mb: int = 20
    """Предел скачивания через Bot API. Больше — только локальный API-сервер."""


settings = BotSettings()
