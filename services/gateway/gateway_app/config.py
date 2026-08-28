from __future__ import annotations

from vscommon.config import CommonSettings


class GatewaySettings(CommonSettings):
    service_name: str = "gateway"
    host: str = "0.0.0.0"
    port: int = 8080

    config_reload_interval_s: float = 30.0
    """Как часто перечитывать ключи и политики на живом сервисе."""

    keys_file: str | None = None
    """JSON с ключами доступа. Тенант выводится из ключа, а не из заголовка."""

    dev_tenant: str = "default"
    """Тенант для запросов без подписи. Действует только при
    `REQUIRE_SIGNATURE=false`, то есть в разработке."""

    require_signature: bool = True
    """В dev можно выключить HMAC-проверку входящих запросов."""

    default_wait_ms: int = 400
    engine_version: str = "unknown"
    """Версия баз clamd; воркер публикует её в Redis, gateway читает для ключа кэша."""


settings = GatewaySettings()
