"""Точка входа: long polling Telegram, без входящих портов."""

from __future__ import annotations

import asyncio
import logging
import sys

from vscommon.logging import setup_logging
from vulnscan_client import VulnscanClient, resolve_ca_file

from .bot import FeedbackBot
from .cards import S3Cards
from .config import settings
from .form import Forms
from .telegram import Telegram, TelegramError

logger = logging.getLogger(__name__)

REQUIRED = ("telegram_token", "scanner_url", "scanner_secret", "s3_bucket")


def _missing() -> list[str]:
    missing = []
    for name in REQUIRED:
        value = getattr(settings, name)
        raw = value.get_secret_value() if hasattr(value, "get_secret_value") else value
        if not raw:
            missing.append(name.upper())
    return missing


async def run() -> None:
    telegram = Telegram(
        settings.telegram_api,
        settings.telegram_token.get_secret_value(),
        settings.telegram_proxy.get_secret_value() if settings.telegram_proxy else None,
        settings.poll_timeout_s,
    )
    scanner = VulnscanClient(
        base_url=settings.scanner_url,
        key_id=settings.scanner_key_id,
        secret=settings.scanner_secret.get_secret_value(),
        wait_ms=settings.wait_ms,
        verify=resolve_ca_file(settings.scanner_ca_file),
    )
    cards = S3Cards(
        endpoint=settings.s3_endpoint,
        region=settings.s3_region,
        bucket=settings.s3_bucket,
        prefix=settings.s3_prefix,
        access_key_id=settings.s3_access_key_id.get_secret_value(),
        secret_access_key=settings.s3_secret_access_key.get_secret_value(),
    )
    bot = FeedbackBot(
        telegram,
        scanner,
        cards,
        Forms(settings.form_ttl_s),
        max_bytes=settings.max_file_mb * 1024 * 1024,
        scan_timeout_s=settings.scan_timeout_s,
        poll_interval_s=settings.poll_interval_s,
        parallel=settings.max_parallel_checks,
    )
    logger.info(
        "бот формы запущен",
        # Есть ли прокси — да; какой — нет: в адресе прокси логин и пароль.
        extra={"scanner": settings.scanner_url, "proxy": settings.telegram_proxy is not None},
    )

    offset = 0
    try:
        while True:
            try:
                updates = await telegram.updates(offset)
            except TelegramError as exc:
                logger.warning("Telegram не ответил", extra={"reason": str(exc)[:200]})
                await asyncio.sleep(5)
                continue
            for update in updates:
                offset = max(offset, int(update["update_id"]) + 1)
                await bot.handle(update)
    finally:
        await bot.wait_idle()
        await scanner.close()
        await telegram.close()


def main() -> int:
    setup_logging(settings.service_name, settings.log_level, settings.log_format)
    missing = _missing()
    if missing:
        logger.error("не заданы обязательные переменные", extra={"missing": missing})
        return 2
    try:
        resolve_ca_file(settings.scanner_ca_file)
    except ValueError as exc:
        # До запуска цикла и одной строкой: иначе это PermissionError из
        # глубины ssl, где не сказано ни какой файл, ни чего не хватает.
        logger.error("сертификат своего центра не годится", extra={"reason": str(exc)})
        return 2
    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
