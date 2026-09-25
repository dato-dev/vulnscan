"""Бот: принимает вложение, отдаёт обезвреженную копию или отказ.

Пользователю не показываются ни коды признаков, ни имена сигнатур — только
исход. Подробности видит сервис, не отправитель.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

from vscommon.logging import log_context, setup_logging
from vscommon.metrics import metrics, setup_metrics
from vscommon.metrics import serve as serve_metrics
from vscommon.telemetry import setup_tracing, shutdown_tracing, span
from vulnscan_client import resolve_ca_file

from . import wording
from .config import settings
from .delivery import DeliveryLedger
from .scanner import ScannerClient, ScanOutcome
from .telegram import TelegramClient, TelegramError
from .webhook import build_app

logger = logging.getLogger(__name__)


class Bot:
    def __init__(self) -> None:
        self._tg = TelegramClient()
        self._scanner = ScannerClient()
        self._deliveries = DeliveryLedger()
        self._offset = 0
        self._tasks: set[asyncio.Task[None]] = set()
        self._stopping = asyncio.Event()

    async def run(self) -> None:
        logger.info("бот запущен", extra={"scanner": settings.scanner_url})
        backoff = 1.0

        while not self._stopping.is_set():
            try:
                updates = await self._tg.get_updates(self._offset)
            except TelegramError as exc:
                if exc.bad_token:
                    # Само не починится: без traceback, одной понятной строкой.
                    logger.error(
                        "Telegram не принял токен — проверьте TELEGRAM_TOKEN "
                        "и перезапустите контейнер"
                    )
                    return
                logger.warning("Telegram вернул ошибку", extra={"reason": str(exc)})
                backoff = await self._back_off(backoff)
                continue
            except Exception:
                logger.exception("не удалось получить обновления")
                backoff = await self._back_off(backoff)
                continue

            backoff = 1.0

            for update in updates:
                self._offset = update["update_id"] + 1
                try:
                    await self._handle(update.get("message") or {})
                except Exception:
                    logger.exception("ошибка обработки сообщения")

    @staticmethod
    async def _back_off(current: float) -> float:
        """Растущая пауза: сбоящий Telegram не должен заливать логи."""
        await asyncio.sleep(current)
        return min(current * 2, 60.0)

    async def _handle(self, message: dict) -> None:
        chat_id = (message.get("chat") or {}).get("id")
        if chat_id is None:
            return

        attachment = _attachment_of(message)
        if attachment is None:
            await self._tg.send_message(chat_id, wording.GREETING)
            return

        file_id, filename, mime = attachment
        with log_context(chat=chat_id):
            downloaded = await self._tg.download(file_id)
            if downloaded is None:
                await self._tg.send_message(chat_id, wording.TOO_BIG.format(settings.max_file_mb))
                return

            content, telegram_name = downloaded
            logger.info("файл принят", extra={"size": len(content), "ext": _ext(filename)})

            name = filename or telegram_name
            # Корень трейса: бот — начало цепочки, дальше контекст едет через
            # gateway и очередь. Имя файла в атрибуты не идёт, только расширение.
            with span("bot.submit", size=len(content), ext=_ext(name) or "none"):
                outcome = await self._scanner.scan(content, name, mime)

            if not outcome.pending:
                await self._reply(chat_id, outcome, name)
                if outcome.scan_id:
                    # Углублённая проверка может уточнить и синхронный ответ.
                    self._deliveries.register(outcome.scan_id, chat_id, name)
                    self._deliveries.claim(outcome.scan_id)
                    self._deliveries.record_verdict(outcome.scan_id, outcome.verdict)
                return

            # Сканер не уложился в синхронный ответ. Регистрируем ожидание и
            # запускаем опрос подстраховкой: вебхук может не дойти.
            self._deliveries.register(outcome.scan_id, chat_id, name)
            self._spawn(self._poll_backstop(outcome.scan_id))

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def on_callback(self, result) -> None:
        """Результат пришёл вебхуком."""
        outcome = self._scanner.outcome_of(result.model_dump(mode="json"))
        if result.deep:
            await self._handle_deep(result.parent_scan_id, outcome)
            return
        await self._deliver(result.scan_id, outcome, source="вебхук")

    async def _handle_deep(self, parent_scan_id: str, outcome: ScanOutcome) -> None:
        """Второй вердикт: беспокоим человека, только если стало хуже.

        У углублённого результата свой идентификатор, поэтому искать надо по
        родительскому — иначе он выглядит как ответ на неизвестный скан и
        молча теряется.
        """
        if not parent_scan_id:
            return

        answered = self._deliveries.answered(parent_scan_id)
        if answered is None:
            logger.debug("углублённый вердикт по забытому скану, пропущен")
            return

        if not wording.got_worse(answered.verdict, outcome.verdict):
            logger.info(
                "углублённая проверка не ухудшила вердикт, человека не беспокоим",
                extra={"было": answered.verdict, "стало": outcome.verdict},
            )
            return

        claimed = self._deliveries.claim_followup(parent_scan_id)
        if not claimed:
            logger.info("уточнение уже отправлено, повтор пропущен")
            return

        text = (
            wording.BLOCKED_AFTER_DEEP
            if outcome.verdict == "malicious"
            else wording.WORSE_AFTER_DEEP.format(reasons=wording.describe(outcome.reasons))
        )
        logger.warning(
            "углублённая проверка ухудшила вердикт, предупреждаем",
            extra={"было": answered.verdict, "стало": outcome.verdict},
        )
        for pending in claimed:
            await self._tg.send_message(pending.chat_id, text)

    async def _poll_backstop(self, scan_id: str) -> None:
        """Опрос на случай, если вебхук не дошёл."""
        outcome = await self._scanner.await_result(scan_id)
        if outcome is None:
            for pending in self._deliveries.claim(scan_id):
                await self._tg.send_message(pending.chat_id, wording.UNAVAILABLE)
            return
        await self._deliver(scan_id, outcome, source="опрос")

    async def _deliver(self, scan_id: str, outcome: ScanOutcome, source: str) -> None:
        """Отвечает пользователю ровно один раз.

        Право ответить забирается атомарно: повторный вебхук и завершившийся
        опрос приходят на один и тот же скан, и второй ответ пользователю не
        нужен.
        """
        waiters = self._deliveries.claim(scan_id)
        if not waiters:
            logger.info(
                "ответ уже отправлен, повтор пропущен", extra={"scan_id": scan_id, "source": source}
            )
            return

        with log_context(scan_id=scan_id):
            logger.info("результат получен", extra={"source": source, "ждущих": len(waiters)})
            # Ждущих может быть несколько: один файл, присланный дважды,
            # получает от сервиса общий идентификатор.
            for pending in waiters:
                await self._reply(pending.chat_id, outcome, pending.filename)
                metrics().deliveries.labels(source=source, verdict=outcome.verdict).inc()
            # Запоминаем выданный вердикт: с ним сравнится углублённый.
            self._deliveries.record_verdict(scan_id, outcome.verdict)

    async def _reply(self, chat_id: int, outcome: ScanOutcome, filename: str) -> None:
        with log_context(scan_id=outcome.scan_id or "-"):
            if not outcome.available:
                # Fail-closed и на стороне бота: непроверенный файл не проходит.
                await self._tg.send_message(chat_id, wording.UNAVAILABLE)
                return

            if outcome.shadow and outcome.verdict == "malicious":
                # Считаем, но не действуем: смысл теневого режима в том, чтобы
                # измерить цену блокировок, не заплатив её.
                logger.warning(
                    "теневой режим: заблокировали бы, но пропускаем",
                    extra={"score": outcome.score, "codes": ",".join(outcome.reasons or [])},
                )

            if outcome.blocking:
                # Что именно нашли — не раскрываем: это подсказка для того,
                # кто подбирает обход.
                logger.info("файл заблокирован", extra={"score": outcome.score})
                await self._tg.send_message(chat_id, wording.BLOCKED)
                return

            if outcome.verdict == "encrypted":
                await self._tg.send_message(chat_id, wording.ENCRYPTED)
                return

            if outcome.verdict == "unsupported":
                await self._tg.send_message(chat_id, wording.UNSUPPORTED)
                return

            if not outcome.deliverable:
                await self._tg.send_message(chat_id, wording.UNAVAILABLE)
                return

            clean = await self._scanner.fetch_clean(outcome.clean_url or "")
            if clean is None:
                await self._tg.send_message(chat_id, wording.UNAVAILABLE)
                return

            caption = (
                wording.CLEAN_CAPTION
                if outcome.verdict == "clean"
                else wording.SUSPICIOUS_CAPTION.format(reasons=wording.describe(outcome.reasons))
            )
            await self._tg.send_document(
                chat_id, clean, _clean_name(filename, outcome.clean_suffix), caption
            )
            logger.info("копия отправлена", extra={"verdict": outcome.verdict})

    async def stop(self) -> None:
        self._stopping.set()
        for task in list(self._tasks):
            task.cancel()
        await self._tg.close()
        await self._scanner.close()


def _attachment_of(message: dict) -> tuple[str, str, str | None] | None:
    document = message.get("document")
    if document:
        return document["file_id"], document.get("file_name", "document"), document.get("mime_type")

    photos = message.get("photo")
    if photos:
        # Telegram отдаёт лесенку размеров; берём самый крупный.
        largest = max(photos, key=lambda p: p.get("file_size", 0))
        return largest["file_id"], "photo.jpg", "image/jpeg"
    return None


def _ext(filename: str | None) -> str:
    return ("." + filename.rsplit(".", 1)[-1]).lower() if filename and "." in filename else ""


def _clean_name(filename: str, suffix: str) -> str:
    """Имя копии.

    Расширение берётся от артефакта, а не от исходника: профиль CDR может
    сменить формат, а раньше картинки приходили вовсе без расширения.
    """
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename
    return f"{stem}-проверено{suffix or Path(filename).suffix}"


async def _serve_webhook(bot: Bot) -> None:
    """HTTP-приёмник коллбэков. Наружу порт не публикуется."""
    import uvicorn

    config = uvicorn.Config(
        build_app(bot.on_callback),
        host="0.0.0.0",
        port=settings.webhook_port,
        log_config=None,
        access_log=False,
    )
    await uvicorn.Server(config).serve()


async def amain() -> None:
    setup_logging(settings.service_name, settings.log_level, settings.log_format)
    setup_metrics(known_tenants=(settings.tenant,))
    setup_tracing(
        settings.service_name,
        enabled=settings.otel_enabled,
        endpoint=settings.otel_endpoint,
        sample_ratio=settings.otel_sample_ratio,
    )
    if settings.metrics_enabled:
        serve_metrics(settings.metrics_port)
    if not settings.telegram_token:
        logger.error("TELEGRAM_TOKEN не задан — бот не запускается")
        return
    try:
        resolve_ca_file(settings.scanner_ca_file)
    except ValueError as exc:
        # Одной строкой и до запуска: иначе это PermissionError из глубины
        # ssl, где не сказано ни какой файл, ни чего не хватает.
        logger.error("сертификат своего центра не годится", extra={"reason": str(exc)})
        return

    bot = Bot()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(bot.stop()))

    tasks = [asyncio.create_task(bot.run())]
    if settings.webhook_url:
        logger.info("приём коллбэков включён", extra={"port": settings.webhook_port})
        tasks.append(asyncio.create_task(_serve_webhook(bot)))
    else:
        logger.info("коллбэки не настроены, работаем опросом")

    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await bot.stop()
        shutdown_tracing()


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
