"""S2: ClamAV через резидентный clamd. Спавнить clamscan на файл нельзя."""

from __future__ import annotations

import logging
import threading
from typing import Any, Protocol

from ..config import settings
from .base import ScanContext, Stage

logger = logging.getLogger(__name__)


class ClamdClient(Protocol):
    def instream(self, buff: Any) -> dict[str, Any]: ...

    def version(self) -> str: ...


def _default_client() -> ClamdClient:
    import clamd

    return clamd.ClamdNetworkSocket(host=settings.clamd_host, port=settings.clamd_port)


class ClamavStage(Stage):
    """Клиент clamd создаётся на каждый поток пула.

    `ClamdNetworkSocket` хранит сокет полем экземпляра: `instream` открывает
    соединение, пишет в него и закрывает. Два потока на одном клиенте
    перезаписывают друг другу `clamd_socket` — файл уходит в чужое соединение,
    и вердикт одного файла достаётся другому. Для сканера это худший из
    возможных отказов, поэтому общего клиента здесь нет.

    Блокировка не подходит: `clamav` — самая долгая стадия (20-300 мс), её
    сериализация обнулила бы конкурентность воркера. Сам clamd рассчитан на
    параллельные соединения — это его штатный режим работы.
    """

    name = "clamav"

    def __init__(self, factory: Any = None) -> None:
        self._factory = factory or _default_client
        self._local = threading.local()
        self._version = "unavailable"
        self._version_lock = threading.Lock()

    @property
    def engine_version(self) -> str:
        return self._version

    def _client(self) -> ClamdClient:
        client: ClamdClient | None = getattr(self._local, "client", None)
        if client is not None:
            return client

        client = self._factory()
        self._local.client = client
        self._remember_version(client)
        return client

    def _remember_version(self, client: ClamdClient) -> None:
        """Запоминает версию баз при первом подключении потока."""
        if self._version != "unavailable":
            return
        with self._version_lock:
            if self._version != "unavailable":
                return
            self._version = str(client.version()).strip()
            logger.info("clamd подключён", extra={"stage": self.name, "version": self._version})

    def refresh_version(self) -> bool:
        """Перечитывает версию баз. Возвращает, изменилась ли она.

        Обязательна для регулярных обновлений. Версия входит в ключ AV-кэша, и
        пока она не менялась, кэш считает прежние результаты действительными.
        Раньше она защёлкивалась на первом подключении и жила до перезапуска
        процесса: freshclam обновлял базы, clamd их подхватывал, а воркер ещё
        сутки (до истечения TTL) отдавал вердикты, снятые старыми сигнатурами.
        Новая сигнатура при этом просто не применялась к уже виденным файлам.
        """
        if not settings.clamd_enabled:
            return False
        try:
            current = str(self._client().version()).strip()
        except Exception:
            # Недоступность clamd — забота стадии, а не этой проверки. Здесь
            # молчим: иначе каждые 30 секунд в лог падал бы одинаковый отказ.
            logger.debug("не удалось перечитать версию баз", exc_info=True)
            return False

        with self._version_lock:
            if current == self._version or not current:
                return False
            previous = self._version
            self._version = current
        logger.info(
            "базы антивируса обновились",
            extra={"stage": self.name, "было": previous, "стало": current},
        )
        return True

    def warmup(self) -> None:
        """Устанавливает соединение заранее, чтобы узнать версию баз.

        Клиент потоко-локальный, поэтому созданный здесь достанется потоку
        прогрева и переиспользован не будет. Нужен не он, а версия: она
        хранится на стадии и входит в ключ AV-кэша.
        """
        if not settings.clamd_enabled:
            return
        try:
            self._client()
        except Exception:
            logger.warning("clamd недоступен при прогреве", extra={"stage": self.name})

    def run(self, ctx: ScanContext) -> None:
        if not settings.clamd_enabled:
            ctx.engines["clamav"] = {"status": "disabled"}
            return

        client = self._client()
        with ctx.path.open("rb") as handle:
            # INSTREAM: файл уходит в демон потоком, на диск демона не пишется.
            response = client.instream(handle)

        status, signature = response.get("stream", ("ERROR", None))
        ctx.engines["clamav"] = {"status": status, "version": self._version}

        if status == "FOUND":
            ctx.add(self.name, "AV_SIGNATURE_MATCH", str(signature))
            logger.info(
                "совпадение сигнатуры AV", extra={"stage": self.name, "sig": str(signature)}
            )
        elif status == "ERROR":
            ctx.add(self.name, "AV_ERROR", str(signature))
