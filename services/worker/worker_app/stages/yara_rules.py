"""S3: собственные YARA-правила поверх сигнатурного детекта."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from pathlib import Path
from typing import Any

from vscommon.limits import STAGE_TIMEOUT_S
from vscommon.metrics import metrics

from ..config import settings
from .base import ScanContext, Stage

logger = logging.getLogger(__name__)

WEIGHT_TAGS = ("critical", "high", "medium", "low")
"""Тег правила задаёт вес через ключ `YARA:<тег>` в таблице весов."""

DEFAULT_TAG = "medium"


class YaraStage(Stage):
    """Скомпилированные правила общие, вызовы `match` сериализованы.

    Гарантий потокобезопасности `yara.Rules` между версиями yara-python нет, а
    полагаться на недокументированное поведение в стадии, куда приходит
    недоверенный файл, не стоит. Экземпляр на поток здесь не выбран
    сознательно: правила компилируются заново в каждом потоке, память
    дублируется, а горячая перезагрузка (M2.4) превращается из атомарной
    подмены одной ссылки в согласование N копий.

    Сериализация обходится дешевле, чем у `clamav`: стадия занимает 5-50 мс
    против 20-300 мс у антивируса.
    """

    name = "yara"

    def __init__(self, rules: Any = None) -> None:
        self._rules = rules
        self._compiled = rules is not None
        self._fingerprint: str | None = None
        self._stat_signature: tuple[tuple[str, int, int], ...] | None = None
        self._lock = threading.Lock()

    @property
    def rules_fingerprint(self) -> str:
        """Отпечаток набора правил: входит в ключ структурного кэша.

        Считается по содержимому файлов, а не по скомпилированному объекту, —
        поэтому не зависит от того, дошло ли дело до компиляции, и меняется
        ровно тогда, когда меняются сами правила.
        """
        if self._fingerprint is None:
            self._fingerprint = self._content_fingerprint()
        return self._fingerprint

    def _rule_files(self) -> list[Path]:
        return sorted(Path(settings.yara_rules_dir).glob("*.yar"))

    def _content_fingerprint(self) -> str:
        digest = hashlib.sha256()
        for path in self._rule_files():
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
        return digest.hexdigest()[:12]

    def _current_stat_signature(self) -> tuple[tuple[str, int, int], ...]:
        """Дешёвая проверка «что-то трогали»: без чтения содержимого."""
        signature = []
        for path in self._rule_files():
            info = path.stat()
            signature.append((path.name, info.st_size, int(info.st_mtime_ns)))
        return tuple(signature)

    def reload_if_changed(self) -> bool:
        """Подхватывает изменённые правила без остановки воркера.

        Возвращает True, только если правила действительно заменены.

        Компиляция идёт ВНЕ блокировки — она может занять секунды, а под локом
        в это время стояли бы все идущие проверки. Под локом только подмена
        ссылки. Если новые правила не компилируются, остаются старые: кривое
        правило не должно останавливать проверку файлов.
        """
        stat_signature = self._current_stat_signature()
        if stat_signature == self._stat_signature:
            return False

        fingerprint = self._content_fingerprint()
        if fingerprint == self._fingerprint:
            # Файл перезаписали тем же содержимым — компилировать нечего.
            self._stat_signature = stat_signature
            return False

        try:
            compiled = self._compile()
        except Exception:
            logger.exception("новые правила YARA не компилируются, оставляю прежние")
            # Снаружи это выглядит как работающий воркер, и так оно и есть —
            # на старом наборе. Счётчик отличает «правила не менялись» от
            # «правила меняли, и не вышло».
            metrics().config_reloads.labels(kind="yara", outcome="failed").inc()
            # Отметку не двигаем: попробуем ещё раз, когда файлы поправят.
            return False

        with self._lock:
            self._rules = compiled
            self._compiled = True
            self._fingerprint = fingerprint
            self._stat_signature = stat_signature

        logger.info("правила YARA перезагружены", extra={"fingerprint": fingerprint})
        metrics().config_reloads.labels(kind="yara", outcome="applied").inc()
        self._report_rules()
        return True

    def _ensure_rules(self) -> Any:
        if self._compiled:
            return self._rules

        with self._lock:
            if self._compiled:
                return self._rules
            self._compiled = True
            self._rules = self._compile()
            # Обе отметки ставятся вместе: без отпечатка содержимого первая
            # же проверка после touch перекомпилировала бы правила впустую.
            self._stat_signature = self._current_stat_signature()
            self._fingerprint = self._content_fingerprint()
        self._report_rules()
        return self._rules

    def _compile(self) -> Any:
        import yara

        sources = {p.stem: str(p) for p in self._rule_files()}
        if not sources:
            logger.warning("правила YARA не найдены", extra={"dir": settings.yara_rules_dir})
            return None

        compiled = yara.compile(filepaths=sources)
        logger.info("правила YARA скомпилированы", extra={"count": len(sources)})
        return compiled

    def _report_rules(self) -> None:
        """Сколько правил в работе и насколько они свежие.

        Ноль — это работающая стадия, которая ничего не находит: по вердиктам
        она неотличима от стадии, которой попадаются только чистые файлы.
        Возраст рядом, потому что правила, не обновлявшиеся месяц, — тоже
        деградация, просто медленная.
        """
        files = self._rule_files()
        metrics().rules_loaded.labels(kind="yara").set(len(files))
        if files:
            newest = max(path.stat().st_mtime for path in files)
            metrics().rules_age.labels(kind="yara").set(max(0.0, time.time() - newest))

    def run(self, ctx: ScanContext) -> None:
        if not settings.yara_enabled:
            ctx.engines["yara"] = {"status": "disabled"}
            return

        rules = self._ensure_rules()
        if rules is None:
            ctx.engines["yara"] = {"status": "no_rules"}
            return

        with self._lock:
            matches = rules.match(str(ctx.path), timeout=int(STAGE_TIMEOUT_S["yara"]))

        ctx.engines["yara"] = {"status": "ok", "matches": len(matches)}
        for match in matches:
            tag = next((t for t in match.tags if t in WEIGHT_TAGS), DEFAULT_TAG)
            ctx.add(
                self.name,
                f"YARA_{match.rule.upper()}",
                match.rule,
                weight_key=f"YARA:{tag}",
            )
