"""S3: собственные YARA-правила поверх сигнатурного детекта."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from vscommon import rules_control as control
from vscommon.limits import STAGE_TIMEOUT_S
from vscommon.metrics import metrics

from ..config import settings
from ..yara_views import EXTERNALS, views
from .base import ScanContext, Stage

logger = logging.getLogger(__name__)

CanaryObserver = Callable[[str, frozenset[str], frozenset[str]], None]
"""Куда уходит расхождение кандидата с действующим набором.

Аргументы: sha256 файла, что нашёл действующий набор, что нашёл кандидат.
Вызывается синхронно из пула потоков, поэтому обязан быть дешёвым: сеть,
блокировки и обращения к диску отсюда запрещены.
"""

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
        self._disabled: frozenset[str] = frozenset()
        self._candidate: Any = None
        self._candidate_signature: tuple[tuple[str, int, int], ...] | None = None
        self._lock = threading.Lock()
        self._observer: CanaryObserver | None = None

    @property
    def rules_fingerprint(self) -> str:
        """Отпечаток набора правил: входит в ключ структурного кэша.

        Содержимое файлов считается, а не скомпилированный объект: так
        отпечаток не зависит от того, дошло ли дело до компиляции, и меняется
        ровно тогда, когда меняются сами правила.

        Выключенные правила (M7.2) входят сюда же, и это обязательно. Иначе
        выключение не обесценило бы кэш: файл, проверенный час назад,
        продолжал бы отдаваться с признаком от правила, которого больше нет в
        работе.
        """
        if self._fingerprint is None:
            self._fingerprint = self._content_fingerprint()
        return f"{self._fingerprint}{control.fingerprint(self._disabled)}"

    @property
    def disabled_rules(self) -> frozenset[str]:
        return self._disabled

    def observe_with(self, observer: CanaryObserver | None) -> None:
        """Куда складывать расхождения кандидата с действующим набором.

        Наблюдатель необязателен: без него канарейка считается только
        метриками. Стадия работает в пуле потоков, поэтому наблюдатель обязан
        быть синхронным и быстрым — никаких сетевых вызовов из горячего пути.
        """
        self._observer = observer

    def apply_control(self, disabled: frozenset[str]) -> bool:
        """Принимает список выключенных правил. Возвращает, изменился ли он.

        Компиляции не требует: правила остаются скомпилированными, отсекаются
        их совпадения. Так выключение действует и на правило, которое сейчас
        не перечитать, — а именно в такие минуты им и пользуются.
        """
        if disabled == self._disabled:
            return False

        with self._lock:
            self._disabled = disabled

        if disabled:
            # На каждой перезагрузке, а не однократно: выключенное и забытое
            # правило — это дыра, и напоминать о ней должно регулярно.
            logger.warning(
                "правила выключены вручную и не участвуют в проверке",
                extra={"rules": sorted(disabled)},
            )
        else:
            logger.info("выключенных правил нет")
        metrics().rules_disabled.set(len(disabled))
        return True

    def _rule_files(self) -> list[Path]:
        return sorted(Path(settings.yara_rules_dir).glob("*.yar"))

    def _candidate_files(self) -> list[Path]:
        directory = settings.yara_candidate_dir
        return sorted(Path(directory).glob("*.yar")) if directory else []

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

        candidate = self._compile_candidate()

        with self._lock:
            self._rules = compiled
            self._compiled = True
            self._fingerprint = fingerprint
            self._stat_signature = stat_signature
            self._candidate = candidate
            self._candidate_signature = self._candidate_stat_signature()

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
            self._candidate = self._compile_candidate()
            self._candidate_signature = self._candidate_stat_signature()
        self._report_rules()
        return self._rules

    def _candidate_stat_signature(self) -> tuple[tuple[str, int, int], ...]:
        return tuple(
            (path.name, path.stat().st_size, int(path.stat().st_mtime_ns))
            for path in self._candidate_files()
        )

    def reload_candidate_if_changed(self) -> bool:
        """Кандидата правят чаще действующего набора — ради этого он и есть.

        Отдельно от `reload_if_changed`, потому что менять их вместе значило
        бы, что правка кандидата обесценивает структурный кэш. Кандидат на
        вердикт не влияет, в отпечаток не входит, кэш трогать не должен.
        """
        signature = self._candidate_stat_signature()
        if signature == self._candidate_signature:
            return False

        candidate = self._compile_candidate()
        with self._lock:
            self._candidate = candidate
            self._candidate_signature = signature
        return True

    def _compile(self) -> Any:
        import yara

        sources = {p.stem: str(p) for p in self._rule_files()}
        if not sources:
            logger.warning("правила YARA не найдены", extra={"dir": settings.yara_rules_dir})
            return None

        compiled = yara.compile(filepaths=sources, externals=EXTERNALS)
        logger.info("правила YARA скомпилированы", extra={"count": len(sources)})
        return compiled

    def _compile_candidate(self) -> Any:
        """Кандидат на выкатку (M7.2). Отсутствует — значит канарейки нет.

        Не компилируется — канарейка просто не работает, и это `WARNING`, а не
        отказ: набор-кандидат по определению сырой, и ронять им проверку файлов
        было бы ровно наоборот тому, ради чего он заведён.
        """
        directory = settings.yara_candidate_dir
        files = self._candidate_files()
        if not files:
            if directory:
                # Каталог задан, а правил в нём нет. Молчать здесь нельзя:
                # снаружи это неотличимо от работающей канарейки, которая не
                # нашла расхождений, — то есть от «кандидат хорош, выкатывай».
                logger.warning(
                    "канарейка настроена, но правил-кандидатов нет",
                    extra={"dir": directory},
                )
                metrics().rules_loaded.labels(kind="yara_candidate").set(0)
            return None

        import yara

        try:
            compiled = yara.compile(filepaths={p.stem: str(p) for p in files}, externals=EXTERNALS)
        except Exception:
            logger.exception("набор-кандидат не компилируется, канарейка выключена")
            metrics().config_reloads.labels(kind="yara_candidate", outcome="failed").inc()
            return None

        logger.info("набор-кандидат скомпилирован", extra={"count": len(files)})
        metrics().config_reloads.labels(kind="yara_candidate", outcome="applied").inc()
        metrics().rules_loaded.labels(kind="yara_candidate").set(len(files))
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

        candidate = self._candidate
        found: set[str] = set()
        candidate_ok = candidate is not None
        matches: list[tuple[Any, str]] = []
        deadline = time.monotonic() + STAGE_TIMEOUT_S["yara"]
        for part, data in views(ctx.path, ctx.detected_mime):
            if part and time.monotonic() > deadline:
                # Части документа кончились раньше времени. Стадия не
                # обязательная, но молча недосмотреть — значит выдать
                # отсутствие совпадений за проверенное.
                ctx.add(self.name, "STAGE_TIMEOUT", "не все части документа проверены")
                break
            with self._lock:
                matches += [(m, part) for m in _match(rules, ctx.path, part, data)]
            if candidate_ok:
                candidate_ok = self._match_candidate(candidate, ctx, part, data, found)

        # Отсев после сопоставления, а не до: правило остаётся
        # скомпилированным, и включить его обратно — снова одна строка в
        # Redis, без чтения файлов и без риска, что набор в этот момент не
        # компилируется.
        kept = [(match, part) for match, part in matches if match.rule not in self._disabled]
        suppressed = len(matches) - len(kept)

        ctx.engines["yara"] = {"status": "ok", "matches": len(kept)}
        if suppressed:
            # В `engines` это видно клиенту и в истории: иначе разбор старого
            # скана не объяснить — правило было, признака нет.
            ctx.engines["yara"]["suppressed"] = suppressed

        for match, part in kept:
            tag = next((t for t in match.tags if t in WEIGHT_TAGS), DEFAULT_TAG)
            ctx.add(
                self.name,
                f"YARA_{match.rule.upper()}",
                # Имя части — стандартное имя внутри пакета Word, а не имя
                # файла пользователя: ПДн в нём нет.
                f"{match.rule} в {part}" if part else match.rule,
                weight_key=f"YARA:{tag}",
            )

        if candidate_ok:
            self._compare_candidate(ctx, active={match.rule for match, _ in kept}, found=found)

    def _match_candidate(
        self, candidate: Any, ctx: ScanContext, part: str, data: bytes | None, found: set[str]
    ) -> bool:
        """Прогон набора-кандидата вхолостую (M7.2). False — кандидат упал.

        Совпадения кандидата НЕ попадают ни в признаки, ни в `engines`, ни
        в кэш. Это не осторожность, а определение: набор, способный изменить
        вердикт, — не канарейка, а выкатка на долю трафика. Кандидат заводят,
        чтобы узнать цену выкатки, и узнать её должно быть безопасно.

        Отсюда и обработка ошибок: что бы кандидат ни сделал, проверка файла
        уже состоялась, и портить её результат нельзя.
        """
        try:
            with self._lock:
                found.update(match.rule for match in _match(candidate, ctx.path, part, data))
        except Exception:
            logger.warning("набор-кандидат не отработал на файле", exc_info=True)
            metrics().canary_runs.labels(outcome="failed").inc()
            return False
        return True

    def _compare_candidate(self, ctx: ScanContext, active: set[str], found: set[str]) -> None:
        if found == active:
            metrics().canary_runs.labels(outcome="agree").inc()
        else:
            # Две стороны расхождения означают разное. Лишнее у кандидата —
            # будущие ложные срабатывания, пропавшее — потерянный детект.
            if found - active:
                metrics().canary_runs.labels(outcome="candidate_only").inc()
            if active - found:
                metrics().canary_runs.labels(outcome="active_only").inc()

        if self._observer is not None and found != active:
            self._observer(ctx.job.sha256, frozenset(active), frozenset(found))


def _match(rules: Any, path: Path, part: str, data: bytes | None) -> list[Any]:
    """Сопоставление одного вида файла: целиком по пути или части из памяти."""
    timeout = int(STAGE_TIMEOUT_S["yara"])
    if data is None:
        return list(rules.match(str(path), externals=EXTERNALS, timeout=timeout))
    return list(rules.match(data=data, externals={"part": part}, timeout=timeout))
