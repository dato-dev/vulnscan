"""Конвейер: стадии с ранним выходом, затем CDR."""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from vscommon.hashing import sha256_bytes, short
from vscommon.limits import CDR_TIMEOUT_S, MAX_ARCHIVE_DEPTH, STAGE_TIMEOUT_S
from vscommon.metrics import metrics
from vscommon.models import (
    UNSCANNABLE_VERDICTS,
    CachedStructural,
    CdrProfile,
    SanitizedArtifact,
    ScanJob,
    ScanMode,
    ScanResult,
    ScanStatus,
    StageTiming,
    Verdict,
)
from vscommon.scoring import verdict_of as verdict_of_facts
from vscommon.storage import ObjectStore
from vscommon.telemetry import span
from vscommon.weights import WeightTable

from . import archive
from .cdr.base import SanitizeError
from .cdr.registry import sanitize
from .config import settings
from .failure import RISKY_STAGES
from .scoring import apply_failure, should_stop_early, verdict_of
from .stages.archive_structure import mark_incomplete
from .stages.base import ScanContext, Stage
from .stages.clamav import ClamavStage
from .stages.filetype import FiletypeStage
from .stages.structure import StructureStage
from .stages.yara_rules import CanaryObserver, YaraStage

logger = logging.getLogger(__name__)

StageReporter = Callable[[str], Awaitable[None]]
"""Отметка «зашли в рискованную стадию» для журнала попыток."""

AllowlistCheck = Callable[[str, "str | None", Verdict], Awaitable[bool]]
"""Проверка, снята ли блокировка для конкретного файла."""


async def _apply_allowlist(
    check: AllowlistCheck | None, sha256: str, tenant: str | None, verdict: Verdict
) -> tuple[Verdict, bool]:
    """Снимает блокировку, если файл внесён в список доверенных.

    Признаки при этом остаются в ответе: оператор должен видеть, что именно
    сработало и было перекрыто вручную.
    """
    if check is None or not await check(sha256, tenant, verdict):
        return verdict, False
    return Verdict.SUSPICIOUS, True


def _file_signature(path: Path) -> tuple[int, int] | None:
    """Размер и mtime: дешёвая проверка «файл трогали»."""
    try:
        info = path.stat()
    except OSError:
        return None
    return info.st_size, int(info.st_mtime_ns)


@contextmanager
def workspace(root: str) -> Iterator[Path]:
    """Каталог в tmpfs, гарантированно удаляемый после обработки."""
    Path(root).mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=root, prefix="scan-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class Pipeline:
    def __init__(
        self,
        store: ObjectStore,
        stages: tuple[Stage, ...] | None = None,
        weights: WeightTable | None = None,
    ) -> None:
        self._store = store
        self._weights = weights or WeightTable.load(settings.weights_file)
        self._weights_signature = (
            _file_signature(Path(settings.weights_file)) if settings.weights_file else None
        )
        self._clamav = ClamavStage()
        self._stages: tuple[Stage, ...] = stages or (
            FiletypeStage(),
            StructureStage(),
            self._clamav,
            YaraStage(),
        )

    @property
    def engine_version(self) -> str:
        return self._clamav.engine_version

    def warmup(self) -> None:
        """Прогревает движки, чтобы их версии были известны до публикации.

        Версия баз антивируса входит в ключ AV-кэша. Опубликованная до первого
        обращения к clamd, она осталась бы навсегда `unavailable`, и кэш
        перестал бы протухать при обновлении баз.
        """
        for stage in self._stages:
            warm = getattr(stage, "warmup", None)
            if warm is not None:
                warm()

    def reload_config(self) -> bool:
        """Подхватывает изменённые правила и веса. True — что-то заменено.

        Веса участвуют в скоринге наравне с правилами, и в M2.3 заявлено, что
        их правка не требует пересборки образа. До перезагрузки это было верно
        только с рестартом воркера.
        """
        # Список, а не генератор: все перезагрузки должны выполниться.
        changed = [self._reload_rules(), self._reload_weights(), self._refresh_engine()]
        return any(changed)

    def _refresh_engine(self) -> bool:
        """Версия баз антивируса. Меняется под нами: freshclam обновляет их,
        clamd подхватывает, и с этого момента прежние вердикты недействительны."""
        refresh = getattr(self._clamav, "refresh_version", None)
        return bool(refresh and refresh())

    def _reload_rules(self) -> bool:
        stage = next((s for s in self._stages if hasattr(s, "reload_if_changed")), None)
        return bool(stage and stage.reload_if_changed())

    def reload_candidate(self) -> bool:
        """Перекомпилирует набор-кандидат, если его правили (M7.2).

        Отдельно от `reload_config`: кандидат на вердикт не влияет и в
        отпечаток не входит, а `reload_config` своим результатом сообщает
        «версия правил сменилась».
        """
        stage = next((s for s in self._stages if hasattr(s, "reload_candidate_if_changed")), None)
        return bool(stage and stage.reload_candidate_if_changed())

    def observe_canary_with(self, observer: CanaryObserver) -> None:
        stage = next((s for s in self._stages if hasattr(s, "observe_with")), None)
        if stage is not None:
            stage.observe_with(observer)

    def apply_rule_control(self, disabled: frozenset[str]) -> bool:
        """Список выключенных правил (M7.2). Возвращает, изменился ли он.

        Отдельно от `reload_config`, потому что источник другой: правила
        лежат файлами, а выключатель — в Redis. Смешивать их значило бы
        сделать выключатель заложником доступности файлов.
        """
        stage = next((s for s in self._stages if hasattr(s, "apply_control")), None)
        return bool(stage and stage.apply_control(disabled))

    def _reload_weights(self) -> bool:
        path = settings.weights_file
        if not path:
            return False

        signature = _file_signature(Path(path))
        if signature == self._weights_signature:
            return False
        self._weights_signature = signature

        try:
            table = WeightTable.load(path)
        except Exception:
            logger.exception("новая таблица весов не читается, оставляю прежнюю")
            # Тот же случай, что и с правилами YARA: сервис продолжает считать
            # балл по старым весам, и это ничем себя не проявляет.
            metrics().config_reloads.labels(kind="weights", outcome="failed").inc()
            return False

        if table.fingerprint() == self._weights.fingerprint():
            return False

        self._weights = table
        logger.info("таблица весов перезагружена", extra={"fingerprint": table.fingerprint()})
        metrics().config_reloads.labels(kind="weights", outcome="applied").inc()
        metrics().rules_loaded.labels(kind="weights").set(len(table))
        return True

    @property
    def rules_version(self) -> str:
        """Версия того, что влияет на структурную часть результата."""
        yara_fp = next(
            (s.rules_fingerprint for s in self._stages if hasattr(s, "rules_fingerprint")),
            "none",
        )
        return f"{yara_fp}-{self._weights.fingerprint()}"

    @property
    def libmagic_available(self) -> bool:
        """Деградация до таблицы сигнатур должна быть видна в /readyz."""
        return any(getattr(stage, "libmagic_available", False) for stage in self._stages)

    @property
    def weights_degraded(self) -> bool:
        """Файл весов задан и не прочитан — балл считается по встроенным.

        Молчаливее этого мало что бывает: стадии отрабатывают, признаки
        находятся, вердикт выдаётся — просто по чужим порогам. Ни в логах после
        старта, ни в вердиктах это не видно, а `unknown_codes` тут не помогут:
        встроенная таблица знает все коды, она просто оценивает их иначе.
        """
        return self._weights.degraded

    async def process(
        self,
        job: ScanJob,
        on_stage: StageReporter | None = None,
        allowlist: AllowlistCheck | None = None,
    ) -> ScanResult:
        if job.cached is not None and self._reusable(job.cached):
            return await self._process_av_only(job, job.cached, on_stage, allowlist)
        return await self._process_full(job, on_stage, allowlist)

    def _reusable(self, cached: CachedStructural) -> bool:
        """Артефакт мог истечь по TTL — тогда структурная часть бесполезна."""
        if cached.sanitized is None:
            return True
        if self._store.exists(cached.sanitized.ref):
            return True
        logger.info("артефакт из кэша исчез, нужен полный проход")
        return False

    async def _process_av_only(
        self,
        job: ScanJob,
        cached: CachedStructural,
        on_stage: StageReporter | None,
        allowlist: AllowlistCheck | None = None,
    ) -> ScanResult:
        """Структурная часть уже есть — обновляем только вердикт антивируса."""
        started = time.perf_counter()

        with workspace(settings.work_dir) as work:
            src = work / "input.bin"
            await asyncio.to_thread(self._store.get_to_path, job.source, src)

            ctx = ScanContext(job=job, path=src, weights=self._weights)
            timings: list[StageTiming] = []
            await self._run_stages(ctx, timings, job, on_stage, stages=(self._clamav,))

            facts = cached.facts.merge(ctx.facts())
            verdict, score = verdict_of_facts(facts, job.policy)
            verdict, allowlisted = await _apply_allowlist(
                allowlist, cached.sha256, job.tenant, verdict
            )
            result = ScanResult(
                scan_id=job.scan_id,
                sha256=cached.sha256,
                status=ScanStatus.DONE,
                verdict=verdict,
                score=score,
                findings=facts.findings,
                engines={**cached.engines, **ctx.engines},
                stages=cached.stages + timings,
                sanitized=cached.sanitized if verdict is not Verdict.MALICIOUS else None,
                facts=facts,
                allowlisted=allowlisted,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            )

        logger.info(
            "скан завершён по кэшу структуры",
            extra={"verdict": result.verdict.value, "elapsed_ms": result.elapsed_ms},
        )
        return result

    async def _process_full(
        self,
        job: ScanJob,
        on_stage: StageReporter | None,
        allowlist: AllowlistCheck | None = None,
    ) -> ScanResult:
        started = time.perf_counter()
        timings: list[StageTiming] = []

        with workspace(settings.work_dir) as work:
            src = work / "input.bin"
            await asyncio.to_thread(self._store.get_to_path, job.source, src)

            sha256 = job.sha256
            if sha256.startswith("ref:"):
                # Файл пришёл ссылкой — хэш считаем здесь, а не в gateway.
                sha256 = await asyncio.to_thread(lambda: sha256_bytes(src.read_bytes()))

            ctx = ScanContext(
                job=job,
                path=src,
                weights=self._weights.with_overrides(job.policy.weight_overrides),
            )
            await self._run_stages(ctx, timings, job, on_stage)
            await self._expand(ctx, timings, job, on_stage)

            verdict, score = verdict_of(ctx, job.policy)
            # Снятие блокировки — ДО решения о пересборке: заблокированный файл
            # в CDR не идёт, и без этого доверенный документ остался бы без
            # обезвреженной копии.
            verdict, allowlisted = await _apply_allowlist(allowlist, sha256, job.tenant, verdict)
            facts = ctx.facts()
            result = ScanResult(
                scan_id=job.scan_id,
                sha256=sha256,
                status=ScanStatus.DONE,
                verdict=verdict,
                score=score,
                findings=ctx.findings,
                engines=ctx.engines,
                stages=timings,
                facts=facts,
                shadow=job.policy.shadow_mode,
                allowlisted=allowlisted,
                deep=job.deep,
                parent_scan_id=job.parent_scan_id,
            )

            if self._should_sanitize(job, verdict):
                if on_stage is not None:
                    await on_stage("cdr")
                await self._sanitize(
                    job, ctx, result, work, sha256, timings, self.profile_for(job, verdict)
                )

            result.elapsed_ms = int((time.perf_counter() - started) * 1000)

        logger.info(
            "скан завершён",
            extra={
                "вердикт": result.verdict.value,
                "балл": result.score,
                "признаки": [f.code for f in result.findings][:8],
                "пересобран": result.sanitized is not None,
                "непроверяем": result.unscannable(),
                "мс": result.elapsed_ms,
                # На что ушло время. Без разбивки «скан занял 900 мс» не
                # говорит ничего: непонятно, тормозит антивирус, растеризация
                # или разбор структуры.
                "стадии": {t.stage: t.elapsed_ms for t in timings},
            },
        )
        return result

    async def _run_stages(
        self,
        ctx: ScanContext,
        timings: list[StageTiming],
        job: ScanJob,
        on_stage: StageReporter | None = None,
        stages: tuple[Stage, ...] | None = None,
    ) -> None:
        for stage in stages or self._stages:
            if on_stage is not None and stage.name in RISKY_STAGES:
                # Отметка ставится ДО входа в C-код: если он уронит процесс,
                # следующая попытка узнает, где именно это случилось.
                await on_stage(stage.name)
            stage_started = time.perf_counter()
            timeout = STAGE_TIMEOUT_S.get(stage.name, 30.0)
            # Спан на стадию: именно здесь видно, какая проверка съела бюджет.
            # Стадия работает в пуле потоков, но контекст спана наследуется —
            # `to_thread` копирует contextvars.
            #
            # Имя стадии — в имени спана, а не только в атрибуте. Коннектор
            # `spanmetrics` в коллекторе считает по умолчанию по `span.name`, и
            # с общим именем «stage» все стадии складывались в один ряд: панель
            # «p95 по спанам» показывала одну линию вместо шести, то есть ровно
            # то, ради чего её заводили, было не видно. Атрибут оставлен —
            # по нему фильтруют в Tempo.
            with span(f"stage.{stage.name}", stage=stage.name, timeout_s=timeout) as sp:
                try:
                    ok = await asyncio.wait_for(
                        asyncio.to_thread(stage.safe_run, ctx), timeout=timeout
                    )
                except TimeoutError:
                    logger.warning(
                        "стадия не уложилась в таймаут",
                        extra={"stage": stage.name, "timeout_s": timeout},
                    )
                    ctx.failed_stages.add(stage.name)
                    ctx.add(stage.name, "STAGE_TIMEOUT", f"{timeout}s")
                    metrics().stage_failures.labels(stage=stage.name, reason="timeout").inc()
                    ok = False

                elapsed_s = time.perf_counter() - stage_started
                sp.set_attribute("ok", ok)

            elapsed = int(elapsed_s * 1000)
            metrics().observe_stage(stage.name, elapsed_s, ok)
            if not ok and stage.name not in ctx.failed_stages:
                metrics().stage_failures.labels(stage=stage.name, reason="failed").inc()
            timings.append(StageTiming(stage=stage.name, elapsed_ms=elapsed, ok=ok))
            logger.debug("стадия завершена", extra={"stage": stage.name, "elapsed_ms": elapsed})

            if not job.deep and should_stop_early(ctx, job.policy):
                # Углублённая проверка идёт до конца: она затем и нужна, чтобы
                # увидеть картину целиком, а не остановиться на первом пороге.
                logger.debug(
                    "ранний выход: порог блокировки достигнут", extra={"stage": stage.name}
                )
                return

    async def _expand(
        self,
        ctx: ScanContext,
        timings: list[StageTiming],
        job: ScanJob,
        on_stage: StageReporter | None,
    ) -> None:
        """Проверка вложений архива: полный проход стадий на каждую запись.

        Вложение проверяется так же, как загруженный файл: антивирус и YARA
        по сжатому архиву видят только сжатые байты. Признаки вложения
        переносятся на архив (`ScanContext.adopt`) — так ZIP с вредоносным PDF
        внутри не получает `clean` (M6.2).

        Рекурсия ограничена явно: глубже `MAX_ARCHIVE_DEPTH` опись не отдаёт
        записей, и сюда же стоит своя проверка — на случай, если опись
        когда-нибудь об этом забудет.
        """
        if not ctx.members or ctx.budget is None or ctx.depth > MAX_ARCHIVE_DEPTH:
            return
        if on_stage is not None:
            # До распаковки: разжимает её zlib, то есть C-код на чужих данных.
            await on_stage("archive")

        started = time.perf_counter()
        with span("archive", members=len(ctx.members), depth=ctx.depth):
            await self._scan_members(ctx, job, on_stage)
        if ctx.depth == 0:
            timings.append(
                StageTiming(
                    stage="archive",
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                    ok="archive" not in ctx.failed_stages,
                )
            )

    async def _scan_members(
        self, ctx: ScanContext, job: ScanJob, on_stage: StageReporter | None
    ) -> None:
        budget = ctx.budget
        assert budget is not None
        # Заявленные клиентом тип и расширение — про архив, а не про его
        # содержимое. Перенесённые на вложение, они давали бы ложное
        # «расширение не совпадает» на каждом файле внутри.
        member_job = job.model_copy(
            update={"filename_ext": None, "declared_mime": None, "cached": None}
        )
        base = Path(tempfile.mkdtemp(dir=ctx.path.parent, prefix=f"members-{ctx.depth}-"))
        try:
            for member in ctx.members:
                if not job.deep and should_stop_early(ctx, job.policy):
                    # Архив уже блокируется: остальное не изменит вердикта.
                    return
                if budget.expired():
                    mark_incomplete(ctx, "archive", "время на проверку вложений вышло")
                    return

                path = base / f"{member.index:05d}.bin"
                try:
                    await asyncio.to_thread(archive.extract, ctx.path, member.info, path, budget)
                except archive.BudgetExceededError as exc:
                    mark_incomplete(ctx, "archive", f"вложение {member.label}: {exc}")
                    return
                except archive.ArchiveError as exc:
                    # Не распаковалось — значит, не проверено.
                    ctx.supported = False
                    ctx.add("archive", "ARCHIVE_MALFORMED", f"вложение {member.label}: {exc}")
                    continue

                child = ScanContext(
                    job=member_job,
                    path=path,
                    weights=ctx.weights,
                    budget=budget,
                    depth=ctx.depth + 1,
                )
                try:
                    # Тайминги вложений в ответ не идут: у архива на сотню
                    # файлов список стадий стал бы длиннее самого ответа.
                    await self._run_stages(child, [], member_job, on_stage)
                    await self._expand(child, [], member_job, on_stage)
                finally:
                    path.unlink(missing_ok=True)
                ctx.adopt(child, f"вложение {member.label}")
        finally:
            shutil.rmtree(base, ignore_errors=True)

    @staticmethod
    def _should_sanitize(job: ScanJob, verdict: Verdict) -> bool:
        """Пересобирать нечего ни у вредоносного файла, ни у непроверяемого.

        Вредоносный не пересобираем осознанно (architecture §3). Непроверяемый —
        тем более: раньше он уходил в CDR, падал с `SanitizeError`, и ветка
        отказа перезаписывала вердикт режимом отказа, вплоть до `clean`
        при `fail-open`.
        """
        if job.mode is ScanMode.DETECT:
            return False
        if verdict in UNSCANNABLE_VERDICTS:
            return False
        if verdict is Verdict.MALICIOUS and job.deep:
            # Углублённая проверка пересобирает и заблокированное: так
            # выясняется, поддаётся ли документ безопасной пересборке вообще.
            return True
        if verdict is Verdict.MALICIOUS:
            # В тени пересобираем и это. Файл уже прошёл через pikepdf на
            # стадии разбора, так что новой поверхности атаки CDR не добавляет,
            # а выход проверяется `verify_sanitized`. Без этого теневой режим
            # оставлял бы пользователя без файла ровно в тех случаях, ради
            # которых он и нужен.
            #
            # И то же самое, когда тенант попросил отдавать заблокированное
            # (M14.9). Пересобирается оно ВСЕГДА растеризацией — см.
            # `profile_for`.
            return job.policy.shadow_mode or job.policy.deliver_blocked == "strict"
        return True

    @staticmethod
    def profile_for(job: ScanJob, verdict: Verdict) -> CdrProfile:
        """Каким профилем пересобирать. Для заблокированного — только `strict`.

        Профиль тенанта здесь не годится. `light` и `standard` удаляют то, что
        мы **знаем**; для чистого файла этого хватает, для заблокированного
        нет — мы уже нашли в нём что-то плохое, а платим за ненайденное.
        Растеризация безопасна by construction: из исходника не остаётся ни
        одного объекта, и утверждение не зависит от того, что в нём было.

        Поэтому выбор не отдан настройке. Возможность собрать заблокированное
        профилем `standard` выглядела бы разумным компромиссом и была бы
        худшим из вариантов: эвристика, выданная за гарантию.
        """
        return CdrProfile.STRICT if verdict is Verdict.MALICIOUS else job.profile

    async def _sanitize(
        self,
        job: ScanJob,
        ctx: ScanContext,
        result: ScanResult,
        work: Path,
        sha256: str,
        timings: list[StageTiming],
        profile: CdrProfile,
    ) -> None:
        out_dir = work / "clean"
        out_dir.mkdir(exist_ok=True)
        started = time.perf_counter()
        timeout = CDR_TIMEOUT_S[profile.value]

        try:
            with span("cdr", profile=profile.value, timeout_s=timeout):
                outcome = await asyncio.wait_for(
                    asyncio.to_thread(sanitize, ctx.path, out_dir, ctx.detected_mime, profile),
                    timeout=timeout,
                )
        except (SanitizeError, TimeoutError) as exc:
            metrics().cdr_seconds.labels(profile=profile.value, ok="false").observe(
                time.perf_counter() - started
            )
            logger.warning(
                "CDR не удался",
                extra={"profile": profile.value, "reason": type(exc).__name__},
            )
            ctx.add("cdr", "CDR_FAILED", type(exc).__name__)
            result.status = ScanStatus.FAILED
            result.verdict = apply_failure(result.verdict, job.policy)
            result.findings = ctx.findings
            return

        clean_bytes = outcome.path.read_bytes()
        clean_sha = sha256_bytes(clean_bytes)
        with outcome.path.open("rb") as handle:
            ref = await asyncio.to_thread(
                self._store.put,
                settings.clean_bucket,
                f"{job.scan_id[:2]}/{job.scan_id}{outcome.path.suffix}",
                handle,
                outcome.content_type,
            )

        result.sanitized = SanitizedArtifact(
            ref=ref,
            profile=profile,
            transforms=outcome.transforms,
            original_sha256=sha256,
            sanitized_sha256=clean_sha,
            expires_at=time.time() + settings.artifact_ttl_s,
        )
        elapsed_s = time.perf_counter() - started
        metrics().cdr_seconds.labels(profile=profile.value, ok="true").observe(elapsed_s)
        elapsed = int(elapsed_s * 1000)
        timings.append(StageTiming(stage="cdr", elapsed_ms=elapsed, ok=True))
        logger.debug(
            "артефакт сохранён",
            extra={"elapsed_ms": elapsed, "clean_sha": short(clean_sha), "size": ref.size},
        )
