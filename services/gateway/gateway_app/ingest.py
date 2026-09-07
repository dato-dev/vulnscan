"""Приём файла: стриминг, хэш, кэш, постановка в очередь, ожидание результата."""

from __future__ import annotations

import logging
import tempfile
import time
import uuid
from pathlib import PurePosixPath

from fastapi import HTTPException, status

from vscommon.cache import assemble, weights_key_for
from vscommon.hashing import StreamHasher, short
from vscommon.logging import log_context
from vscommon.metrics import CACHED_FULL, metrics, tenant_label
from vscommon.models import (
    CachedStructural,
    ObjectRef,
    ScanJob,
    ScanRecord,
    ScanRequest,
    ScanResult,
    ScanStatus,
    Verdict,
)
from vscommon.policy import upload_limit_for
from vscommon.telemetry import current_traceparent, span

from .cache_probe import CacheProbe
from .config import settings
from .state import AppState
from .throttle import DEFAULT_TENANT

logger = logging.getLogger(__name__)

CHUNK = 1024 * 1024
_HEX = frozenset("0123456789abcdef")


def _check_idempotency_key(key: str | None, sha256: str) -> None:
    """Ключ идемпотентности, если это хэш, обязан совпасть с содержимым.

    Так ловится обрезанная загрузка. Ключи произвольного вида (uuid и прочее)
    пропускаем: дедупликация всё равно идёт по содержимому файла.
    """
    if key is None:
        return
    candidate = key.strip().lower()
    if len(candidate) != 64 or not set(candidate) <= _HEX:
        return
    if candidate != sha256:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Idempotency-Key не совпадает с sha256 полученного файла",
        )


class Ingestor:
    def __init__(self, state: AppState) -> None:
        self._state = state

    async def ingest_upload(
        self,
        upload,
        request: ScanRequest,
        idempotency_key: str | None = None,
        max_bytes: int | None = None,
    ) -> tuple[ScanResult, bool]:
        """Приём multipart-файла. Возвращает (результат, синхронный_ли_ответ).

        `max_bytes` приходит из талона (M12.1) и **сужает** предел политики, а
        не заменяет его. Иначе талон, выписанный когда-то на больший размер,
        пережил бы ужесточение политики и остался лазейкой.

        Контекст трассировки сюда не передаётся: заголовок принимает
        `tracing_middleware`, и всё внутри — обычные вложенные спаны.
        """
        started = time.perf_counter()
        policy = self._state.policies.for_tenant(request.tenant)
        size_limit = upload_limit_for(policy)
        if max_bytes is not None:
            size_limit = min(size_limit, max_bytes)

        hasher = StreamHasher()
        with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as buffer:
            # Чтение тела и потоковый sha256 — самая долгая часть приёма
            # шестнадцатимегабайтного файла, и до этого спана она не попадала
            # в трейс вовсе: `scan.accept` открывался уже после неё.
            with span("ingest.read"):
                while chunk := await upload.read(CHUNK):
                    hasher.update(chunk)
                    if hasher.size > size_limit:
                        # Чтение прерываем сразу: дочитывать то, что всё равно
                        # отвергнем, — подарок тому, кто шлёт большие файлы.
                        metrics().rejections.labels(reason="too_large").inc()
                        raise HTTPException(
                            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"файл больше {size_limit} байт",
                        )
                    buffer.write(chunk)

            if hasher.size == 0:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "пустой файл")

            sha256 = hasher.hexdigest
            _check_idempotency_key(idempotency_key, sha256)

            # Размер снимается на приёме, а не рядом с вердиктом. Рядом с
            # вердиктом он описывал бы только те файлы, что успели ответить
            # синхронно, — то есть заведомо лёгкие, при том что метрика
            # заведена ровно ради тяжёлых.
            self._observe_accepted(self._resolve_profile(request), hasher.size)

            probe = await self._lookup_cache(sha256, request, hasher.size)
            if probe.result is not None:
                self._observe_verdict(
                    probe.result,
                    request,
                    self._resolve_profile(request),
                    CACHED_FULL,
                    time.perf_counter() - started,
                )
                return probe.result, True

            ref = self._state.store.put(
                settings.raw_bucket,
                f"{sha256[:2]}/{sha256}",
                buffer,
                request.declared_mime or "application/octet-stream",
            )
        ref.size = hasher.size
        return await self._dispatch(sha256, ref, hasher.size, request, probe.structural)

    async def ingest_ref(self, request: ScanRequest) -> tuple[ScanResult, bool]:
        """Приём файла по ссылке — файл уже лежит в общем хранилище."""
        if request.source is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "не задан source")
        if not self._state.store.exists(request.source):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "объект не найден")

        # sha256 по ссылке считает воркер: gateway не тянет тело ради хэша.
        pseudo = f"ref:{request.source.bucket}/{request.source.key}"
        self._observe_accepted(self._resolve_profile(request), request.source.size or 0)
        return await self._dispatch(
            sha256=pseudo,
            ref=request.source,
            size=request.source.size or 0,
            request=request,
        )

    def _resolve_profile(self, request: ScanRequest) -> str:
        policy = self._state.policies.for_tenant(request.tenant)
        return (request.profile or policy.default_profile).value

    async def _lookup_cache(self, sha256: str, request: ScanRequest, size: int) -> CacheProbe:
        policy = self._state.policies.for_tenant(request.tenant)
        structural = await self._state.structural.get(
            sha256,
            self._resolve_profile(request),
            await self._state.rules_version(),
            weights_key_for(policy),
        )
        metrics().observe_cache("structural", structural is not None)
        if structural is None:
            return CacheProbe()

        if structural.sanitized is not None and not self._state.store.exists(
            structural.sanitized.ref
        ):
            logger.info("артефакт из кэша исчез, нужен полный проход")
            return CacheProbe()

        av = await self._state.av_cache.get(sha256, await self._state.engine_version())
        metrics().observe_cache("av", av is not None)
        if av is None:
            # Базы обновились. Структурная часть при этом не обесценилась —
            # ради этого уровни и разделены.
            logger.info("структурный кэш-хит, нужен только антивирус")
            return CacheProbe(structural=structural)

        result = assemble(structural, av, policy)

        if result.verdict is Verdict.MALICIOUS and await self._state.allowlist.get(
            sha256, request.tenant
        ):
            if structural.sanitized is None:
                # Запись внесли уже после того, как файл заблокировали: копии в
                # кэше нет, потому что CDR для заблокированного не запускался.
                # Один полный проход — и дальше кэш снова годится.
                #
                # Заявку на проверку тоже снимаем: она живёт ещё несколько минут
                # после завершения скана, и без этого повторный запрос
                # дедуплицировался бы на прежний, заблокированный результат —
                # то есть снятие блокировки не действовало бы до её истечения.
                await self._state.registry.release(sha256, self._resolve_profile(request))
                logger.info("файл в списке доверенных, копии в кэше нет — пересканируем")
                return CacheProbe()

            logger.info("блокировка снята записью в списке доверенных (ответ из кэша)")
            result.verdict = Verdict.SUSPICIOUS
            result.allowlisted = True
            result.sanitized = structural.sanitized

        # Ответ из кэша получает новый scan_id, и статус под ним надо сохранить:
        # иначе GET /v1/scan/{id} и выдача обезвреженной копии дают 404 на
        # совершенно успешную проверку.
        await self._state.results.store_status(result)
        # Владелец записывается ВЕЗДЕ, где наружу уходит новый scan_id, а не
        # только на пути полной проверки. Ответ из кэша получает свежий
        # идентификатор, и без этой строки клиент не мог забрать собственный
        # результат: проверка владения честно отвечала `404`.
        await self._state.ownership.claim(result.scan_id, request.tenant)
        # История пишется и здесь. Ответ из кэша — такая же оказанная услуга:
        # тенант получил вердикт, и без записи он мог бы прислать тысячу файлов,
        # а по документам не сделать ни одной проверки. Воркер сюда не заходит
        # вовсе, так что кроме gateway записать некому.
        await self._record_history(result, request, size)
        logger.info("полный кэш-хит", extra={"verdict": result.verdict.value})
        return CacheProbe(result=result)

    @staticmethod
    def _observe_accepted(profile: str, size: int) -> None:
        """Размер принятого файла — на приёме, независимо от исхода.

        Исход бывает трёх видов: ответ из кэша, синхронный вердикт и уход в
        `202` с коллбэком. Первый и третий до вердикта в gateway не доходят,
        поэтому измерение, привязанное к вердикту, описывало бы только
        середину — файлы, которые успели в `wait_ms`, то есть лёгкие. Метрика
        заведена (M10.11) объяснять уехавший p95, а объясняют его как раз
        тяжёлые.
        """
        if size <= 0:
            # Приём по ссылке: размер знает воркер, gateway тело не тянет.
            # Ноль в гистограмме — не наблюдение, а испорченная нижняя корзина.
            return
        metrics().input_bytes.labels(profile=profile).observe(size)

    @staticmethod
    def _observe_verdict(
        result: ScanResult,
        request: ScanRequest,
        profile: str,
        cached: str,
        elapsed_s: float,
    ) -> None:
        """Вердикт, отданный **самим gateway**, — то есть ответ из кэша.

        Всё остальное считает воркер: он единственный видит и те сканы, что
        успели в `wait_ms`, и те, что ушли в коллбэк. Считать здесь и там
        значило бы считать синхронные дважды, а считать только здесь — не
        считать асинхронные вовсе. Ровно так и было: `vs_scans_total` описывал
        полосу между кэшем и дедлайном, а алерт на долю вредоносных делил одно
        смещённое число на другое.

        Меряется здесь, а не в middleware: middleware видит длительность
        запроса целиком, вместе с чтением тела.
        """
        current = metrics()
        current.scans.labels(
            verdict=result.verdict.value,
            tenant=tenant_label(request.tenant),
            mode=request.mode.value,
        ).inc()
        current.verdict_seconds.labels(profile=profile, cached=cached).observe(elapsed_s)

    async def _record_history(self, result: ScanResult, request: ScanRequest, size: int) -> None:
        """Отправляет запись в поток истории.

        Отказ не прерывает ответ клиенту: вердикт важнее истории. В базу
        gateway не ходит — там владеет только Result Writer.
        """
        try:
            await self._state.history.publish(
                ScanRecord(
                    result=result,
                    tenant=request.tenant,
                    size=size,
                    detected_mime=result.facts.detected_mime if result.facts else None,
                    rules_version=await self._state.rules_version(),
                    av_db_version=await self._state.engine_version(),
                    traceparent=current_traceparent() or "",
                )
            )
        except Exception:
            logger.exception("не удалось записать ответ из кэша в историю")

    async def _dispatch(
        self,
        sha256: str,
        ref: ObjectRef,
        size: int,
        request: ScanRequest,
        cached: CachedStructural | None = None,
    ) -> tuple[ScanResult, bool]:
        ext = PurePosixPath(request.filename).suffix.lower()[:16] if request.filename else None

        # Политика приходит с сервера, а не из запроса: клиент не должен иметь
        # возможности выбрать себе fail-open (см. ROADMAP M1.1).
        policy = self._state.policies.for_tenant(request.tenant)
        profile = request.profile or policy.default_profile
        wait_ms = min(request.wait_ms, policy.max_wait_ms)

        # Заявка на проверку: тот же файл, присланный дважды, получает один
        # scan_id и проверяется один раз (ROADMAP M1.5).
        candidate = uuid.uuid4().hex
        scan_id = await self._state.registry.claim(sha256, profile.value, candidate)
        duplicate = scan_id != candidate

        if not duplicate and not await self._state.concurrency.acquire(
            request.tenant or DEFAULT_TENANT, scan_id, policy.max_concurrent_scans
        ):
            # Дубль слот не занимает: он ждёт чужую проверку, а не создаёт свою.
            await self._state.registry.release(sha256, profile.value)
            logger.warning(
                "превышен предел одновременных проверок",
                extra={"tenant": request.tenant, "limit": policy.max_concurrent_scans},
            )
            metrics().rejections.labels(reason="concurrency").inc()
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "слишком много одновременных проверок",
                headers={"Retry-After": "5"},
            )

        with (
            log_context(scan_id=scan_id, sha=short(sha256), tenant=request.tenant),
            # Обычный вложенный спан, а не продолжение чужого контекста. Контекст
            # от клиента принимает `tracing_middleware` — единственная точка, где
            # он вообще принимается. `continue_trace` здесь ставил бы родителя
            # заново, из заголовка, и спан приёма оказывался бы не потомком
            # серверного спана, а его братом: чтение тела и заливка в S3 висели
            # бы в дереве отдельно от того, ради чего они делались.
            span(
                "scan.accept",
                scan_id=scan_id,
                tenant=tenant_label(request.tenant),
                profile=profile.value,
                size=size,
                duplicate=duplicate,
                av_only=cached is not None,
            ),
        ):
            started = time.perf_counter()

            if duplicate:
                logger.info(
                    "дубль: файл уже проверяется, ждём общий результат",
                    extra={"size": size, "profile": profile.value},
                )
            else:
                await self._state.queue.publish(
                    ScanJob(
                        scan_id=scan_id,
                        sha256=sha256,
                        source=ref,
                        size=size,
                        filename_ext=ext,
                        declared_mime=request.declared_mime,
                        mode=request.mode,
                        profile=profile,
                        policy=policy,
                        callback_url=str(request.callback_url) if request.callback_url else None,
                        tenant=request.tenant,
                        cached=cached,
                        traceparent=current_traceparent() or "",
                        key_id=request.key_id,
                    )
                )
                logger.info(
                    "скан принят",
                    extra={
                        "size": size,
                        "ext": ext,
                        "profile": profile.value,
                        "fail_mode": policy.fail_mode.value,
                        "av_only": cached is not None,
                    },
                )

            # Владельца фиксируем ДО ожидания результата: иначе при таймауте
            # клиент получил бы `202` и не смог забрать собственный скан.
            await self._state.ownership.claim(scan_id, request.tenant)

            result = await self._state.results.wait(scan_id, wait_ms)
            if result is not None:
                elapsed_s = time.perf_counter() - started
                logger.debug(
                    "синхронный ответ",
                    extra={"elapsed_ms": int(elapsed_s * 1000), "duplicate": duplicate},
                )
                # Вердикт здесь не считается: этот скан прошёл через воркер, и
                # считает его воркер — вместе с теми, что не успели в `wait_ms`
                # и ушли коллбэком. См. `_observe_verdict`.
                return result, True

            logger.debug("дедлайн синхронного ответа истёк, уходим в коллбэк")
            pending = ScanResult(
                scan_id=scan_id,
                sha256=sha256,
                status=ScanStatus.QUEUED,
                verdict=Verdict.SUSPICIOUS,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
            )
            return pending, False
