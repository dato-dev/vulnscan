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
from vscommon.metrics import metrics, tenant_label
from vscommon.models import (
    CachedStructural,
    ObjectRef,
    ScanJob,
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
        self, upload, request: ScanRequest, idempotency_key: str | None = None
    ) -> tuple[ScanResult, bool]:
        """Приём multipart-файла. Возвращает (результат, синхронный_ли_ответ)."""
        policy = self._state.policies.for_tenant(request.tenant)
        size_limit = upload_limit_for(policy)

        hasher = StreamHasher()
        with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as buffer:
            while chunk := await upload.read(CHUNK):
                hasher.update(chunk)
                if hasher.size > size_limit:
                    # Чтение прерываем сразу: дочитывать то, что всё равно
                    # отвергнем, — подарок тому, кто шлёт большие файлы.
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"файл больше {size_limit} байт",
                    )
                buffer.write(chunk)

            if hasher.size == 0:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "пустой файл")

            sha256 = hasher.hexdigest
            _check_idempotency_key(idempotency_key, sha256)

            probe = await self._lookup_cache(sha256, request)
            if probe.result is not None:
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
        return await self._dispatch(
            sha256=pseudo, ref=request.source, size=request.source.size or 0, request=request
        )

    def _resolve_profile(self, request: ScanRequest) -> str:
        policy = self._state.policies.for_tenant(request.tenant)
        return (request.profile or policy.default_profile).value

    async def _lookup_cache(self, sha256: str, request: ScanRequest) -> CacheProbe:
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
        logger.info("полный кэш-хит", extra={"verdict": result.verdict.value})
        return CacheProbe(result=result)

    @staticmethod
    def _observe_verdict(
        result: ScanResult,
        request: ScanRequest,
        profile: str,
        cached: CachedStructural | None,
        elapsed_s: float,
    ) -> None:
        """Время до вердикта, а не латентность API.

        Меряется здесь, а не в middleware: middleware видит длительность
        запроса, включая чтение тела, и не отличает ответ из кэша от полного
        прохода.
        """
        current = metrics()
        current.scans.labels(
            verdict=result.verdict.value,
            tenant=tenant_label(request.tenant),
            mode=request.mode.value,
        ).inc()
        current.verdict_seconds.labels(
            profile=profile, cached=str(cached is not None).lower()
        ).observe(elapsed_s)

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
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "слишком много одновременных проверок",
                headers={"Retry-After": "5"},
            )

        with (
            log_context(scan_id=scan_id, sha=short(sha256), tenant=request.tenant),
            # Корневой спан скана. Имя файла и полный sha256 в атрибуты не идут:
            # спан уезжает наружу и живёт там дольше лога.
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
                self._observe_verdict(result, request, profile.value, cached, elapsed_s)
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
