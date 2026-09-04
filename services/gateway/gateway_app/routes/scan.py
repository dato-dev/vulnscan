"""Публичные эндпоинты сканирования."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from vscommon.cache import assemble, weights_key_for
from vscommon.callbacks import CallbackRejectedError, validate_callback
from vscommon.hashing import short
from vscommon.keys import AccessKey
from vscommon.models import ScanRequest, ScanResult, Verdict
from vscommon.policy import upload_limit_for

from ..auth import (
    ORIGIN_HEADER,
    require_key,
    require_key_or_ticket,
    require_signed_body,
    require_site_key,
)
from ..ingest import Ingestor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1", tags=["scan"])


def _seconds_until_utc_midnight() -> int:
    """Сколько ждать до обнуления суточной квоты.

    Считается по UTC, потому что по UTC считается и сама квота. Отдавать в
    `Retry-After` минуту, как при обычном превышении частоты, здесь неверно:
    через минуту счётчик будет тем же, и клиент сходит впустую.
    """
    now = datetime.now(UTC)
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((midnight - now).total_seconds()))


def _state(request: Request):
    return request.app.state.vs


@router.post("/scan", response_model=ScanResult)
async def scan_upload(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    meta: str = Form("{}"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    key: AccessKey = Depends(require_key_or_ticket),
) -> ScanResult:
    """Приём файла multipart.

    `meta` — JSON с полями `ScanRequest` (кроме `source`). Отдаёт `200` с готовым
    результатом, если воркер уложился в `wait_ms`, иначе `202` и результат придёт
    вебхуком на `callback_url`.

    Повторная отправка того же файла не запускает вторую проверку: и пока идёт
    первая, и после неё запрос получает тот же `scan_id`.
    """
    try:
        scan_request = ScanRequest.model_validate(json.loads(meta or "{}"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"некорректный meta: {exc}") from exc

    if scan_request.filename is None:
        scan_request.filename = file.filename
    if scan_request.declared_mime is None:
        scan_request.declared_mime = file.content_type

    # Тенант выводится ИЗ КЛЮЧА и перетирает всё, что прислал клиент. В его
    # политике лежат пороги и режим отказа: позволить выбирать её запросом —
    # это тот же `fail-open` полем, только этажом выше.
    scan_request.tenant = key.tenant
    scan_request.key_id = key.key_id

    # Адрес коллбэка проверяется ЗДЕСЬ, на приёме, а не при доставке: иначе
    # файл будет принят и проверен, а результат девать некуда.
    if scan_request.callback_url is not None:
        try:
            validate_callback(str(scan_request.callback_url), key.callback_hosts)
        except CallbackRejectedError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # Контекст трассировки клиента: без него дерево рвётся на HTTP-границе и
    # «что делал бот» и «что делал сервис» оказываются разными трейсами.
    ticket = getattr(request.state, "ticket", None)
    result, synchronous = await Ingestor(_state(request)).ingest_upload(
        file,
        scan_request,
        idempotency_key,
        request.headers.get("traceparent"),
        max_bytes=ticket.max_bytes if ticket is not None else None,
    )
    response.status_code = status.HTTP_200_OK if synchronous else status.HTTP_202_ACCEPTED

    if ticket is not None and not synchronous:
        # Загрузка из браузера не уложилась в отведённое время. Прочитать
        # вердикт фрейм не может — для этого нужна подпись, — а без ответа
        # посетитель остаётся с «ещё проверяется» навсегда.
        #
        # Выдаём предмет ровно на одно: наблюдать за ЭТИМ сканом. Ни вердикта
        # чужого скана, ни файла он не даёт. Заголовком, а не полем ответа:
        # `ScanResult` — публичная модель, и класть в неё то, что нужно одному
        # способу подключения, значит менять контракт ради частного случая.
        token, ttl = await _state(request).status_tickets.issue(result.scan_id, key.tenant)
        response.headers["X-Vulnscan-Status-Ticket"] = token
        response.headers["X-Vulnscan-Status-TTL"] = str(ttl)

    return result


@router.post("/tickets", status_code=status.HTTP_201_CREATED)
async def issue_ticket(request: Request, response: Response) -> dict[str, object]:
    """Выдаёт одноразовый талон на загрузку одного файла (M12.1, M12.3).

    Два пути получения, и оба ведут к одному предмету.

    **Подписанным запросом** — бэкенд сайта просит талон своим секретным
    ключом и отдаёт его в браузер. Секрет при этом остаётся на сервере.

    **Публичным ключом сайта** — запрос идёт прямо из браузера, ключ лежит в
    HTML, а вместо подписи проверяется `Origin`. Так работает виджет: сайту не
    нужен ни бэкенд, ни знание протокола.

    Талон не даёт ничего, кроме одной загрузки: ни чтения результата, ни
    скачивания обезвреженной копии.
    """
    if request.headers.get(ORIGIN_HEADER):
        # Есть Origin — значит запрос из браузера, и ключ должен быть
        # публичным. Пробовать сначала подпись здесь нельзя: браузер её не
        # поставит, и клиент получил бы отказ про подпись вместо внятного
        # ответа про ключ сайта.
        key = await require_site_key(request)
        origin = request.headers.get(ORIGIN_HEADER, "")
        # Ответ адресный: заголовок отдаётся тому origin, который проверен, а
        # не `*`. Со звёздочкой ответ прочитала бы любая страница.
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    else:
        await require_signed_body(request)
        key = request.state.access_key
        origin = ""

    state = _state(request)
    policy = state.policies.for_tenant(key.tenant)

    if key.public:
        # Два разных ограничения, и оба нужны (M12.5).
        #
        # Частота — по ИДЕНТИФИКАТОРУ КЛЮЧА, а не по тенанту: общее ведро
        # означало бы, что наплыв через виджет вытесняет собственные вызовы
        # сайта, то есть наша защита ломает клиента.
        rate = await state.rate_limiter.check(
            f"public:{key.key_id}", policy.public_rate_limit_per_min
        )
        if not rate.allowed:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "превышена частота выдачи талонов",
                headers={"Retry-After": str(rate.retry_after_s)},
            )

        # Суточная квота — про стоимость, а не про нагрузку. Шестьдесят
        # запросов в минуту это восемьдесят шесть тысяч файлов в сутки, и
        # ограничение частоты такой поток считает совершенно штатным.
        if not await state.quota.spend(key.key_id, policy.public_daily_tickets):
            logger.warning(
                "суточная квота публичного ключа исчерпана",
                extra={"key_id": key.key_id, "лимит": policy.public_daily_tickets},
            )
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "суточная квота исчерпана",
                # До полуночи UTC: раньше счётчик не обнулится, и предлагать
                # зайти через минуту значит звать на бесполезный круг.
                headers={"Retry-After": str(_seconds_until_utc_midnight())},
            )

    # Предел размера — из политики тенанта, а не из запроса. Клиент, способный
    # выписать себе талон на гигабайт, — это способ разорить владельца ключа.
    max_bytes = upload_limit_for(policy)

    ticket, ttl = await state.tickets.issue(
        tenant=key.tenant, key_id=key.key_id, max_bytes=max_bytes, origin=origin
    )
    logger.info(
        "выдан талон на загрузку",
        extra={
            "tenant": key.tenant,
            "ttl_s": ttl,
            "лимит_байт": max_bytes,
            "из_браузера": bool(origin),
        },
    )
    return {"ticket": ticket.token, "expires_in": ttl, "max_bytes": max_bytes}


@router.post("/scan/ref", response_model=ScanResult)
async def scan_by_ref(
    request: Request,
    response: Response,
    body: bytes = Depends(require_signed_body),
) -> ScanResult:
    """Приём по ссылке на объект в общем хранилище — без второй заливки тела."""
    try:
        scan_request = ScanRequest.model_validate_json(body)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    result, synchronous = await Ingestor(_state(request)).ingest_ref(
        scan_request, request.headers.get("traceparent")
    )
    response.status_code = status.HTTP_200_OK if synchronous else status.HTTP_202_ACCEPTED
    return result


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(
    request: Request, scan_id: str, key: AccessKey = Depends(require_key)
) -> ScanResult:
    """Polling для клиентов, которым неудобен вебхук.

    Задача, ушедшая в dead-letter, отдаётся здесь со статусом `manual_review`
    ещё неделю — 404 на неё был бы неотличим от «всё хорошо».
    """
    state = _state(request)
    await _require_owner(state, scan_id, key)
    result = await state.results.load_status(scan_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "скан не найден или устарел")
    return result


async def _require_owner(state: object, scan_id: str, key: AccessKey) -> None:
    """Скан принадлежит тенанту ключа — иначе его не существует.

    Отвечаем `404`, а не `403`: `403` подтвердил бы, что такой скан есть, и
    превратил бы ручку в способ проверять чужие идентификаторы.
    """
    if not await state.ownership.allows(scan_id, key.tenant):  # type: ignore[attr-defined]
        logger.warning("запрошен чужой скан", extra={"scan_id": scan_id, "tenant": key.tenant})
        raise HTTPException(status.HTTP_404_NOT_FOUND, "скан не найден или устарел")


@router.get("/scan/{scan_id}/clean")
async def download_clean(
    request: Request, scan_id: str, key: AccessKey = Depends(require_key)
) -> FileResponse:
    """Отдаёт обезвреженный файл.

    Хранилище наружу не светится: клиент получает артефакт только через
    сервис и только если проверка завершилась не вердиктом `malicious`.
    """
    state = _state(request)
    await _require_owner(state, scan_id, key)
    result = await state.results.load_status(scan_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "скан не найден или устарел")
    if result.sanitized is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"обезвреженного файла нет: вердикт {result.verdict.value}",
        )

    tmp_dir = Path(tempfile.mkdtemp(prefix="vsclean-"))
    dest = tmp_dir / Path(result.sanitized.ref.key).name
    await asyncio.to_thread(state.store.get_to_path, result.sanitized.ref, dest)

    return FileResponse(
        dest,
        media_type=result.sanitized.ref.content_type or "application/octet-stream",
        filename=dest.name,
        background=BackgroundTask(shutil.rmtree, tmp_dir, ignore_errors=True),
    )


@router.get("/lookup/{sha256}", response_model=ScanResult)
async def lookup(
    request: Request,
    sha256: str,
    profile: str = "standard",
    key: AccessKey = Depends(require_key),
) -> ScanResult:
    """Дешёвая проверка по хэшу до загрузки тела файла.

    Отвечает только при полном попадании в оба уровня кэша: без тела файла
    антивирус на свежих базах прогнать нельзя.
    """
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256.lower()):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "ожидается sha256 в hex")

    state = _state(request)
    digest = sha256.lower()
    policy = state.policies.for_tenant(key.tenant)

    structural = await state.structural.get(
        digest, profile, await state.rules_version(), weights_key_for(policy)
    )
    av = await state.av_cache.get(digest, await state.engine_version())
    if structural is None or av is None:
        logger.debug("lookup: промах", extra={"sha": short(digest)})
        raise HTTPException(status.HTTP_404_NOT_FOUND, "вердикт неизвестен")

    result = assemble(structural, av, policy)
    if result.verdict is Verdict.MALICIOUS and await state.allowlist.get(digest, key.tenant):
        # Отвечаем согласованно с тем, что получит реальный запрос на проверку.
        result.verdict = Verdict.SUSPICIOUS
        result.allowlisted = True
    return result
