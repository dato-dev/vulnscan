"""Аутентификация входящих запросов.

Тенант выводится **из ключа** и ниоткуда больше. Раньше он приходил заголовком
при одном общем секрете: любой, кто мог обратиться к сервису, называл себя кем
угодно и получал чужую политику вместе с порогами и режимом отказа.

Две схемы подписи, потому что задачи разные:

- ручки с JSON-телом подписывают тело целиком;
- загрузка файла подписывает **канонический запрос без тела**.

Второе — осознанный размен. Подписать тело multipart можно только прочитав его,
а читать тело до аутентификации нельзя: тогда нагрузка уже принята, и проверка
частоты теряет смысл. Целостность файла при этом обеспечивает TLS (M8.10), а
подпись доказывает, кто отправитель. Тот же приём, что и `UNSIGNED-PAYLOAD` у
облачных провайдеров.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from vscommon.keys import KEY_ID_HEADER, AccessKey, origin_allowed
from vscommon.signing import (
    MAX_SKEW_S,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    canonical_request,
)

from .config import settings

logger = logging.getLogger(__name__)


async def require_key(request: Request) -> AccessKey:
    """Аутентификация загрузки файла. Тело не читается.

    Возвращает ключ; тенант берётся из него. Заголовок с именем тенанта на
    выбор политики больше не влияет.
    """
    return await _authenticate(request, body=None)


TICKET_HEADER = "X-Vulnscan-Ticket"
ORIGIN_HEADER = "Origin"


def _own_origin(request: Request) -> str:
    """Origin самого сервиса — тот, с которого отдан документ фрейма.

    Берётся из заголовка `Host`, а не из настройки: за обратным прокси адрес
    задаёт он, и зашитое значение разошлось бы с действительностью ровно там,
    где это труднее всего заметить.
    """
    host = request.headers.get("host", "")
    return f"{request.url.scheme}://{host}".rstrip("/").lower() if host else ""


async def require_site_key(request: Request) -> AccessKey:
    """Публичный ключ сайта плюс разрешённый `Origin` (M12.3).

    Единственное, что этим ключом можно сделать, — получить талон. Подписи тут
    нет и быть не может: ключ лежит открыто в HTML, и «секрет» у него знает
    каждый посетитель.

    Отсюда же следует, чего эта проверка НЕ даёт. `Origin` ставит браузер, и
    вне браузера он подделывается свободно. Проверка защищает от того, что
    чужой сайт вставит ваш ключ к себе и будет расходовать вашу квоту; от
    скрипта, который шлёт запросы напрямую, защищают только квоты (M12.5).
    Считать её защитой от подделки нельзя.
    """
    key_id = request.headers.get(KEY_ID_HEADER, "").strip()
    origin = request.headers.get(ORIGIN_HEADER, "")

    registry = request.app.state.vs.keys
    if registry.degraded:
        logger.error("реестр ключей недоступен, запрос отклонён")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "аутентификация временно недоступна"
        )

    key = registry.get(key_id) if key_id else None

    # Origin принимается в двух случаях, и второй неочевиден.
    #
    # 1. Адрес из списка ключа — прямой вызов со страницы сайта, кросс-доменно.
    #
    # 2. НАШ СОБСТВЕННЫЙ адрес — запрос пришёл из документа фрейма. Фрейм
    #    живёт на нашем origin, и обращение к `/v1/tickets` для него
    #    same-origin: браузер поставит наш адрес, а не адрес сайта.
    #
    #    Доверие здесь опирается не на заголовок, а на `frame-ancestors`:
    #    загрузиться этот документ мог только на странице из списка ключа, и
    #    проверяет это браузер. Без второй ветки виджет не работает вовсе —
    #    ровно то, на чём он и споткнулся при первом же запуске.
    from_our_frame = bool(origin) and origin.rstrip("/").lower() == _own_origin(request)

    if key is None or not key.public or not (from_our_frame or origin_allowed(key, origin)):
        # Одна ветка на три случая: ключа нет, ключ не публичный, origin чужой.
        # Разделять их в ответе — подсказывать, какой из них исправить.
        logger.warning(
            "ключ сайта отклонён",
            extra={"key_id": key_id, "origin_known": bool(origin)},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "ключ сайта недействителен")

    request.state.access_key = key
    request.state.origin = origin
    return key


async def require_key_or_ticket(request: Request) -> AccessKey:
    """Загрузка: либо подпись, либо одноразовый талон (M12.2).

    Талон — предмет, который можно отдать в браузер: им нельзя ни прочитать
    результат, ни скачать копию, ни загрузить второй файл. Поэтому он принят
    ЗДЕСЬ и только здесь; на остальных ручках заголовок с талоном просто не
    смотрят, и предъявивший его получит обычное «запрос не подписан».

    Порядок проверки важен: сначала подпись. Иначе клиент с валидной подписью,
    случайно приславший протухший талон, получил бы отказ вместо загрузки.
    """
    if request.headers.get(KEY_ID_HEADER, "").strip():
        return await _authenticate(request, body=None)

    token = request.headers.get(TICKET_HEADER, "").strip()
    if not token:
        return await _authenticate(request, body=None)

    ticket = await request.app.state.vs.tickets.redeem(token)
    if ticket is None:
        # Причина не уходит в ответ: «не существовал», «истёк» и «уже погашен»
        # для предъявителя одно и то же, а различать их — значит подсказывать.
        logger.warning("талон отклонён", extra={"path": request.url.path})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "талон недействителен")

    # Отключённый ключ реестр не возвращает — это его правило, и второй
    # проверки здесь нет намеренно: два места, решающих одно, расходятся.
    # Следствие важное: отзыв ключа гасит и выданные им талоны сразу, а не
    # «примерно скоро», когда истечёт последний.
    key = request.app.state.vs.keys.get(ticket.key_id)
    if key is None:
        logger.warning("талон выдан ключом, которого больше нет", extra={"key_id": ticket.key_id})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "талон недействителен")

    request.state.access_key = key
    request.state.ticket = ticket
    return key


async def require_signed_body(request: Request) -> bytes:
    """Возвращает сырое тело, предварительно проверив подпись по нему."""
    body = await request.body()
    if not settings.require_signature:
        # Послабление для разработки. В проде включение подписи обязательно,
        # и это проверяется на старте.
        return body
    await _authenticate(request, body=body)
    return body


async def require_signed_ops(request: Request) -> bytes:
    """То же, но проверка обязательна всегда.

    Служебные ручки отдают метаданные карантина, поэтому dev-послабление
    `REQUIRE_SIGNATURE=false` на них не распространяется.
    """
    body = await request.body()
    await _authenticate(request, body=body)
    return body


async def ops_scope(request: Request) -> str | None:
    """Чьи служебные данные вправе видеть вызывающий (M7.7).

    `None` — все: так отвечает только административный ключ. Обычному ключу
    возвращается его тенант, и ручка обязана этим ограничиться.

    Зачем понадобилось. Подписи для служебных ручек хватало любой, а отдают
    они разбор карантина, список доверенных и учёт теневого режима. Читать
    там нечего только на одном тенанте: `scan_id` и ключи объектов соседей,
    авторы и причины их разрешений — это рассказ о чужом потоке документов.
    Хуже того, `POST /v1/ops/allowlist` принимал `tenant: "*"`, то есть любой
    клиент мог снять блокировку с файла сразу для всех.
    """
    key = key_of(request)
    if key is None:
        # Сюда попадают только после `require_signed_ops`, который без ключа
        # не пропускает. Отсутствие ключа значит, что порядок зависимостей
        # сломали — и тогда сузить видимость некуда, кроме «ничего».
        logger.error("служебная ручка без проверенного ключа: порядок зависимостей")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "запрос не подписан")
    return None if key.admin else key.tenant


async def _authenticate(request: Request, body: bytes | None) -> AccessKey:
    if not settings.require_signature and body is None:
        # В dev загрузка без подписи допустима; тенант берётся из умолчания.
        return AccessKey(key_id="dev", tenant=settings.dev_tenant, secret="")

    key_id = request.headers.get(KEY_ID_HEADER, "").strip()
    timestamp = request.headers.get(TIMESTAMP_HEADER, "")
    signature = request.headers.get(SIGNATURE_HEADER, "")

    if not key_id or not timestamp or not signature:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "запрос не подписан")

    registry = request.app.state.vs.keys
    if registry.degraded:
        # Реестр ключей не прочитан. Пускать всех на умолчаниях нельзя:
        # умолчание в аутентификации — это дыра.
        logger.error("реестр ключей недоступен, запрос отклонён")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "аутентификация временно недоступна"
        )

    payload = (
        body if body is not None else canonical_request(request.method, request.url.path, key_id)
    )
    key, check = registry.check(key_id, payload, timestamp, signature)
    if key is None:
        # В ответ причина не уходит: клиенту незачем знать, ключа нет или
        # подпись не сошлась. В лог — обязана: без неё расхождение часов между
        # площадками выглядит как неверный ключ, и разбираться можно часами.
        logger.warning(
            "запрос отклонён при проверке подписи",
            extra={
                "path": request.url.path,
                "key_id": key_id,
                "причина": check.reason.value,
                "расхождение_с": check.skew_s,
                "окно_с": MAX_SKEW_S,
            },
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "подпись неверна")

    request.state.access_key = key
    return key


async def require_admin(request: Request) -> AccessKey:
    """Административная ручка. Обычный ключ тенанта сюда не проходит.

    Иначе клиент выписывал бы себе новые ключи и менял себе политику — тот же
    `fail-open` полем в запросе, только окольным путём.
    """
    key = await _authenticate(request, body=await request.body())
    if not key.admin:
        # `404`, а не `403`: незачем подтверждать существование ручки тому,
        # у кого нет на неё прав.
        logger.warning(
            "попытка обратиться к административной ручке обычным ключом",
            extra={"key_id": key.key_id, "tenant": key.tenant},
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, "не найдено")
    return key


def key_of(request: Request) -> AccessKey | None:
    """Ключ, которым аутентифицирован запрос, если он был."""
    return getattr(request.state, "access_key", None)


def tenant_of_request(request: Request) -> str | None:
    """Тенант запроса. Из ключа, не из заголовка и не из тела."""
    key = key_of(request)
    return key.tenant if key is not None else None
