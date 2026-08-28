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

from vscommon.keys import KEY_ID_HEADER, AccessKey
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
