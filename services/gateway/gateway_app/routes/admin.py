"""Заведение тенантов и ключей (ROADMAP M8.7).

Раньше новая команда означала ssh, редактор и перезапуск — то есть окно, в
которое сервис не принимает файлы, ради добавления строки.

Все ручки требуют административного ключа. Обычный ключ тенанта сюда не
проходит: иначе клиент выписывал бы себе новые ключи и менял себе политику,
а это ровно тот `fail-open` полем, который мы убирали.
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from vscommon.keys import MIN_SECRET_LEN, AccessKey
from vscommon.provisioning import generate_secret

from ..auth import require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin", tags=["admin"])


class IssueKeyRequest(BaseModel):
    tenant: str = Field(min_length=1, max_length=64)
    key_id: str = Field(min_length=3, max_length=64)
    callback_hosts: list[str] = Field(default_factory=list)
    """Куда этому тенанту разрешено слать коллбэк. Пусто — коллбэки запрещены."""


class IssueKeyResponse(BaseModel):
    key_id: str
    tenant: str
    secret: str
    """Показывается ОДИН раз. Сервис хранит его, но повторно не отдаёт."""


class TenantPolicyPatch(BaseModel):
    """Только то, что тенанту можно настраивать.

    Режим отказа и пороги остаются серверной политикой — их правит
    администратор, а не сам тенант.
    """

    block_threshold: int | None = Field(default=None, ge=1, le=1000)
    suspicious_threshold: int | None = Field(default=None, ge=1, le=1000)
    default_profile: str | None = None
    fail_mode: str | None = None
    rate_limit_per_min: int | None = Field(default=None, ge=1)
    max_concurrent_scans: int | None = Field(default=None, ge=1)


def _store(request: Request):
    return request.app.state.vs.tenants


@router.post("/keys", response_model=IssueKeyResponse, status_code=status.HTTP_201_CREATED)
async def issue_key(
    request: Request,
    body: IssueKeyRequest,
    admin: AccessKey = Depends(require_admin),
) -> IssueKeyResponse:
    """Выпускает ключ. Секрет генерируется сервером и показывается один раз.

    Принимать секрет от клиента нельзя: присланный мог бы оказаться коротким,
    повторно использованным или подсмотренным.
    """
    store = _store(request)
    if body.key_id in await store.all_keys():
        raise HTTPException(status.HTTP_409_CONFLICT, "ключ с таким идентификатором уже есть")

    secret = generate_secret()
    await store.put_key(
        body.key_id,
        body.tenant,
        secret,
        callback_hosts=tuple(h.lower() for h in body.callback_hosts),
    )
    await request.app.state.vs.reload_keys()
    logger.info(
        "ключ выпущен",
        extra={"key_id": body.key_id, "tenant": body.tenant, "кем": admin.key_id},
    )
    return IssueKeyResponse(key_id=body.key_id, tenant=body.tenant, secret=secret)


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    request: Request, key_id: str, admin: AccessKey = Depends(require_admin)
) -> None:
    """Отзывает ключ. Действует сразу, без перезапуска сервиса."""
    if key_id == admin.key_id:
        # Иначе администратор одним запросом отрезает себе доступ.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "нельзя отозвать собственный ключ")

    if not await _store(request).revoke_key(key_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ключ не найден")
    await request.app.state.vs.reload_keys()
    logger.info("ключ отозван", extra={"key_id": key_id, "кем": admin.key_id})


@router.get("/keys")
async def list_keys(
    request: Request, admin: AccessKey = Depends(require_admin)
) -> dict[str, object]:
    """Состав реестра без секретов.

    Секрет не отдаётся даже администратору: он показан один раз при выпуске, и
    ручка, отдающая ключи списком, превратила бы одну утечку во все сразу.
    """
    keys = await _store(request).all_keys()
    return {
        "keys": [
            {
                "key_id": key.key_id,
                "tenant": key.tenant,
                "disabled": key.disabled,
                "callback_hosts": list(key.callback_hosts),
            }
            for key in sorted(keys.values(), key=lambda k: k.key_id)
        ]
    }


@router.put("/tenants/{tenant}/policy", status_code=status.HTTP_204_NO_CONTENT)
async def set_policy(
    request: Request,
    tenant: str,
    body: TenantPolicyPatch,
    admin: AccessKey = Depends(require_admin),
) -> None:
    """Меняет политику тенанта без правки файла и перезапуска."""
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    if not patch:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "пустое изменение")

    await _store(request).put_policy(tenant, patch)
    await request.app.state.vs.reload_policies()
    logger.info("политика изменена", extra={"tenant": tenant, "кем": admin.key_id})


@router.get("/tenants")
async def list_tenants(
    request: Request, admin: AccessKey = Depends(require_admin)
) -> dict[str, object]:
    store = _store(request)
    return {"tenants": list(await store.tenants()), "policies": await store.all_policies()}


@router.get("/policies/{tenant}")
async def effective_policy(
    request: Request, tenant: str, admin: AccessKey = Depends(require_admin)
) -> dict[str, object]:
    """Какая политика ДЕЙСТВУЕТ для тенанта прямо сейчас.

    Заведено после того, как настройка доставки трижды подряд не применялась и
    каждый раз это выяснялось чтением логов: политика, названная по
    идентификатору ключа; ссылка на несуществующую учётку; блок `delivery`,
    негодный для старого образа. Все три выглядят одинаково — сервис работает,
    файлы не приходят.

    Отдаёт не файл, а **разобранное** состояние: то, что видит gateway после
    загрузки. Файл на диске и действующая политика — разные вещи, и расходятся
    они молча: тенант без записи получает умолчания, негодный блок `delivery`
    оставляет пороги в силе и отключает выгрузку.

    Здесь же пример имени объекта. Вопрос «как будут называться мои файлы»
    иначе проверяется только отправкой файла и походом в бакет.
    """
    policy = request.app.state.vs.policies.for_tenant(tenant)
    known = tenant in {key.tenant for key in request.app.state.vs.keys.all_keys()}

    delivery: dict[str, object] | None = None
    if policy.delivery is not None:
        sample = policy.delivery.object_name(
            scan_id="0" * 32,
            sha256="0" * 64,
            verdict="clean",
            ext=".pdf",
            when=time.time(),
            filename="пример",
        )
        delivery = {
            "bucket": policy.delivery.bucket,
            "prefix": policy.delivery.prefix,
            "endpoint": policy.delivery.endpoint,
            "credentials_id": policy.delivery.credentials_id,
            "key_template": policy.delivery.key_template,
            # Полный ключ, как он ляжет в бакет, — вместе с префиксом.
            "пример_ключа": policy.delivery.key_for(sample),
            # Учётные данные лежат у notifier, и gateway их не видит. Сказать
            # «ключ на месте» отсюда нельзя — это проверяет `make config-check`.
            "хранит_имя_файла": policy.delivery.needs_filename,
        }

    logger.info("запрошена действующая политика", extra={"tenant": tenant, "кем": admin.key_id})
    return {
        "tenant": tenant,
        # Главный вопрос при разборе: применилась запись или взяли умолчания.
        "своя_политика": policy.tenant == tenant,
        "есть_ключи": known,
        "block_threshold": policy.block_threshold,
        "default_profile": policy.default_profile.value,
        "deliver_blocked": policy.deliver_blocked,
        "delivery": delivery,
        # Пусто — блок либо годен, либо не задан. Непусто — задан и сломан:
        # выгрузки не будет, а всё остальное работает.
        "delivery_error": policy.delivery_error,
    }


__all__ = ["MIN_SECRET_LEN", "router"]
