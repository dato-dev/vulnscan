"""Реестр политик тенантов.

Политика — серверная конфигурация. Единственное место, где решается, что делать
при сбое проверки и где проходят пороги скоринга. Клиент на неё не влияет.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vscommon.config import CommonSettings
from vscommon.delivery import DeliveryError, parse_delivery
from vscommon.limits import MAX_UPLOAD_BYTES
from vscommon.models import CdrProfile, FailMode, TenantPolicy


def upload_limit_for(policy: TenantPolicy) -> int:
    """Свой предел размера у тенанта, но не выше общего.

    Общий лимит — жёсткая граница: он защищает не тенанта от себя, а сервис
    от любого входа.
    """
    if policy.max_upload_bytes:
        return min(policy.max_upload_bytes, MAX_UPLOAD_BYTES)
    return MAX_UPLOAD_BYTES


logger = logging.getLogger(__name__)


def build_policy(base: TenantPolicy, tenant: str, payload: dict[str, object]) -> TenantPolicy:
    """Собирает политику тенанта поверх базовой.

    Блок `delivery` разбирается отдельно и строго, а не вместе с остальным. У
    `TenantPolicy` мягкий разбор: неизвестные поля отбрасываются, и это
    правильно — так клиент не подсунет себе `on_timeout: fail-open`. Но для
    приёмника мягкость означала бы, что опечатка в имени поля превращается в
    «доставка не настроена», и файлы перестают появляться в ящике при
    исправном с виду сервисе.

    Публичная намеренно: этой же функцией проверяет файл `deploy/configure.py`.
    Своя копия правил в мастере разошлась бы с загрузчиком и начала одобрять
    то, что сервис отвергнет, — или наоборот, как и случилось при первой
    попытке: мастер объявлял негодной всю политику там, где сервис сохранял
    пороги и помечал сломанным только приёмник.

    Поэтому негодный блок не отбрасывается и не роняет остальную политику: он
    запоминается как `delivery_error`. Пороги тенанта остаются в силе —
    заменить их умолчаниями из-за опечатки в адресе означало бы ослабить
    проверку там, где сломана выдача.
    """
    merged = {**base.model_dump(), **payload, "tenant": tenant}

    described = merged.pop("delivery", None)
    merged["delivery"] = None
    merged["delivery_error"] = ""

    policy = TenantPolicy.model_validate(merged)
    if described is None:
        return policy

    try:
        policy.delivery = parse_delivery(described)
    except DeliveryError as exc:
        policy.delivery_error = str(exc)
        logger.error(
            "приёмник тенанта описан негодно, доставка выполняться не будет",
            extra={"tenant": tenant, "причина": str(exc)},
        )
    return policy


class PolicyRegistry:
    def __init__(
        self,
        default: TenantPolicy,
        overrides: dict[str, TenantPolicy],
        degraded: bool = False,
    ) -> None:
        self._default = default
        self._overrides = overrides
        self.degraded = degraded
        """Файл политик задан, но прочитать его не удалось.

        Сервис продолжает работать на значениях по умолчанию — падать в цикл
        перезапуска из-за конфигурации нельзя. Но тенант, которому настроили
        более строгую политику, получает обычную, поэтому это видно в /readyz
        и логируется как ошибка.
        """

    def for_tenant(self, tenant: str | None) -> TenantPolicy:
        if tenant is None:
            return self._default
        return self._overrides.get(tenant, self._default)

    @classmethod
    def load(
        cls, settings: CommonSettings, managed: dict[str, dict[str, object]] | None = None
    ) -> PolicyRegistry:
        """Дефолт из окружения, переопределения — из файла и из хранилища.

        `managed` — то, что заведено через административный API. Оно
        перекрывает файл: изменить политику через API должно получаться и
        тогда, когда для тенанта есть запись в `policies.json`.
        """
        default = TenantPolicy(
            fail_mode=FailMode(settings.default_fail_mode),
            block_threshold=settings.default_block_threshold,
            suspicious_threshold=settings.default_suspicious_threshold,
            default_profile=CdrProfile(settings.default_cdr_profile),
            shadow_mode=settings.default_shadow_mode,
        )

        overrides: dict[str, TenantPolicy] = {}
        degraded = False

        if settings.policy_file:
            path = Path(settings.policy_file)
            if not path.is_file():
                # Отдельный случай от «файл битый»: политик просто нет. Так же
                # выглядит промах bind-mount — Docker подменяет отсутствующий
                # файл каталогом.
                logger.warning(
                    "файл политик не найден, работаем на значениях по умолчанию",
                    extra={"path": str(path), "is_dir": path.is_dir()},
                )
            else:
                try:
                    raw = json.loads(path.read_text())
                    for tenant, payload in raw.items():
                        overrides[tenant] = build_policy(default, tenant, payload)
                    # Приёмники считаем отдельной цифрой, и это не украшение
                    # строки. «Доставка не настроена» — штатное состояние, оно
                    # нигде не логируется и ни во что не попадает: воркер
                    # молча не ставит задание, notifier молча ничего не ждёт,
                    # бакет остаётся пустым. Отличить это от поломки можно
                    # было только руками через `redis-cli XINFO GROUPS`.
                    #
                    # Ноль здесь при настроенном приёмнике означает ровно одно:
                    # блок `delivery` лежит не у того тенанта. Так уже было
                    # дважды — политику заводили под идентификатор ключа
                    # (`telegram-bot-1`) вместо имени тенанта.
                    with_delivery = sum(1 for p in overrides.values() if p.delivery is not None)
                    broken = sum(1 for p in overrides.values() if p.delivery_error)
                    logger.info(
                        "политики тенантов загружены",
                        extra={
                            "tenants": len(overrides),
                            "с_приёмником": with_delivery,
                            "приёмник_негоден": broken,
                        },
                    )
                except Exception:
                    degraded = True
                    overrides.clear()
                    logger.exception(
                        "файл политик не читается: тенанты получат политику "
                        "по умолчанию, проверьте конфигурацию"
                    )

        for tenant, payload in (managed or {}).items():
            base = overrides.get(tenant, default)
            try:
                overrides[tenant] = build_policy(base, tenant, payload)
            except Exception:
                # Одна негодная запись не должна ронять политики остальных.
                logger.exception(
                    "негодная политика из хранилища, оставляю прежнюю",
                    extra={"tenant": tenant},
                )

        if default.shadow_mode:
            # Блокировок нет вовсе: об этом должно быть видно в логе, иначе
            # режим легко забыть выключенным после обкатки.
            logger.warning("ТЕНЕВОЙ РЕЖИМ: вердикты считаются, но не применяются")

        if default.fail_mode is FailMode.FAIL_OPEN:
            # Это осознанный выбор оператора, но он должен быть виден в логах.
            logger.warning("политика по умолчанию работает в режиме fail-open")

        return cls(default=default, overrides=overrides, degraded=degraded)
