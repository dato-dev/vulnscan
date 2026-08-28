"""Реестр политик тенантов.

Политика — серверная конфигурация. Единственное место, где решается, что делать
при сбое проверки и где проходят пороги скоринга. Клиент на неё не влияет.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vscommon.config import CommonSettings
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
                        overrides[tenant] = TenantPolicy.model_validate(
                            {**default.model_dump(), **payload, "tenant": tenant}
                        )
                    logger.info("политики тенантов загружены", extra={"tenants": len(overrides)})
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
                overrides[tenant] = TenantPolicy.model_validate(
                    {**base.model_dump(), **payload, "tenant": tenant}
                )
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
