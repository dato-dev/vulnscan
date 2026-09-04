"""Выключатель отдельного правила: откат без выката (M7.2).

Зачем. Правило, дающее массовые ложные срабатывания, надо убрать **сейчас**, а
не после сборки образа и раскатки. До сих пор единственным способом было
поправить файл правил и дождаться `reload_interval_s` на всех воркерах — то
есть починка требовала доступа к тому, что смонтировано в контейнеры, и
человека, который знает, куда именно.

Здесь другое: имя правила кладётся в Redis, воркеры перестают учитывать его
совпадения на ближайшей перезагрузке конфигурации. Файлы правил при этом не
трогаются — их приводят в порядок отдельно и без спешки.

Ограничения те же, что у списка доверенных файлов, и по той же причине — это
механизм **ослабления** проверки:

* автор и причина обязательны;
* каждое выключение пишется в лог;
* сколько правил выключено, видно метрикой и панелью.

Чего здесь намеренно нет — срока жизни. У записи в списке доверенных он есть:
она разрешает один файл, и мир вокруг меняется. Выключенное правило —
наоборот: его выключили, потому что оно ошибается, и автоматически включить
его обратно значит вернуть ровно ту аварию, из-за которой выключали. Забытое
выключение ловится не таймером, а тем, что оно на виду.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time

from pydantic import BaseModel, Field
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

DISABLED_KEY = "rules:disabled"
"""Ключ общий: набор правил — свойство установки, а не клиента.

Тенанту нельзя выключать правила: он выключил бы их себе, а платит за это
не он. Если правило ошибается на потоке одного клиента, лечится это весами
(`weight_overrides`) или записью в списке доверенных, а не отключением детекта.
"""


class DisabledRule(BaseModel):
    rule: str
    reason: str = Field(min_length=8)
    author: str = Field(min_length=2)
    disabled_at: float = Field(default_factory=time.time)

    @property
    def days(self) -> int:
        """Сколько правило уже выключено. Растущее число — повод вернуться."""
        return int((time.time() - self.disabled_at) / 86400)


class RulesControl:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def disable(self, entry: DisabledRule) -> DisabledRule:
        await self._redis.hset(DISABLED_KEY, entry.rule, entry.model_dump_json())
        logger.warning(
            "правило выключено вручную",
            extra={"rule": entry.rule, "author": entry.author, "reason": entry.reason},
        )
        return entry

    async def enable(self, rule: str, author: str) -> bool:
        removed = await self._redis.hdel(DISABLED_KEY, rule)
        if removed:
            logger.warning("правило снова включено", extra={"rule": rule, "author": author})
        return bool(removed)

    async def disabled(self) -> frozenset[str]:
        """Имена выключенных правил. Читается воркером на каждой перезагрузке."""
        return frozenset(await self._redis.hkeys(DISABLED_KEY))

    async def entries(self) -> list[DisabledRule]:
        """Записи целиком — для отчёта: кто, когда и зачем."""
        found = []
        for raw in (await self._redis.hgetall(DISABLED_KEY)).values():
            try:
                found.append(DisabledRule.model_validate_json(raw))
            except ValueError:
                logger.warning("битая запись выключенного правила, пропускаю")
        return sorted(found, key=lambda entry: entry.disabled_at)


SERVER_FIELDS = frozenset({"disabled_at"})
"""Проставляется сервером: иначе давность выключения назначал бы тот, кто его
и выполняет, — а именно по ней записи и пересматривают."""


def entry_from_request(payload: dict[str, object]) -> DisabledRule:
    allowed = set(DisabledRule.model_fields) - SERVER_FIELDS
    return DisabledRule.model_validate({k: v for k, v in payload.items() if k in allowed})


def fingerprint(disabled: frozenset[str]) -> str:
    """Отпечаток набора выключенных правил.

    Входит в версию правил, а значит в ключ структурного кэша. Иначе
    выключение правила не обесценило бы записи, снятые при включённом: файл,
    проверенный час назад, продолжал бы отдаваться с признаком, которого
    больше не существует. Ровно тот способ, которым в этом проекте уже
    несколько раз протухали кэшированные факты.
    """
    if not disabled:
        # Пустой набор — обычное состояние, и метка для него должна быть
        # короткой и стабильной: она попадает в каждый ключ кэша.
        return "on"
    joined = ",".join(sorted(disabled)).encode()
    return "off" + hashlib.sha256(joined).hexdigest()[:8]


def audit_line(entry: DisabledRule) -> str:
    return json.dumps(
        {"rule": entry.rule, "author": entry.author, "reason": entry.reason, "days": entry.days},
        ensure_ascii=False,
    )
