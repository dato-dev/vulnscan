"""Контракт стадии конвейера."""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vscommon.models import Finding, ScanFacts, ScanJob
from vscommon.weights import WeightTable

from ..archive import Member, UnpackBudget

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ScanContext:
    """Общее состояние прохода конвейера. Стадии читают и дополняют его."""

    job: ScanJob
    path: Path
    detected_mime: str | None = None
    detected_ext: str | None = None
    findings: list[Finding] = field(default_factory=list)
    engines: dict[str, Any] = field(default_factory=dict)
    weights: WeightTable = field(default_factory=WeightTable)
    """Сколько весит признак, решает таблица, а не стадия."""

    failed_stages: set[str] = field(default_factory=set)
    """Стадии, не доведённые до конца: упали или не уложились в таймаут.

    Балл за это начислять недостаточно — он тонет под порогом. Полнота
    покрытия проверяется отдельно, см. `scoring.coverage_incomplete`.
    """
    encrypted: bool = False
    """Содержимое недоступно без пароля. Владельческий пароль сюда не входит:
    такой документ читается и проверяется как обычный."""

    supported: bool = True

    budget: UnpackBudget | None = None
    """Бюджет распаковки всего дерева (M6.1). Один объект на загруженный файл:
    вложение получает бюджет контейнера, а не новый."""

    depth: int = 0
    """Уровень вложенности: корень — ноль."""

    members: list[Member] = field(default_factory=list)
    """Что распаковать и проверить после стадий. Заполняет разбор архива."""

    def add(
        self,
        stage: str,
        code: str,
        detail: str | None = None,
        *,
        weight_key: str | None = None,
    ) -> None:
        """Стадия сообщает, что нашла. Вес и severity подставляет таблица.

        `weight_key` нужен там, где код признака формируется динамически:
        у YARA имя правила уникально, а вес берётся по его тегу.
        """
        if any(f.code == code for f in self.findings):
            # Один код — один признак. Иначе две проверки, независимо нашедшие
            # одно и то же свойство файла, удваивают его вес в скоринге.
            return

        rule = self.weights.rule_for(weight_key or code)
        self.findings.append(
            Finding(
                stage=stage,
                code=code,
                severity=rule.severity,
                score=rule.score,
                detail=detail,
            )
        )

    def adopt(self, child: ScanContext, label: str) -> None:
        """Признаки вложения становятся признаками контейнера (M6.2).

        Без этого архив с вредоносным PDF внутри получал бы `clean`: сам
        архив ничем не плох, плохо его содержимое. Переносится всё, что
        влияет на вердикт, — и признаки, и то, что проверить не удалось:
        непроверенное вложение делает непроверенным весь архив.

        Балл признака не пересчитывается — вложение считалось той же
        таблицей весов. Повторный код не удваивается, как и у одного файла:
        десять одинаковых документов в архиве — не десятикратная улика.
        """
        for finding in child.findings:
            if any(own.code == finding.code for own in self.findings):
                continue
            detail = f"{label}: {finding.detail}" if finding.detail else label
            self.findings.append(finding.model_copy(update={"detail": detail}))
        self.failed_stages |= child.failed_stages
        self.encrypted = self.encrypted or child.encrypted
        self.supported = self.supported and child.supported

    def facts(self) -> ScanFacts:
        """Срез, которого достаточно для вердикта и для кэша."""
        return ScanFacts(
            findings=list(self.findings),
            detected_mime=self.detected_mime,
            encrypted=self.encrypted,
            supported=self.supported,
            failed_stages=set(self.failed_stages),
        )

    def current_score(self) -> int:
        return min(100, sum(f.score for f in self.findings))


class Stage(abc.ABC):
    """Стадия возвращает признаки, но никогда не вердикт (см. CLAUDE.md)."""

    name: str

    @abc.abstractmethod
    def run(self, ctx: ScanContext) -> None:
        """Блокирующая работа. Вызывается через asyncio.to_thread."""

    def safe_run(self, ctx: ScanContext) -> bool:
        """Обёртка: исключение стадии не роняет скан, а становится признаком."""
        try:
            self.run(ctx)
        except Exception:
            logger.exception("стадия упала", extra={"stage": self.name})
            ctx.failed_stages.add(self.name)
            ctx.add(self.name, "STAGE_FAILED", detail=f"стадия {self.name} завершилась с ошибкой")
            return False
        return True
