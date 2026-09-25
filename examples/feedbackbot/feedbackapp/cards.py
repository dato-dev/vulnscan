"""Карточка обращения в S3: кто прислал и чем кончилась проверка.

Сам файл кладёт сканер — доставкой в хранилище тенанта (M14), пересобранную
копию, а не оригинал. Бот пишет рядом только карточку. Сопоставляются они по
`scan_id`, а на случай ответа из кэша — по `sha256` (см. README).

Карточка по одной на обращение, а не на файл: один и тот же бланк могут
прислать двое, и вторая карточка не должна затирать первую.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

logger = logging.getLogger(__name__)

CARD_VERSION = 1
"""Версия формата. Карточки читают чужие скрипты, и молчаливая смена
структуры сломала бы их так же, как переименование поля в API."""


@dataclass(frozen=True, slots=True)
class Submission:
    full_name: str
    user_id: int
    username: str | None
    chat_id: int
    file_name: str
    file_size: int
    sha256: str
    scan_id: str
    verdict: str
    score: int
    rebuilt_from_blocked: bool = False
    """Копия пересобрана из заблокированного файла и лежит в `_rebuilt/`."""


class CardStore(Protocol):
    async def put(self, submission: Submission) -> str: ...


def card_for(submission: Submission, submission_id: str, at: datetime) -> dict[str, Any]:
    return {
        "card_version": CARD_VERSION,
        "submission_id": submission_id,
        "received_at": at.isoformat(timespec="seconds"),
        "full_name": submission.full_name,
        "telegram": {
            "user_id": submission.user_id,
            "username": submission.username,
            "chat_id": submission.chat_id,
        },
        "file": {
            "name": submission.file_name,
            "size": submission.file_size,
            "sha256": submission.sha256,
        },
        "scan": {
            "scan_id": submission.scan_id,
            "verdict": submission.verdict,
            "score": submission.score,
            # Где искать копию: пересобранные из заблокированного сканер
            # кладёт в `_rebuilt/` внутри префикса доставки, а не рядом с
            # обычными — чтобы их нельзя было принять за обычные.
            "rebuilt_from_blocked": submission.rebuilt_from_blocked,
        },
    }


def key_for(prefix: str, submission: Submission, submission_id: str, at: datetime) -> str:
    """`cards/2026/09/24/<scan_id>--<submission_id>.json`.

    `scan_id` в начале имени — чтобы по нему находить карточку листингом, без
    чтения всех подряд.
    """
    return f"{prefix}{at:%Y/%m/%d}/{submission.scan_id}--{submission_id}.json"


class S3Cards:
    def __init__(
        self,
        endpoint: str,
        region: str,
        bucket: str,
        prefix: str,
        access_key_id: str,
        secret_access_key: str,
    ) -> None:
        import boto3

        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )
        self._bucket = bucket
        self._prefix = prefix

    async def put(self, submission: Submission) -> str:
        """Номер обращения. Исключение — карточка не сохранена."""
        submission_id = uuid.uuid4().hex[:12]
        at = datetime.now(UTC)
        body = json.dumps(card_for(submission, submission_id, at), ensure_ascii=False, indent=2)
        await asyncio.to_thread(
            self._client.put_object,
            Bucket=self._bucket,
            Key=key_for(self._prefix, submission, submission_id, at),
            Body=body.encode(),
            ContentType="application/json; charset=utf-8",
        )
        return submission_id
