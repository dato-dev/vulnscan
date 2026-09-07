"""Выгрузка обезвреженной копии в хранилище клиента (M14.1, M14.3).

Живёт в notifier, а не в воркере, и это не вопрос удобства. У воркера нет
сетевого выхода наружу: сеть объявлена `internal: true`, и дыра в парсере при
таком раскладе означает «упал контейнер», а не «есть канал наружу». Выгрузка
оттуда разобрала бы ровно тот периметр, ради которого воркер и заперт.

Рядом с каждым файлом уезжает **манифест** — и он же уезжает вместо файла,
когда выгружать нечего. Без него приёмник отвечает на вопрос «что стало с
документом» молчанием, а молчание означает одновременно «заблокирован», «ещё
в работе» и «сервис сломался». Различить их по содержимому ящика невозможно,
и разбираться приходится у нас в логах — то есть там, куда владелец документа
не смотрит.

Манифест нужен и для прошедших файлов. Вердикт `suspicious` тоже отдаётся:
сервис детектит, а решение принимает клиент. Без манифеста чистый и
подозрительный документы в ящике неразличимы.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from vscommon.delivery import Delivery, DeliveryCredentials
from vscommon.models import ObjectRef

logger = logging.getLogger(__name__)

MANIFEST_SUFFIX = ".vulnscan.json"
"""Манифест лежит рядом с файлом и назван по нему.

Отдельный каталог развёл бы файл и решение о нём по разным местам, а
сопоставлять их пришлось бы по имени — то есть тем же способом, только вручную.
"""

OUTCOMES = ("delivered", "manifest_only", "retry", "lost")
"""Исходы выгрузки — закрытый список меток метрики (M14.5).

`delivered` — уехали файл и манифест. `manifest_only` — файл не прошёл
проверку, уехало решение о нём; это успешная доставка, а не отказ, и путать их
на графике нельзя: рост здесь означает выросшую блокировку.
`retry` — приёмник не ответил, повтор отложен. `lost` — не доехало совсем.

Список закрытый, потому что метка из открытого множества — это ряд на каждое
значение, а метрики оседают в Prometheus на весь срок хранения.
"""

MANIFEST_VERSION = 1
"""Версия формата манифеста. Читать его будут чужие скрипты, и молчаливая смена
структуры сломала бы их так же, как переименование кода признака."""


class DropoffError(Exception):
    """Выгрузка не удалась. Повтор решает вызывающий."""


def manifest_for(payload: str, task_name: str, delivered: bool) -> dict[str, Any]:
    """Что положить рядом с файлом. Содержимого документа здесь нет.

    `delivered` отвечает на главный вопрос ящика: файл рядом есть или его не
    будет. Выводить это из наличия соседнего объекта нельзя — «объекта нет»
    означает и «не прошёл», и «выгрузка ещё идёт».
    """
    try:
        result = json.loads(payload)
    except ValueError:
        # Результат собирали мы сами, и разобрать его обязаны. Но манифест
        # важнее подробностей: без него в ящике не останется вообще ничего.
        logger.exception("не разобрать результат для манифеста")
        result = {}

    return {
        "manifest_version": MANIFEST_VERSION,
        "scan_id": result.get("scan_id", ""),
        "object": task_name if delivered else None,
        "delivered": delivered,
        "verdict": result.get("verdict", "unknown"),
        "status": result.get("status", ""),
        "score": result.get("score", 0),
        "sha256": result.get("sha256", ""),
        "findings": [
            {"code": finding.get("code", ""), "severity": finding.get("severity", "")}
            for finding in result.get("findings", [])
        ],
        "sanitized_sha256": (result.get("sanitized") or {}).get("sanitized_sha256", ""),
        "profile": (result.get("sanitized") or {}).get("profile", ""),
        "shadow": result.get("shadow", False),
    }


class Dropoff:
    """Клиент чужого хранилища. Создаётся на задание: приёмники у всех разные.

    Кэшировать клиента по `credentials_id` было бы дешевле, но цена ошибки
    выше выигрыша: клиент держит учётные данные, а задания разных тенантов
    идут через один процесс. Стоимость создания — доли миллисекунды против
    сетевой выгрузки файла.
    """

    def __init__(self, destination: Delivery, credentials: DeliveryCredentials) -> None:
        import boto3  # локальный импорт: тестам boto3 не нужен

        self._destination = destination
        self._client = boto3.client(
            "s3",
            endpoint_url=destination.endpoint or None,
            aws_access_key_id=credentials.access_key,
            aws_secret_access_key=credentials.secret_key,
            region_name=destination.region or None,
        )

    def put_file(self, ref: ObjectRef, source: Path, name: str) -> str:
        """Выгружает файл. Возвращает ключ объекта в приёмнике."""
        key = self._destination.key_for(name)
        try:
            with source.open("rb") as stream:
                self._client.upload_fileobj(
                    stream,
                    self._destination.bucket,
                    key,
                    ExtraArgs={"ContentType": ref.content_type or "application/octet-stream"},
                )
        except Exception as exc:
            raise DropoffError(f"не удалось выгрузить объект: {exc}") from exc
        return key

    def put_manifest(self, name: str, manifest: dict[str, Any]) -> str:
        """Кладёт манифест рядом с файлом."""
        key = self._destination.key_for(name + MANIFEST_SUFFIX)
        body = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
        try:
            self._client.put_object(
                Bucket=self._destination.bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
            )
        except Exception as exc:
            raise DropoffError(f"не удалось выгрузить манифест: {exc}") from exc
        return key
