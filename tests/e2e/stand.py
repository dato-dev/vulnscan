"""Обвязка сквозного прогона: подпись, отправка файла, ожидание объектов.

Отдельно от `conftest.py`, потому что оттуда имена не импортируются:
conftest — точка расширения pytest, а не библиотека.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
GATEWAY = os.environ.get("E2E_GATEWAY", "http://localhost:18080")
MINIO = os.environ.get("E2E_MINIO", "http://localhost:19000")

KEY_ID = "telegram-bot-1"
TENANT = "telegram-bot"
SINK_BUCKET = os.environ.get("E2E_SINK_BUCKET") or "sink"
SINK_PREFIX = os.environ.get("E2E_SINK_PREFIX") or "telegram-bot-1/"

# Адрес приёмника ГЛАЗАМИ ТЕСТА. Сервис ходит по внутреннему имени `minio`,
# тест — снаружи; для внешнего хранилища адрес один и тот же.
SINK_ENDPOINT = os.environ.get("E2E_SINK_ENDPOINT") or MINIO
SINK_REGION = os.environ.get("E2E_SINK_REGION") or "us-east-1"

# Чем тест ЧИТАЕТ приёмник. У сервиса учётка другая, с правами только на
# запись: смешав их, прогон подтверждал бы работу с правами, которых в бою
# не будет.
READER_KEY = os.environ.get("E2E_READER_ACCESS_KEY") or "minioadmin"
READER_SECRET = os.environ.get("E2E_READER_SECRET_KEY") or "minioadmin"

# Учётка самого сервиса — её проверяют на недостаточность прав.
SERVICE_KEY = os.environ.get("E2E_SINK_ACCESS_KEY") or "dropuser"
SERVICE_SECRET = os.environ.get("E2E_SINK_SECRET_KEY") or "dropuser-secret-32-symbols-long"

EXTERNAL = bool(os.environ.get("E2E_SINK_ENDPOINT"))
"""Приёмник — настоящее чужое хранилище, а не MinIO стенда."""

SKIP_REASON = (
    "стенд не поднят — запустите его: "
    "docker compose -f tests/e2e/docker-compose.yml up -d --build --wait"
)


def secret() -> str:
    keys = json.loads((HERE / "config" / "keys.json").read_text(encoding="utf-8"))
    return keys[KEY_ID]["secret"]


def ready() -> bool:
    try:
        with urllib.request.urlopen(f"{GATEWAY}/readyz", timeout=2) as response:
            return response.status == 200
    except Exception:
        return False


def sign(body: bytes) -> dict[str, str]:
    """Подпись запроса ключом тенанта.

    Считается здесь, а не импортом из `vscommon`: сквозной прогон проверяет
    сервис снаружи, глазами клиента. Взяв нашу же функцию, мы проверили бы её
    саму на себе, и расхождение формата с документацией осталось бы незаметным.
    """
    timestamp = str(int(time.time()))
    mac = hmac.new(secret().encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return {
        "X-Vulnscan-Key": KEY_ID,
        "X-Vulnscan-Timestamp": timestamp,
        "X-Vulnscan-Signature": f"sha256={mac.hexdigest()}",
    }


def upload(content: bytes, filename: str, wait_ms: int = 9000) -> dict[str, Any]:
    """Отправляет файл так же, как это делает клиент: multipart и подпись."""
    boundary = "----vse2e"
    meta = json.dumps({"filename": filename, "wait_ms": wait_ms}).encode()
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
            b"Content-Type: application/pdf\r\n\r\n",
            content,
            f"\r\n--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="meta"\r\n\r\n',
            meta,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    # Подпись загрузки считается по каноническому запросу без тела: читать тело
    # до аутентификации нельзя, иначе нагрузка уже принята.
    timestamp = str(int(time.time()))
    canonical = f"POST\n/v1/scan\n{KEY_ID}".encode()
    mac = hmac.new(secret().encode(), f"{timestamp}.".encode() + canonical, hashlib.sha256)

    request = urllib.request.Request(
        f"{GATEWAY}/v1/scan",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Vulnscan-Key": KEY_ID,
            "X-Vulnscan-Timestamp": timestamp,
            "X-Vulnscan-Signature": f"sha256={mac.hexdigest()}",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def wait_for(sink: Any, predicate: Any, timeout_s: float = 60.0) -> list[str]:
    """Ждёт появления объектов в приёмнике.

    Доставка асинхронная: ответ клиенту отдаётся раньше выгрузки. Ожидание с
    опросом, а не фиксированная пауза, — иначе прогон был бы либо медленным,
    либо плавающим.
    """
    deadline = time.time() + timeout_s
    seen: list[str] = []
    while time.time() < deadline:
        page = sink.list_objects_v2(Bucket=SINK_BUCKET, Prefix=SINK_PREFIX)
        seen = [item["Key"] for item in page.get("Contents", [])]
        if predicate(seen):
            return seen
        time.sleep(1.0)
    return seen
