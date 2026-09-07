"""Настраивает приёмник стенда: MinIO по умолчанию или чужое хранилище.

Зачем параметризация. MinIO проверяет нашу логику, но не проверяет **чужой
S3**: подпись, регион, поведение при отказе в правах у каждого провайдера свои.
Разница вылезает не в коде, а на первой выгрузке в боевой бакет — то есть
там, где её дороже всего находить.

Поэтому стенд один, а приёмников два. Умолчание — MinIO: быстро, герметично,
годится для каждого push. Переменные окружения переключают его на настоящее
хранилище, и такой прогон идёт отдельной задачей по расписанию: недоступный
внешний сервис не должен красить сборку в тот же цвет, что сломанный код.

    E2E_SINK_ENDPOINT=https://storage.yandexcloud.net \\
    E2E_SINK_BUCKET=vulnscan-e2e \\
    E2E_SINK_REGION=ru-central1 \\
    E2E_SINK_ACCESS_KEY=... E2E_SINK_SECRET_KEY=... \\
    E2E_SINK_PREFIX=run-1234/ \\
        python tests/e2e/configure_sink.py

Префикс задаётся снаружи и должен быть уникальным на прогон. Учётка сервиса —
только на запись, удалять за собой она не может; в боевом бакете уборку делает
правило жизненного цикла, а не тест.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "packages"))

CREDENTIALS_ID = "telegram-bot-1"

DEFAULTS = {
    "endpoint": "http://minio:9000",
    "bucket": "sink",
    "region": "us-east-1",
    "prefix": "telegram-bot-1/",
    "access_key": "dropuser",
    "secret_key": "dropuser-secret-32-symbols-long",
}


def setting(name: str) -> str:
    return os.environ.get(f"E2E_SINK_{name.upper()}", "") or DEFAULTS[name]


def main() -> int:
    delivery = {
        "backend": "s3",
        "endpoint": setting("endpoint"),
        "bucket": setting("bucket"),
        "prefix": setting("prefix"),
        "region": setting("region"),
        "credentials_id": CREDENTIALS_ID,
        "key_template": "{filename}-Проверено-{verdict}-{sha}{ext}",
    }

    # Разбираем настоящим загрузчиком сервиса. Стенд, поднятый с негодной
    # политикой, дал бы пустой приёмник — то есть отказ, неотличимый от
    # сломанной доставки, ради проверки которой всё и затевалось.
    from vscommon.delivery import parse_delivery
    from vscommon.models import TenantPolicy
    from vscommon.policy import build_policy

    parse_delivery(delivery)

    policies = {
        "telegram-bot": {
            "fail_mode": "suspicious",
            "block_threshold": 80,
            "suspicious_threshold": 30,
            "default_profile": "standard",
            "deliver_blocked": "strict",
            "delivery": delivery,
        }
    }
    policy = build_policy(TenantPolicy(), "telegram-bot", policies["telegram-bot"])
    if policy.delivery is None:
        raise SystemExit(f"политика стенда негодна: {policy.delivery_error}")

    (HERE / "config" / "policies.json").write_text(
        json.dumps(policies, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    secrets = HERE / "secrets"
    secrets.mkdir(exist_ok=True)
    target = secrets / "delivery.json"
    target.write_text(
        json.dumps(
            {
                CREDENTIALS_ID: {
                    "access_key": setting("access_key"),
                    "secret_key": setting("secret_key"),
                }
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    target.chmod(0o600)

    # Ключи в вывод не идут: он попадает в лог конвейера, а лог переживает
    # прогон и виден каждому, у кого есть доступ к репозиторию.
    print(
        f"приёмник: {delivery['endpoint']}/{delivery['bucket']}/{delivery['prefix']} "
        f"(учётка {setting('access_key')[:4]}…)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
