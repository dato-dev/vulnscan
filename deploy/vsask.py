"""Подписанный запрос к служебным ручкам сервиса.

Зачем это существует. Все ручки `/v1/ops` и `/v1/admin` требуют подписи —
иначе разбор карантина и список доверенных были бы доступны каждому, кто
дотянулся до порта. Но обратная сторона в том, что **обратиться к ним обычным
`curl` невозможно**, и оператор в разгар разбора остаётся без инструмента:
сервис отвечает «запрос не подписан», и на этом всё.

Секрет берётся из `keys.json` по идентификатору ключа и в командную строку не
попадает: аргументы процесса видны в `ps` любому на машине, а история shell
переживает сессию.

    python deploy/vsask.py /v1/admin/policies/telegram-bot
    python deploy/vsask.py /v1/ops/dlq --key admin-1 --url http://scan.example:8080

Подписывается тело запроса, а для GET оно пустое, — та же схема, что у
`require_admin` в gateway. Схема подписи загрузки файла другая (канонический
запрос без тела), и здесь она не нужна: файлы этим скриптом не отправляют.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages"))

if sys.version_info < (3, 12):  # noqa: UP036 — запускают чем угодно, см. ниже
    # Та же ловушка, что и у `configure.py`: системный python3 бывает старым, а
    # ошибка импорта изнутри vscommon читается как «пакета нет».
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    sys.stderr.write(
        f"нужен Python 3.12, запущен {version}.\n"
        "Запускайте окружением репозитория: .venv/bin/python deploy/vsask.py ...\n"
    )
    raise SystemExit(2)

try:
    from vscommon.keys import KEY_ID_HEADER
    from vscommon.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign
except ImportError as exc:  # pragma: no cover — проверяется глазами, не тестом
    sys.stderr.write(
        f"не найден пакет vscommon ({exc}).\n"
        "Подпись считается теми же функциями, что и в сервисе: своя копия\n"
        "разошлась бы с ним, и запросы начали бы отвергаться без объяснения.\n"
    )
    raise SystemExit(2) from None

DEFAULT_CONFIG = ROOT / "deploy" / "config"


def pick_key(keys: dict, wanted: str | None) -> tuple[str, str]:
    """Ключ для подписи: указанный или единственный административный.

    Автовыбор только когда админский ключ один. Два — и угадывать нельзя:
    запрос уйдёт от чужого имени, а в аудите останется не тот, кто спрашивал.
    """
    if wanted:
        entry = keys.get(wanted)
        if entry is None:
            raise SystemExit(f"в keys.json нет ключа «{wanted}»")
        return wanted, entry["secret"]

    admins = [
        (key_id, entry["secret"])
        for key_id, entry in keys.items()
        if not key_id.startswith("_") and entry.get("admin") and not entry.get("disabled")
    ]
    if not admins:
        raise SystemExit(
            "административного ключа нет. Заведите его:\n"
            "  python deploy/configure.py keys add\n"
            "и ответьте «да» на вопрос про административный ключ.\n"
            "Обычным ключом тенанта служебные ручки отвечают «не найдено»."
        )
    if len(admins) > 1:
        names = ", ".join(key_id for key_id, _ in admins)
        raise SystemExit(f"административных ключей несколько ({names}) — укажите --key")
    return admins[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", help="путь ручки, например /v1/admin/policies/telegram-bot")
    parser.add_argument("--url", default="http://localhost:8080", help="адрес gateway")
    parser.add_argument("--key", help="идентификатор ключа; по умолчанию единственный админский")
    parser.add_argument("--config-dir", default=str(DEFAULT_CONFIG))
    parser.add_argument("--method", default="GET")
    parser.add_argument("--data", help="тело запроса для POST")
    args = parser.parse_args()

    keys_file = Path(args.config_dir) / "keys.json"
    if not keys_file.is_file():
        raise SystemExit(f"нет файла ключей: {keys_file}")

    key_id, secret = pick_key(json.loads(keys_file.read_text(encoding="utf-8")), args.key)
    body = (args.data or "").encode()
    timestamp, signature = sign(secret, body)

    request = urllib.request.Request(
        f"{args.url.rstrip('/')}{args.path}",
        data=body if args.data else None,
        method=args.method,
        headers={
            KEY_ID_HEADER: key_id,
            TIMESTAMP_HEADER: timestamp,
            SIGNATURE_HEADER: signature,
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read().decode()
    except urllib.error.HTTPError as exc:
        # Тело ответа важнее кода: сервис объясняет отказ именно там.
        sys.stderr.write(f"{exc.code} {exc.reason}\n{exc.read().decode(errors='replace')}\n")
        if exc.code == 404:
            sys.stderr.write(
                "\n404 на служебной ручке чаще всего означает не «нет такой», а\n"
                "«ключ не административный»: существование ручки не подтверждают\n"
                "тому, у кого нет на неё прав.\n"
            )
        return 1
    except urllib.error.URLError as exc:
        raise SystemExit(f"сервис недоступен: {exc.reason}") from None

    try:
        print(json.dumps(json.loads(payload), ensure_ascii=False, indent=2))
    except ValueError:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
