"""Интерактивная настройка `keys.json`, `weights.json` и `policies.json`.

Три файла, которые правятся руками чаще всего, и три разных способа ошибиться
в них молча. Ключ с коротким секретом не загружается — но сервис при этом
стартует и просто не пускает владельца. Опечатка в коде признака даёт не
ошибку, а запасной вес. Битый `policies.json` не роняет gateway: он переводит
ВСЕХ тенантов на умолчания, и снаружи это выглядит как исправная работа.

Поэтому инструмент делает две вещи, а не одну:

1. спрашивает значения по одному, с объяснением, что параметр меняет, и
   принимает только допустимые;
2. перед тем как оставить правку, прогоняет файл **теми же загрузчиками, что
   и сервис** (`KeyRegistry.load`, `TenantPolicy.model_validate`). Не сошлось —
   файл возвращается в прежнее состояние.

Второе важнее первого. Свои правила проверки здесь заводить нельзя: разъехавшись
с загрузчиком, они начнут одобрять то, что сервис отвергнет, — а это ровно тот
класс ошибки, ради которого инструмент и написан.

Запуск:
    python deploy/configure.py                 # меню
    python deploy/configure.py keys add        # сразу команда
    python deploy/configure.py check           # только проверка, ничего не пишет
    python deploy/configure.py --config-dir ~/vulnscan/config keys list

Нужен исходный код репозитория: проверка опирается на `packages/vscommon`.
На сервере, куда скопирован только `deploy/`, инструмент не работает — правьте
конфигурацию в репозитории и копируйте `config/` целиком.

## Как добавить команду

Одна функция и один декоратор:

    @command("policy dump", "Политики тенантов", "выгрузить политику в JSON")
    def cmd_policy_dump(files: Files) -> None:
        tenant = choose("тенант", sorted(files.policies.load()))
        print(json.dumps(files.policies.load()[tenant], ensure_ascii=False, indent=2))

Команда сразу появляется в меню, в `--help` и в списке команд. Новый параметр —
это `Param(...)` в списке рядом с остальными: описание, допустимые значения и
разбор лежат в одном месте, а не растекаются по коду вопроса.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import secrets
import sys
import textwrap
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages"))

# Версия проверяется ДО импорта. Иначе `ImportError` из глубины vscommon
# приписывается отсутствию пакета, и оператор ищет несуществующую проблему:
# сообщение «не найден пакет vscommon» на старом Python врёт про причину.
if sys.version_info < (3, 12):  # noqa: UP036 — запускают чем угодно, см. ниже
    # Версия проверяется ДО импорта. Иначе `ImportError` из глубины vscommon
    # приписывается отсутствию пакета, и оператор ищет несуществующую проблему:
    # сообщение «не найден пакет vscommon» на старом Python врёт про причину.
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    sys.stderr.write(
        f"нужен Python 3.12, запущен {version}.\n"
        "Скорее всего сработал системный python3. Запускайте окружением репозитория:\n"
        "  .venv/bin/python deploy/configure.py ...\n"
        "или через make: make config-check\n"
        "Окружение создаётся `make venv` (нужен uv).\n"
    )
    raise SystemExit(2)

try:
    from vscommon.delivery import DeliveryError, parse_delivery
    from vscommon.keys import MIN_SECRET_LEN, KeyRegistry
    from vscommon.models import CdrProfile, FailMode, Severity, TenantPolicy
    from vscommon.policy import build_policy
    from vscommon.weights import DEFAULT_WEIGHTS
except ImportError as exc:  # pragma: no cover — проверяется глазами, не тестом
    sys.stderr.write(
        f"не найден пакет vscommon ({exc}).\n"
        "Инструмент проверяет файлы загрузчиками сервиса и без них работать не\n"
        "будет: собственные правила проверки разошлись бы с настоящими.\n"
        "Запускайте из репозитория: python deploy/configure.py\n"
    )
    raise SystemExit(2) from None

DEFAULT_CONFIG_DIR = ROOT / "deploy" / "config"

SERVICE_UID = 10001
"""Под каким пользователем работают контейнеры сервиса.

Из Dockerfile: `USER 10001`. Файл с правами `0600`, созданный кем-то другим,
сервису недоступен — и узнать об этом можно только по `503` на каждом
подписанном запросе. Автоматически это не проверяется: на macOS Docker
подменяет владельца при монтировании, и проверка врала бы на машине
разработчика.
"""

KEYS_MODE = 0o600
"""Файл ключей читает только владелец. Там секреты подписи, а не настройки."""

CONFIG_MODE = 0o644

_TTY = sys.stdout.isatty()


def _b(text: str) -> str:
    return f"\033[1m{text}\033[0m" if _TTY else text


def _d(text: str) -> str:
    return f"\033[2m{text}\033[0m" if _TTY else text


def _wrap(text: str, width: int = 72) -> list[str]:
    return [line for para in text.split("\n") for line in (textwrap.wrap(para, width) or [""])]


class AbortedError(Exception):
    """Оператор прервал ввод. Ни один файл не тронут."""


class BadValueError(ValueError):
    """Значение не годится. Текст показывается человеку как есть."""


# ─────────────────────────────── разбор ввода ───────────────────────────────
#
# Каждый разборщик возвращает готовое значение либо бросает BadValueError с
# объяснением. Объяснение пишется для того, кто настраивает сервис в три часа
# ночи, а не для того, кто писал этот файл.

Parser = Callable[[str], Any]

_TRUE = {"да", "д", "yes", "y", "true", "1", "+"}
_FALSE = {"нет", "н", "no", "n", "false", "0", "-"}


def p_bool(raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise BadValueError("нужно «да» или «нет»")


def p_int(low: int, high: int | None = None) -> Parser:
    def parse(raw: str) -> int:
        try:
            value = int(raw.strip().replace("_", "").replace(" ", ""))
        except ValueError:
            raise BadValueError("нужно целое число") from None
        if value < low or (high is not None and value > high):
            limit = f"{low}..{high}" if high is not None else f"не меньше {low}"
            raise BadValueError(f"вне допустимого диапазона ({limit})")
        return value

    return parse


_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "б": 1,
    "k": 1024,
    "kb": 1024,
    "к": 1024,
    "кб": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "м": 1024**2,
    "мб": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "г": 1024**3,
    "гб": 1024**3,
}


def p_bytes(raw: str) -> int:
    """Байты, но человеку разрешено писать «20MB»: 20971520 глазами не читается."""
    text = raw.strip().lower().replace(" ", "")
    match = re.fullmatch(r"(\d+)([a-zа-я]*)", text)
    if match is None:
        raise BadValueError("нужно число байт или размер вида 20MB")
    unit = _SIZE_UNITS.get(match.group(2))
    if unit is None:
        raise BadValueError("непонятная единица: допустимы B, KB, MB, GB")
    return int(match.group(1)) * unit


def show_bytes(value: int) -> str:
    if not value:
        return "0 (общий лимит)"
    if value >= 1024**2:
        return f"{value} ({value / 1024**2:.1f} МБ)"
    return str(value)


def p_choice(values: Sequence[str]) -> Parser:
    def parse(raw: str) -> str:
        value = raw.strip().lower()
        for allowed in values:
            if value == allowed.lower():
                return allowed
        raise BadValueError("допустимо только: " + ", ".join(values))

    return parse


def p_text(pattern: str | None = None, hint: str = "", min_len: int = 1) -> Parser:
    def parse(raw: str) -> str:
        value = raw.strip()
        if len(value) < min_len:
            raise BadValueError(f"не короче {min_len} символов")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            raise BadValueError(hint or "недопустимые символы")
        return value

    return parse


def p_secret(raw: str) -> str:
    value = raw.strip()
    if len(value) < MIN_SECRET_LEN:
        # Ровно та же граница, что и в загрузчике: короткий секрет перебирается,
        # и ключ с ним просто не загрузится.
        raise BadValueError(
            f"секрет короче {MIN_SECRET_LEN} символов — такой ключ сервис не примет"
        )
    return value


def p_list(item: Parser) -> Parser:
    def parse(raw: str) -> list[str]:
        parts = [chunk.strip() for chunk in re.split(r"[,\s]+", raw.strip()) if chunk.strip()]
        return [item(part) for part in parts]

    return parse


def p_host(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    if "://" in value or "/" in value:
        raise BadValueError(
            f"нужно имя хоста без схемы и пути: не «{raw}», а «bot» или «api.acme.tld»"
        )
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?::\d+)?", value) is None:
        raise BadValueError("непохоже на имя хоста")
    return value


def p_origin(raw: str) -> str:
    """Origin публичного ключа. Масок нет — и это не придирка разборщика.

    `*.example.com` превращает захват любого заброшенного поддомена в кражу
    ключа. Три адреса руками дешевле такого разбирательства.
    """
    value = raw.strip().rstrip("/")
    if "*" in value:
        raise BadValueError("маски не поддерживаются: перечислите адреса по одному")
    match = re.fullmatch(r"(https?)://([a-zA-Z0-9.-]+)(:\d+)?", value)
    if match is None:
        raise BadValueError("нужен адрес вида https://acme.tld или http://localhost:3000")
    if match.group(1) == "http" and match.group(2) not in {"localhost", "127.0.0.1"}:
        raise BadValueError("http допустим только для localhost: ключ уедет по открытому каналу")
    return value


CODE_RE = r"[A-Z][A-Z0-9_]*|YARA:[a-z0-9_]+"


def p_code(raw: str) -> str:
    value = raw.strip()
    if re.fullmatch(CODE_RE, value) is None:
        raise BadValueError("код пишется как PDF_LAUNCH либо как YARA:high для тега правила")
    return value


def p_scores(raw: str) -> dict[str, int]:
    """Переопределения весов тенанта: `PDF_LAUNCH=90, PDF_OBJSTM=0`."""
    result: dict[str, int] = {}
    for chunk in re.split(r"[,\s]+", raw.strip()):
        if not chunk:
            continue
        if "=" not in chunk:
            raise BadValueError(f"«{chunk}» — нужно КОД=БАЛЛ, например PDF_LAUNCH=90")
        code, _, score = chunk.partition("=")
        result[p_code(code)] = p_int(0, 100)(score)
    return result


def show_scores(value: dict[str, int]) -> str:
    return ", ".join(f"{code}={score}" for code, score in value.items()) if value else "—"


def p_delivery(raw: str) -> dict[str, str]:
    """Приёмник обезвреженных копий: `bucket=clean, credentials_id=team-drop`.

    Разбирается настоящим загрузчиком сервиса, а не копией формата. Копия
    разошлась бы с ним молча: мастер сохранял бы то, что сервис потом не
    прочитает, и узнать об этом можно было бы только по отсутствию файлов в
    приёмнике.
    """
    fields: dict[str, str] = {}
    for chunk in re.split(r"[,\s]+", raw.strip()):
        if not chunk:
            continue
        if "=" not in chunk:
            raise BadValueError(f"«{chunk}» — нужно ПОЛЕ=ЗНАЧЕНИЕ, например bucket=clean")
        name, _, value = chunk.partition("=")
        fields[name.strip()] = value.strip()

    try:
        parse_delivery(fields)
    except DeliveryError as exc:
        raise BadValueError(str(exc)) from None
    return fields


def show_delivery(value: dict[str, str] | None) -> str:
    if not value:
        return "— (копию забирают у нас)"
    return ", ".join(f"{name}={item}" for name, item in value.items())


# ─────────────────────────────── диалог ────────────────────────────────────

_MISSING = object()
_NO_EMPTY = object()


@dataclass(frozen=True, slots=True)
class Param:
    """Один вопрос: что настраиваем, что это меняет и что считается ответом.

    Описание живёт рядом с разбором намеренно. Разъехавшись, подсказка начинает
    объяснять не тот параметр, который спрашивают, — а замечают это позже всего.
    """

    name: str
    title: str
    allowed: str
    help: str
    parse: Parser
    default: Any = None
    render: Callable[[Any], str] = str
    empty: Any = _NO_EMPTY
    """Значение для ответа «-». Есть не у всех: очистить `tenant` нельзя."""


def read_line(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        raise AbortedError from None


def _explain(param: Param) -> None:
    print()
    print(f"  {_b(param.name)} — {param.title}")
    for line in _wrap(param.help):
        print(f"      {_d(line)}")
    tail = "; «-» — очистить" if param.empty is not _NO_EMPTY else ""
    print(f"      {_d('допустимо: ' + param.allowed + tail)}")


def ask(param: Param, current: Any = _MISSING) -> Any:
    """Спрашивает значение, пока не введут допустимое.

    `current` — то, что уже настроено: при правке существующей записи ответом
    по умолчанию должно быть текущее значение, а не заводское. Иначе Enter
    молча возвращает параметр к умолчанию.
    """
    fallback = param.default if current is _MISSING else current
    _explain(param)
    while True:
        shown = param.render(fallback) if fallback is not None else "не задано"
        raw = read_line(f"      [{shown}] > ").strip()
        if raw in {"q", "й"}:
            raise AbortedError
        if raw == "?":
            _explain(param)
            continue
        if raw == "-" and param.empty is not _NO_EMPTY:
            return param.empty
        if not raw:
            if fallback is None:
                print("      ✗ значение обязательно")
                continue
            return fallback
        try:
            return param.parse(raw)
        except BadValueError as exc:
            print(f"      ✗ {exc}")


def confirm(question: str, default: bool = True) -> bool:
    suffix = "[Да/нет]" if default else "[да/Нет]"
    while True:
        raw = read_line(f"  {question} {suffix} ").strip()
        if not raw:
            return default
        try:
            return p_bool(raw)
        except BadValueError as exc:
            print(f"  ✗ {exc}")


def choose(
    what: str,
    options: Sequence[str],
    allow_new: Parser | None = None,
) -> str:
    """Выбор из списка по номеру или по имени.

    `allow_new` — разборщик для имени, которого в списке ещё нет. Без него
    выбрать можно только существующее. Проверять новое имя обязательно:
    политика тенанта с опечаткой в названии не ошибка ни для одного
    загрузчика — она просто никогда ни к кому не применится.
    """
    if not options and allow_new is None:
        raise BadValueError(f"выбирать не из чего: {what} ещё не заведены")
    print()
    for number, option in enumerate(options, 1):
        print(f"    {number:>2}) {option}")
    hint = "номер, имя или новое имя" if allow_new else "номер или имя"
    while True:
        raw = read_line(f"  {what} ({hint}): ").strip()
        if raw in {"q", "й"} or not raw:
            raise AbortedError
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        if raw in options:
            return raw
        if allow_new is not None:
            try:
                return allow_new(raw)
            except BadValueError as exc:
                print(f"  ✗ {exc}")
                continue
        print("  ✗ такого нет в списке")


# ──────────────────────────── файлы конфигурации ────────────────────────────


@dataclass(frozen=True, slots=True)
class Store:
    """JSON-файл конфигурации. Запись атомарная, права выставляются явно.

    Атомарность здесь не украшение: файлы читает живой сервис — политики и веса
    перечитываются на ходу. Запись на месте означает окно, в котором сервис
    видит половину файла, объявляет конфигурацию битой и уводит всех тенантов
    на умолчания.
    """

    path: Path
    mode: int
    seed: dict[str, Any] | None = None
    """Чем наполнить файл, которого ещё нет: пояснение для того, кто откроет его руками."""

    def load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return dict(self.seed or {})
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BadValueError(f"{self.path} не читается: {exc}") from None
        if not isinstance(data, dict):
            raise BadValueError(f"{self.path}: ожидался объект, а не {type(data).__name__}")
        return data

    def snapshot(self) -> bytes | None:
        return self.path.read_bytes() if self.path.is_file() else None

    def restore(self, snapshot: bytes | None) -> None:
        if snapshot is None:
            self.path.unlink(missing_ok=True)
        else:
            self.path.write_bytes(snapshot)
            os.chmod(self.path, self.mode)

    def save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, self.mode)
        os.replace(tmp, self.path)


@dataclass(frozen=True, slots=True)
class Files:
    keys: Store
    policies: Store
    weights: Store


def files_at(config_dir: Path) -> Files:
    return Files(
        keys=Store(config_dir / "keys.json", KEYS_MODE, seed=KEYS_SEED),
        policies=Store(config_dir / "policies.json", CONFIG_MODE),
        weights=Store(config_dir / "weights.json", CONFIG_MODE, seed=WEIGHTS_SEED),
    )


KEYS_SEED: dict[str, Any] = {
    "_": [
        "Ключи доступа. Тенант выводится ИЗ КЛЮЧА и ниоткуда больше.",
        "Записи с подчёркивания в начале — комментарии, сервис их пропускает.",
        "Файл заполняется через deploy/configure.py; правка руками тоже допустима.",
    ]
}

WEIGHTS_SEED: dict[str, Any] = {
    "_": [
        "Переопределяет встроенные веса из packages/vscommon/weights.py.",
        "Кодов, которых здесь нет, правка не касается — они берутся из кода.",
    ]
}


def entries(data: dict[str, Any]) -> dict[str, Any]:
    """Записи без комментариев: ключи с подчёркивания сервис пропускает."""
    return {name: value for name, value in data.items() if not name.startswith("_")}


# ─────────────────────────────── проверка ───────────────────────────────────
#
# Проверяют загрузчики сервиса, а не этот файл. Своя копия правил однажды
# одобрит то, что сервис отвергнет, и разбираться с этим будут по симптому
# «ключ есть в файле, но не работает».


def verify_keys(path: Path) -> list[str]:
    if not path.is_file():
        return []
    registry = KeyRegistry.load(str(path))
    if registry.degraded:
        return [f"{path.name}: файл не читается загрузчиком сервиса"]
    expected = set(entries(json.loads(path.read_text(encoding="utf-8"))))
    rejected = expected - {key.key_id for key in registry.all_keys()}
    return [f"{path.name}: запись «{name}» отвергнута загрузчиком" for name in sorted(rejected)]


def verify_policies(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        return [f"{path.name}: не разбирается как JSON ({exc})"]
    problems: list[str] = []
    destinations: dict[tuple[str, str], str] = {}

    for tenant, payload in entries(raw).items():
        try:
            # Той же функцией, что и сервис. Своя проверка разошлась бы с ним:
            # первая версия объявляла негодной всю политику там, где сервис
            # сохраняет пороги и помечает сломанным только приёмник.
            policy = build_policy(TenantPolicy(), tenant, payload)
        except Exception as exc:
            first = str(exc).splitlines()[-1].strip()
            problems.append(f"{path.name}: политика «{tenant}» негодна — {first}")
            continue

        if policy.delivery_error:
            cause = policy.delivery_error.splitlines()[0]
            problems.append(f"{path.name}: приёмник «{tenant}» негоден — {cause}")
            continue
        if policy.delivery is None:
            continue

        problems.extend(_check_destination(path.name, tenant, policy.delivery, destinations))

    return problems


def _check_destination(
    where: str, tenant: str, delivery: Any, seen: dict[tuple[str, str], str]
) -> list[str]:
    """Приёмник разбирается загрузчиком, а тут проверяется его разграничение.

    Формально это годная конфигурация, поэтому загрузчик её принимает.
    Практически — способ смешать документы двух клиентов в одном каталоге и
    выдать учётную запись, которой можно писать в чужое.
    """
    problems: list[str] = []
    place = (delivery.bucket, delivery.prefix.strip("/"))

    if not delivery.prefix.strip("/"):
        problems.append(
            f"{where}: у приёмника «{tenant}» нет prefix — учётной записью можно "
            f"писать в весь бакет; префикс на тенанта ограничивает ущерб от её утечки"
        )

    neighbour = seen.get(place)
    if neighbour is not None:
        problems.append(
            f"{where}: «{tenant}» и «{neighbour}» пишут в один каталог "
            f"({delivery.bucket}/{place[1] or ''}) — документы двух клиентов смешаются"
        )
    seen[place] = tenant
    return problems


DELIVERY_SECRETS = Path("secrets") / "delivery.json"
"""Где лежат учётные данные приёмников — рядом с `config`, а не внутри него.

Каталог `config` монтируется в gateway, воркер и deepscan целиком. Ключ доступа
к чужому хранилищу в нём означал бы, что дыра в парсере даёт запись в
инфраструктуру клиента, — поэтому секреты живут отдельно и видны только
notifier.
"""


def _check_credentials(policies: Store) -> list[str]:
    """Ссылки `credentials_id` из политик разрешаются в файле секретов."""
    raw = entries(policies.load())
    wanted = {
        payload["delivery"]["credentials_id"]: tenant
        for tenant, payload in raw.items()
        if isinstance(payload.get("delivery"), dict)
        and isinstance(payload["delivery"].get("credentials_id"), str)
    }
    if not wanted:
        return []

    path = policies.path.parent.parent / DELIVERY_SECRETS
    if not path.is_file():
        example = path.with_name("delivery.example.json")
        hint = f"; образец рядом: {example}" if example.is_file() else ""
        return [
            f"приёмники настроены ({', '.join(sorted(wanted.values()))}), "
            f"а учётных данных нет: {path} отсутствует{hint}"
        ]

    try:
        known = set(entries(json.loads(path.read_text(encoding="utf-8"))))
    except ValueError as exc:
        return [f"{path.name}: не разбирается как JSON ({exc})"]

    return [
        f"{path.name}: нет записи «{name}» — на неё ссылается политика «{tenant}»"
        for name, tenant in sorted(wanted.items())
        if name not in known
    ]


def verify_weights(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        return [f"{path.name}: не разбирается как JSON ({exc})"]
    problems: list[str] = []
    for code, payload in entries(raw).items():
        if not isinstance(payload, dict):
            problems.append(f"{path.name}: у кода «{code}» ожидался объект со score и severity")
            continue
        try:
            p_int(0, 100)(str(payload.get("score")))
        except BadValueError as exc:
            problems.append(f"{path.name}: «{code}» — балл {exc}")
        try:
            Severity(payload.get("severity", "medium"))
        except ValueError:
            allowed = ", ".join(s.value for s in Severity)
            problems.append(f"{path.name}: «{code}» — severity не из списка ({allowed})")
    return problems


def apply(store: Store, data: dict[str, Any], verify: Callable[[Path], list[str]]) -> None:
    """Записать и проверить. Не сошлось — вернуть как было.

    Порядок именно такой: сначала запись, потом проверка настоящего файла.
    Проверять содержимое в памяти означало бы проверять не то, что прочтёт
    сервис, — мимо остались бы права доступа и сама запись на диск.
    """
    previous = store.snapshot()
    store.save(data)
    problems = verify(store.path)
    if problems:
        store.restore(previous)
        raise BadValueError("\n  ".join(["правка отменена, файл не изменён:", *problems]))
    print(f"\n  записано: {store.path}")


# ─────────────────────────── параметры: ключи ───────────────────────────────

KEY_ID = Param(
    "key_id",
    "идентификатор ключа",
    "буквы, цифры, «-», «_», «.»",
    "Приходит в заголовке X-Vulnscan-Key и попадает в логи. Секретом не "
    "является, поэтому называйте по владельцу: telegram-bot-1, acme-site-public. "
    "Тенант выводится из ключа, а не из заголовка запроса — переименование "
    "идентификатора требует правки на стороне клиента.",
    p_text(
        r"[A-Za-z0-9][A-Za-z0-9._-]*",
        "нельзя начинать с подчёркивания: такие записи сервис считает комментарием",
    ),
)

KEY_TENANT = Param(
    "tenant",
    "тенант, от имени которого работает ключ",
    "непустая строка",
    "Определяет, какая политика применится к запросу: пороги, режим отказа, "
    "лимиты. Заголовок с именем тенанта и поле tenant в теле игнорируются — "
    "иначе клиент выбирал бы себе пороги сам. У одного тенанта может быть "
    "несколько ключей: так их отзывают по одному.",
    p_text(r"[a-z0-9][a-z0-9._-]*", "строчные буквы, цифры, «-», «_», «.»"),
)

KEY_PUBLIC = Param(
    "public",
    "ключ сайта, лежащий открыто в HTML",
    "да / нет",
    "Публичный ключ умеет ровно одно: получить талон на загрузку для виджета. "
    "Подписать им запрос НЕЛЬЗЯ — его секрет знает каждый посетитель, и сервис "
    "отвергает такой ключ до сравнения подписи. Для серверной интеграции — «нет».",
    p_bool,
    default=False,
    render=lambda v: "да" if v else "нет",
)

KEY_ADMIN = Param(
    "admin",
    "административный ключ",
    "да / нет",
    "Заводит тенантов и выпускает другие ключи через API. Нужен одному-двум "
    "ключам на установку. Утечка такого ключа означает выпуск любых других, "
    "поэтому для обычной интеграции — «нет».",
    p_bool,
    default=False,
    render=lambda v: "да" if v else "нет",
)

KEY_CALLBACK_HOSTS = Param(
    "callback_hosts",
    "куда разрешено слать коллбэк",
    "имена хостов через запятую",
    "Адрес коллбэка приходит в запросе клиента, поэтому список обязателен: без "
    "него сервис становится посредником для обращений во внутреннюю сеть. "
    "Пусто — коллбэки этому ключу запрещены, результат забирают опросом. "
    "Указывается только имя хоста: bot, api.acme.tld — без схемы и пути.",
    p_list(p_host),
    default=[],
    render=lambda v: ", ".join(v) if v else "коллбэки запрещены",
    empty=[],
)

KEY_ORIGINS = Param(
    "origins",
    "с каких адресов принимать публичный ключ",
    "https://acme.tld через запятую",
    "Обязателен для ключа сайта: пустой список означает, что ключ не работает "
    "нигде. Сравнение точное, масок нет — «*.example.com» превратил бы захват "
    "любого заброшенного поддомена в кражу ключа. Проверка Origin защищает от "
    "вставки ключа на чужой сайт, но не от запросов мимо браузера: там заголовок "
    "подделывается, и от этого защищают квоты.",
    p_list(p_origin),
    render=lambda v: ", ".join(v) if v else "нигде не работает",
)

KEY_DISABLED = Param(
    "disabled",
    "ключ отозван",
    "да / нет",
    "Отзыв действует без перезапуска сервиса — реестр перечитывается на живом "
    "gateway. Запись остаётся в файле: удалённый ключ неотличим от «никогда не "
    "существовал», а при разборе инцидента разница важна.",
    p_bool,
    default=False,
    render=lambda v: "да" if v else "нет",
)


# ───────────────────────── параметры: политика тенанта ──────────────────────

POLICY_PARAMS: tuple[Param, ...] = (
    Param(
        "fail_mode",
        "вердикт, когда проверка НЕ СОСТОЯЛАСЬ",
        " | ".join(m.value for m in FailMode),
        "Отвечает на один вопрос: что считать результатом, если проверить не "
        "удалось — упал clamd, стадия не уложилась в таймаут, оборвался разбор. "
        "На уже найденное не влияет: /Launch останется malicious при любом режиме.\n"
        "fail-closed — считать вредоносным: когда пропущенный вредонос дороже "
        "отказа в обслуживании.\n"
        "suspicious — пометить подозрительным, решает клиент (умолчание).\n"
        "fail-open — считать чистым. Осмысленно только на обкатке в теневом "
        "режиме: на боевом потоке недоступный clamd превращает сервис в дорогой "
        "способ пересобирать файлы, ничего не проверяя, и клиент об этом не узнает.",
        p_choice([m.value for m in FailMode]),
        default=FailMode.SUSPICIOUS.value,
    ),
    Param(
        "block_threshold",
        "балл, с которого вердикт malicious",
        "1..100",
        "Сумма весов найденных признаков сравнивается с этим порогом. Снижение "
        "делает сервис строже и одновременно поднимает долю ложных срабатываний. "
        "Прежде чем менять, посмотрите реальный поток в теневом режиме: чаще "
        "помогает не порог, а вес конкретного признака — порог глушит всё сразу.",
        p_int(1, 100),
        default=80,
    ),
    Param(
        "suspicious_threshold",
        "балл, с которого вердикт suspicious",
        "1..100, ниже block_threshold",
        "Нижняя граница: до неё файл считается чистым. Между порогами — "
        "подозрительный: сервис не блокирует, но и не молчит.",
        p_int(1, 100),
        default=30,
    ),
    Param(
        "default_profile",
        "профиль CDR, если клиент не указал свой",
        " | ".join(p.value for p in CdrProfile),
        "На вердикт не влияет вовсе — только на то, что получит пользователь. "
        "Файл всегда собирается заново, ни один байт исходника не переносится.\n"
        "light — убирает JS и автозапуск, НО ОСТАВЛЯЕТ МЕТАДАННЫЕ: для потока "
        "сканов с персональными данными это утечка автора и организации.\n"
        "standard — плюс вложения, XFA и полная пересборка структуры (умолчание).\n"
        "strict — страницы растеризуются, из исходника не переносится ни один "
        "объект. Платите текстовым слоем: копировать и искать текст будет нельзя.",
        p_choice([p.value for p in CdrProfile]),
        default=CdrProfile.STANDARD.value,
    ),
    Param(
        "max_wait_ms",
        "потолок синхронного ожидания, мс",
        "0..10000",
        "Сколько gateway ждёт результат, прежде чем ответить 202 и дослать "
        "вердикт коллбэком. Больше — выше доля синхронных ответов и дольше "
        "занят обработчик запроса.",
        p_int(0, 10_000),
        default=2_000,
    ),
    Param(
        "shadow_mode",
        "теневой режим: проверять, но не действовать",
        "да / нет",
        "Вердикт остаётся честным, клиент по нему не блокирует. Нужен один раз — "
        "когда сервис ставят на реальный поток и надо узнать цену включения "
        "блокировок, не задев людей. Ранний выход при этом отключён, а "
        "заблокированное тоже пересобирается — иначе режим не покрывал бы как "
        "раз те случаи, ради которых нужен. Отчёт: GET /v1/ops/shadow.",
        p_bool,
        default=False,
        render=lambda v: "да" if v else "нет",
    ),
    Param(
        "rate_limit_per_min",
        "запросов в минуту",
        "целое, 0 — без ограничения",
        "Проверяется до чтения тела запроса: иначе нагрузка уже принята. "
        "Защищает сервис от одного клиента, но не защищает соседей от очереди — "
        "это делает max_concurrent_scans.",
        p_int(0),
        default=1_200,
    ),
    Param(
        "max_concurrent_scans",
        "проверок этого тенанта одновременно",
        "целое, 0 — без ограничения",
        "Именно этот лимит защищает латентность остальных: он ограничивает долю "
        "очереди, которую способен занять один клиент. Частота в минуту этого не "
        "делает — пачка тяжёлых PDF укладывается в любой лимит частоты.",
        p_int(0),
        default=64,
    ),
    Param(
        "max_upload_bytes",
        "свой предел размера файла",
        "байты или 20MB, 0 — общий лимит",
        "Выше общего лимита сервиса не поднимается: тот защищает не тенанта от "
        "себя, а сервис от любого входа. Имеет смысл занижать — чтобы клиент, "
        "присылающий только сканы паспортов, не мог прислать гигабайтный архив.",
        p_bytes,
        default=0,
        render=show_bytes,
    ),
    Param(
        "public_rate_limit_per_min",
        "талонов в минуту по публичному ключу сайта",
        "целое, 0 — без ограничения",
        "Считается по идентификатору ключа, а не по тенанту, и ведро отдельное "
        "от rate_limit_per_min. Общее означало бы, что наплыв через форму на "
        "сайте вытесняет вызовы его собственного бэкенда: наша защита от "
        "перегрузки ломала бы клиента ровно тогда, когда ему тяжелее всего.",
        p_int(0),
        default=60,
    ),
    Param(
        "public_daily_tickets",
        "талонов в сутки по публичному ключу",
        "целое, 0 — без счёта",
        "Это про стоимость, а не про нагрузку. Шестьдесят запросов в минуту — "
        "восемьдесят шесть тысяч файлов в сутки, и поток внутри лимита частоты "
        "выглядит штатным. Без потолка публичный ключ превращается в бесплатный "
        "антивирус за чужой счёт. Счёт по календарным суткам UTC.",
        p_int(0),
        default=5_000,
    ),
    Param(
        "widget_on_unavailable",
        "что делает виджет, когда проверка не состоялась",
        "block | mark",
        "block — файл к отправке не годится, поле очищается (умолчание: "
        "непроверенный файл не должен выглядеть проверенным). mark — файл "
        "остаётся помеченным непроверенным, решение принимает сайт. Настройка "
        "серверная: оставь мы выбор в JavaScript страницы, «не смогли проверить» "
        "рано или поздно стало бы «отправляем как есть», причём тихо.",
        p_choice(["block", "mark"]),
        default="block",
    ),
    Param(
        "deliver_blocked",
        "отдавать ли пересобранную копию ЗАБЛОКИРОВАННОГО файла",
        "never | strict",
        "never — не отдавать (умолчание). Мы нашли в файле что-то плохое, и "
        "отдать из него документ значит утверждать, что он теперь безопасен. "
        "Профили light и standard такого утверждения не выдерживают: они "
        "удаляют то, что мы ЗНАЕМ, а платим мы за ненайденное.\n"
        "strict — пересобрать растеризацией и отдать. Здесь утверждение "
        "держится: из исходника не остаётся ни одного объекта, поэтому оно не "
        "зависит от того, что в нём было. Цена — теряется текстовый слой, "
        "документ становится картинками; для договора обычно приемлемо, для "
        "файла, который дальше разбирают программой, — нет.\n"
        "Такие копии уезжают в отдельный каталог _rebuilt/ и помечены в "
        "манифесте: смешивать их с обычными нельзя, скрипт на стороне клиента "
        "обрабатывает каталог целиком и манифест у каждого файла не читает.",
        p_choice(["never", "strict"]),
        default="never",
    ),
    Param(
        "delivery",
        "куда складывать обезвреженную копию",
        "ПОЛЕ=ЗНАЧЕНИЕ через запятую, «-» — никуда",
        "Пусто — копию забирают у нас через API, и через сутки её не станет. "
        "Заполнено — копия уезжает в ваше хранилище, и хранить её перестаём мы.\n"
        "Обязательны bucket и credentials_id. Необязательны endpoint, region и "
        "prefix — свой префикс на тенанта стоит задать: он ограничивает, куда "
        "можно писать, если учётку скомпрометируют.\n"
        "credentials_id — ССЫЛКА на учётные данные, а не они сами. Ключи лежат "
        "в отдельном файле, который читает только notifier: этот каталог видят "
        "и воркеры, а им ключ от вашего хранилища знать незачем.\n"
        "Пример: bucket=incoming-clean, prefix=vulnscan/, credentials_id=team-drop",
        p_delivery,
        default=None,
        render=show_delivery,
        empty=None,
    ),
    Param(
        "weight_overrides",
        "свои веса признаков поверх общей таблицы",
        "КОД=БАЛЛ через запятую",
        "Только баллы — severity остаётся общей, иначе один признак описывался бы "
        "разными словами для разных клиентов. Пример: PDF_EMBEDDED_FILE=80. "
        "Общие для всех веса правятся командой «weights set».",
        p_scores,
        default={},
        render=show_scores,
        empty={},
    ),
)


# ──────────────────────── параметры: веса признаков ─────────────────────────

WEIGHT_CODE = Param(
    "code",
    "код признака",
    "PDF_LAUNCH или YARA:high",
    "Стабильный код из Finding — часть публичного контракта API. Коды, которых "
    "нет в файле, берутся из встроенной таблицы. Для YARA ключ строится по тегу "
    "правила: YARA:critical, YARA:high, YARA:medium, YARA:low.",
    p_code,
)

WEIGHT_SCORE = Param(
    "score",
    "балл признака",
    "0..100",
    "Складывается с баллами других признаков и сравнивается с порогами тенанта. "
    "Ноль означает «наблюдение записываем, в балл не берём». Коррелированные "
    "признаки объединены в семейства, и внутри семейства в балл идёт только "
    "сильнейший — три взгляда на одну поломку не дают тройной вес.",
    p_int(0, 100),
)

WEIGHT_SEVERITY = Param(
    "severity",
    "как признак называется в ответе",
    " | ".join(s.value for s in Severity),
    "На арифметику не влияет — это то, что увидит человек в списке признаков. "
    "Держите согласованным с баллом: critical при пяти баллах читается как ошибка.",
    p_choice([s.value for s in Severity]),
)


# ─────────────────────────────── команды ────────────────────────────────────
#
# Команда — функция и декоратор. Ничего, кроме этого, добавлять не нужно:
# меню, справка и разбор аргументов строятся по этому же реестру.


@dataclass(frozen=True, slots=True)
class Command:
    name: str
    group: str
    title: str
    run: Callable[[Files], int | None]


COMMANDS: dict[str, Command] = {}


def command(name: str, group: str, title: str) -> Callable[..., Any]:
    def register(func: Callable[[Files], int | None]) -> Callable[[Files], int | None]:
        COMMANDS[name] = Command(name=name, group=group, title=title, run=func)
        return func

    return register


KEY_SECRET = Param(
    "secret",
    "секрет подписи",
    f"строка не короче {MIN_SECRET_LEN} символов",
    "Им подписываются запросы клиента. Короткий перебирается, поэтому загрузчик "
    "отвергает ключ целиком. Обычно генерируется — вводить свой нужно только при "
    "переносе уже работающей интеграции.",
    p_secret,
)


def _role(entry: dict[str, Any]) -> str:
    if entry.get("public"):
        return "публичный"
    return "админ" if entry.get("admin") else "обычный"


def _pick_key(files: Files, what: str = "ключ") -> tuple[dict[str, Any], str]:
    data = files.keys.load()
    known = sorted(entries(data))
    if not known:
        raise BadValueError(f"в {files.keys.path} нет ни одного ключа — заведите через «keys add»")
    key_id = choose(what, known)
    if not isinstance(data[key_id], dict):
        raise BadValueError(f"запись «{key_id}» в файле — не объект: поправьте руками или удалите")
    return data, key_id


def _announce_secret(key_id: str, secret: str, public: bool) -> None:
    print()
    if public:
        print(f"  секрет ключа {key_id}: {_b(secret)}")
        print(_d("  он публичен по назначению — его место в HTML страницы сайта."))
        print(_d("  Подписать им ничего нельзя: сервис отвергает такой ключ до сравнения подписи."))
    else:
        print(f"  секрет ключа {key_id}: {_b(secret)}")
        print(_d("  Показан один раз. Передайте владельцу защищённым каналом — не в чате"))
        print(_d("  и не в задаче трекера. Забыли: «keys rotate» выдаст новый."))


def _ask_key_entry(existing: dict[str, Any] | None) -> dict[str, Any]:
    """Вопросы про ключ. Состав зависит от ответов: у публичного ключа нет коллбэков."""
    current = existing or {}
    entry: dict[str, Any] = {"tenant": ask(KEY_TENANT, current.get("tenant", _MISSING))}

    public = ask(KEY_PUBLIC, current.get("public", False))
    if public:
        entry["public"] = True
        entry["origins"] = ask(KEY_ORIGINS, current.get("origins", _MISSING))
    else:
        if ask(KEY_ADMIN, current.get("admin", False)):
            entry["admin"] = True
        hosts = ask(KEY_CALLBACK_HOSTS, current.get("callback_hosts", []))
        if hosts:
            entry["callback_hosts"] = hosts

    entry["disabled"] = ask(KEY_DISABLED, current.get("disabled", False))
    return entry


@command("keys add", "Ключи доступа", "завести ключ тенанта")
def cmd_keys_add(files: Files) -> None:
    data = files.keys.load()
    key_id = ask(KEY_ID)
    if key_id in data:
        raise BadValueError(f"ключ «{key_id}» уже есть — правьте через «keys edit»")

    entry = _ask_key_entry(existing=None)
    generated = confirm("сгенерировать секрет?", default=True)
    secret = _make_secret() if generated else ask(KEY_SECRET)
    entry = {**entry, "secret": secret}

    data[key_id] = _ordered_key(entry)
    apply(files.keys, data, verify_keys)
    if generated:
        _announce_secret(key_id, secret, bool(entry.get("public")))


def _make_secret() -> str:
    return secrets.token_urlsafe(32)


def _ordered_key(entry: dict[str, Any]) -> dict[str, Any]:
    """Поля в предсказуемом порядке: файл читают и глазами тоже."""
    order = ("tenant", "secret", "admin", "public", "origins", "callback_hosts", "disabled")
    return {name: entry[name] for name in order if name in entry}


@command("keys edit", "Ключи доступа", "изменить ключ, не трогая секрет")
def cmd_keys_edit(files: Files) -> None:
    data, key_id = _pick_key(files, "какой ключ править")
    existing = data[key_id]
    entry = _ask_key_entry(existing)

    secret = str(existing.get("secret", ""))
    announce = False
    if len(secret) < MIN_SECRET_LEN:
        # Такой ключ загрузчик отвергает целиком, и правка соседних полей
        # ничего бы не изменила — сказать об этом надо здесь, а не откатом.
        print()
        print(f"  у ключа «{key_id}» нет годного секрета: короче {MIN_SECRET_LEN} символов")
        generate = confirm("сгенерировать новый?", default=True)
        secret = _make_secret() if generate else ask(KEY_SECRET)
        announce = generate

    data[key_id] = _ordered_key({**entry, "secret": secret})
    apply(files.keys, data, verify_keys)
    if announce:
        _announce_secret(key_id, secret, bool(entry.get("public")))


@command("keys rotate", "Ключи доступа", "выдать ключу новый секрет")
def cmd_keys_rotate(files: Files) -> None:
    data, key_id = _pick_key(files, "какому ключу сменить секрет")
    print()
    print(_d("  Старый секрет перестанет работать сразу после перечитывания файла."))
    print(_d("  Клиент, не получивший новый, начнёт получать отказ подписи."))
    if not confirm(f"сменить секрет ключа «{key_id}»?", default=False):
        raise AbortedError
    secret = _make_secret()
    data[key_id] = _ordered_key({**data[key_id], "secret": secret})
    apply(files.keys, data, verify_keys)
    _announce_secret(key_id, secret, bool(data[key_id].get("public")))


@command("keys disable", "Ключи доступа", "отозвать ключ (без перезапуска)")
def cmd_keys_disable(files: Files) -> None:
    data, key_id = _pick_key(files, "какой ключ отозвать")
    data[key_id] = _ordered_key({**data[key_id], "disabled": True})
    apply(files.keys, data, verify_keys)
    print(_d("  Запись осталась в файле: при разборе инцидента «отозван» и «не существовал» —"))
    print(_d("  разные вещи. Совсем убрать: «keys remove»."))


@command("keys enable", "Ключи доступа", "вернуть отозванный ключ в работу")
def cmd_keys_enable(files: Files) -> None:
    data, key_id = _pick_key(files, "какой ключ включить")
    data[key_id] = _ordered_key({**data[key_id], "disabled": False})
    apply(files.keys, data, verify_keys)


@command("keys remove", "Ключи доступа", "удалить запись о ключе")
def cmd_keys_remove(files: Files) -> None:
    data, key_id = _pick_key(files, "какой ключ удалить")
    if not confirm(f"удалить «{key_id}» насовсем?", default=False):
        raise AbortedError
    del data[key_id]
    apply(files.keys, data, verify_keys)


@command("keys list", "Ключи доступа", "показать ключи (секреты не печатаются)")
def cmd_keys_list(files: Files) -> None:
    data = entries(files.keys.load())
    if not data:
        print(f"\n  {files.keys.path}: ключей нет — подписанные запросы приниматься не будут")
        return
    print()
    print(f"  {'идентификатор':<24} {'тенант':<16} {'роль':<11} {'состояние':<10} коллбэки")
    for key_id, entry in sorted(data.items()):
        if not isinstance(entry, dict):
            print(f"  {key_id:<24} ✗ запись не является объектом, сервис её пропустит")
            continue
        state = "отозван" if entry.get("disabled") else "работает"
        where = ", ".join(entry.get("origins") or entry.get("callback_hosts") or []) or "—"
        print(
            f"  {key_id:<24} {entry.get('tenant', '?'):<16} {_role(entry):<11} {state:<10} {where}"
        )
    print()
    print(_d("  Секреты не печатаются: вывод команды попадает в историю консоли и в логи CI."))


@command("keys show-public", "Ключи доступа", "показать секрет публичного ключа сайта")
def cmd_keys_show_public(files: Files) -> None:
    data = files.keys.load()
    public = sorted(name for name, entry in entries(data).items() if entry.get("public"))
    if not public:
        raise BadValueError(
            "публичных ключей нет: заведите через «keys add», ответив «да» на public"
        )
    key_id = choose("какой ключ показать", public)
    # Единственное место, где секрет печатается по запросу, и это законно:
    # значение публичного ключа лежит в HTML страницы и конфиденциальным не
    # является. Для обычного ключа такой команды нет намеренно.
    _announce_secret(key_id, str(data[key_id].get("secret", "")), public=True)


@command("policy set", "Политики тенантов", "настроить политику тенанта")
def cmd_policy_set(files: Files) -> None:
    data = files.policies.load()
    known = sorted(entries(data))
    print()
    print(_d("  Незаданные поля берутся из переменных окружения DEFAULT_*."))
    print(_d("  Тенант, которого нет в файле, работает на умолчаниях целиком."))
    tenant = choose("тенант (или новое имя)", known, allow_new=KEY_TENANT.parse)
    current = data.get(tenant, {})

    payload: dict[str, Any] = {}
    for param in POLICY_PARAMS:
        value = ask(param, current.get(param.name, _MISSING))
        # Пустые словари в файл не пишем: пустой weight_overrides выглядит как
        # настройка, которой не занимались, и читается хуже отсутствия ключа.
        if value != {} or param.name in current:
            payload[param.name] = value

    if payload["suspicious_threshold"] >= payload["block_threshold"]:
        raise BadValueError(
            "suspicious_threshold должен быть ниже block_threshold: иначе между "
            "порогами нет вердикта suspicious и файл прыгает из clean в malicious"
        )

    data[tenant] = payload
    apply(files.policies, data, verify_policies)


@command("policy show", "Политики тенантов", "показать политику тенанта")
def cmd_policy_show(files: Files) -> None:
    data = entries(files.policies.load())
    tenant = choose("тенант", sorted(data))
    payload = data[tenant]
    print()
    for param in POLICY_PARAMS:
        if param.name in payload:
            print(f"  {param.name:<26} {param.render(payload[param.name])}")
        else:
            print(_d(f"  {param.name:<26} — из DEFAULT_* окружения"))


@command("policy list", "Политики тенантов", "показать все политики кратко")
def cmd_policy_list(files: Files) -> None:
    data = entries(files.policies.load())
    if not data:
        print(f"\n  {files.policies.path}: политик нет — все тенанты на умолчаниях")
        return
    print()
    print(f"  {'тенант':<18} {'режим отказа':<13} {'пороги':<10} {'профиль':<9} тень")
    for tenant, payload in sorted(data.items()):
        low = payload.get("suspicious_threshold", "—")
        high = payload.get("block_threshold", "—")
        thresholds = f"{low}/{high}"
        shadow = "да" if payload.get("shadow_mode") else "—"
        print(
            f"  {tenant:<18} {payload.get('fail_mode', '—')!s:<13} "
            f"{thresholds:<10} {payload.get('default_profile', '—')!s:<9} {shadow}"
        )


@command("policy remove", "Политики тенантов", "убрать политику (тенант уйдёт на умолчания)")
def cmd_policy_remove(files: Files) -> None:
    data = files.policies.load()
    tenant = choose("какую политику убрать", sorted(entries(data)))
    print()
    print(_d(f"  «{tenant}» получит DEFAULT_* целиком: пороги, режим отказа, лимиты."))
    if not confirm(f"убрать политику «{tenant}»?", default=False):
        raise AbortedError
    del data[tenant]
    apply(files.policies, data, verify_policies)


@command("weights set", "Веса признаков", "изменить вес признака для всех тенантов")
def cmd_weights_set(files: Files) -> None:
    data = files.weights.load()
    code = ask(WEIGHT_CODE)
    builtin = DEFAULT_WEIGHTS.get(code)
    if builtin is None:
        print()
        print(f"  {code} нет во встроенной таблице.")
        print(_d("  Либо это опечатка, либо код появился в стадии, но не заведён в"))
        print(_d("  vscommon/weights.py — тогда он получает запасной вес и попадает в"))
        print(_d("  unknown_codes. Файл конфигурации это не чинит: заводите код в таблице."))
        if not confirm("всё равно записать?", default=False):
            raise AbortedError

    current = data.get(code, {})
    score = ask(WEIGHT_SCORE, current.get("score", builtin.score if builtin else _MISSING))
    severity = ask(
        WEIGHT_SEVERITY,
        current.get("severity", builtin.severity.value if builtin else _MISSING),
    )
    data[code] = {"score": score, "severity": severity}
    apply(files.weights, data, verify_weights)
    print(_d("  Живой воркер подхватит правку сам — перезапуск не нужен."))
    print(_d("  Структурный кэш обесценится: отпечаток таблицы входит в его ключ."))


@command("weights unset", "Веса признаков", "убрать переопределение, вернуть встроенный вес")
def cmd_weights_unset(files: Files) -> None:
    data = files.weights.load()
    overridden = sorted(entries(data))
    if not overridden:
        raise BadValueError("переопределений нет: все веса берутся из встроенной таблицы")
    code = choose("какое переопределение убрать", overridden)
    del data[code]
    apply(files.weights, data, verify_weights)


@command("weights list", "Веса признаков", "показать переопределения рядом со встроенными")
def cmd_weights_list(files: Files) -> None:
    data = entries(files.weights.load())
    if not data:
        print(f"\n  {files.weights.path}: переопределений нет, действуют встроенные веса")
        return
    print()
    print(f"  {'код':<30} {'балл':>6} {'встроенный':>11}  severity")
    for code, payload in sorted(data.items()):
        builtin = DEFAULT_WEIGHTS.get(code)
        was = str(builtin.score) if builtin else "нет в таблице"
        mark = " " if builtin and builtin.score == payload.get("score") else "*"
        print(
            f" {mark}{code:<30} {payload.get('score')!s:>6} {was:>11}  "
            f"{payload.get('severity', '—')}"
        )
    print()
    print(_d("  * — значение отличается от встроенного."))


@command("weights builtin", "Веса признаков", "показать встроенную таблицу весов")
def cmd_weights_builtin(files: Files) -> None:
    print()
    for code, rule in sorted(DEFAULT_WEIGHTS.items()):
        print(f"  {code:<30} {rule.score:>4}  {rule.severity.value}")
    print()
    print(_d(f"  всего кодов: {len(DEFAULT_WEIGHTS)}. Правятся здесь только через «weights set»."))


@command("check", "Проверка", "проверить все три файла, ничего не меняя")
def cmd_check(files: Files) -> int:
    """Ровно то, что сделает сервис на старте, но до выката, а не по логам.

    Отдельная команда нужна потому, что все три файла деградируют молча:
    непрочитанный `policies.json` уводит тенантов на умолчания, отсутствующий
    `keys.json` отвергает всех, а опечатка в коде признака даёт запасной вес.
    Ни одно из этих состояний снаружи не отличается от исправной работы.
    """
    problems: list[str] = []
    notes: list[str] = []

    for store, verify, missing in (
        (files.keys, verify_keys, "ключей нет: ни один подписанный запрос не будет принят"),
        (files.policies, verify_policies, "политик нет: все тенанты на умолчаниях DEFAULT_*"),
        (files.weights, verify_weights, "переопределений нет: действуют встроенные веса"),
    ):
        if not store.path.is_file():
            # Рядом почти всегда лежит `*.example.json`. Не сказать о нём —
            # значит оставить читателя гадать, файла нет или он не там.
            example = store.path.with_name(store.path.name.replace(".json", ".example.json"))
            hint = f"; образец рядом: {example.name}" if example.is_file() else ""
            notes.append(f"{store.path.name} отсутствует — {missing}{hint}")
            continue
        problems.extend(verify(store.path))

    # Файлы с секретами: у них права строже, чем у остальной конфигурации.
    # Отдельным списком, а не одной строкой на `keys.json`: следующий такой
    # файл (учётные данные приёмников из M14) иначе появился бы без проверки —
    # и заметить это можно было бы только по чужому доступу к бакету.
    secret_files = [
        (files.keys.path, "секреты подписи"),
        (files.keys.path.parent.parent / "secrets" / "delivery.json", "ключи к чужим хранилищам"),
    ]
    for path, what in secret_files:
        if not path.is_file():
            continue
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            # Про владельца сказано не для полноты. Сузив права и не сменив
            # владельца, вы получите файл, недоступный самому сервису:
            # контейнеры работают под uid 10001. Отказ при этом молчит про
            # доступ — реестр помечается негодным, и каждый подписанный запрос
            # получает 503 «аутентификация временно недоступна».
            problems.append(
                f"{path.name} доступен не только владельцу (права {mode:04o}): "
                f"в нём {what}. Сузить нужно ВМЕСТЕ со сменой владельца, иначе "
                f"сервис его не прочитает:\n"
                f"      sudo chown {SERVICE_UID} {path} && sudo chmod 600 {path}"
            )

    # Приёмник настроен, а учёток к нему нет — доставки не будет ни одной, и
    # узнать об этом можно только по пустому ящику у клиента. Ссылка
    # `credentials_id` из политики проверяется здесь, до выката, а не в бою по
    # записям dead-letter.
    problems.extend(_check_credentials(files.policies))

    keys_data = entries(files.keys.load())
    policy_data = entries(files.policies.load())
    weights_data = entries(files.weights.load())

    with_keys = {entry.get("tenant") for entry in keys_data.values()}
    for tenant in sorted(set(policy_data) - with_keys):
        # Частный случай, и он не «может быть»: имя политики совпало с
        # ИДЕНТИФИКАТОРОМ КЛЮЧА, у которого другой тенант. `policies.json`
        # ключуется по тенанту, поэтому такая запись не применится никогда.
        #
        # Отдельной строкой, потому что путаница естественная: в `.env` лежит
        # `KEY_ID=telegram-bot-1`, он же встречается в логах и в заголовке
        # запроса, а тенант виден только внутри `keys.json`. Ошибка при этом
        # молчит: сервис работает, вердикты выдаёт, настройка не действует.
        owner = keys_data.get(tenant, {}).get("tenant")
        if owner:
            problems.append(
                f"политика «{tenant}» названа по идентификатору ключа, а не по тенанту: "
                f"этот ключ принадлежит тенанту «{owner}». Переименуйте запись в «{owner}» — "
                f"иначе она не применится никогда"
            )
            continue
        # Общий случай: тенант может ещё не получить ключ. Но чаще это опечатка
        # в имени, а выглядит она как «политику настроили, а она не работает».
        notes.append(f"политика «{tenant}» настроена, но ключей этого тенанта нет")
    for tenant in sorted(with_keys - set(policy_data) - {None}):
        notes.append(f"тенант «{tenant}» работает на умолчаниях: своей политики нет")

    for tenant, payload in sorted(policy_data.items()):
        template = (payload.get("delivery") or {}).get("key_template", "")
        if template and not any(token in template for token in ("{scan_id}", "{sha}")):
            # Не ошибка: в бакете может быть включено версионирование, и тогда
            # перезапись не теряет документ. Но по умолчанию теряет — молча, и
            # обнаруживается это, когда файл ищут и не находят.
            notes.append(
                f"приёмник «{tenant}»: в key_template нет ни {{scan_id}}, ни {{sha}} — "
                f"два документа с одинаковым именем затрут друг друга"
            )

    unknown = {
        code
        for payload in policy_data.values()
        for code in (payload.get("weight_overrides") or {})
        if code not in DEFAULT_WEIGHTS
    } | {code for code in weights_data if code not in DEFAULT_WEIGHTS}
    for code in sorted(unknown):
        notes.append(f"код «{code}» не встречается во встроенной таблице — опечатка?")

    for public_id, entry in sorted(keys_data.items()):
        if entry.get("public") and not entry.get("origins"):
            problems.append(f"публичный ключ «{public_id}» без origins не работает нигде")

    print()
    for note in notes:
        print(f"  · {note}")
    if problems:
        print()
        for problem in problems:
            print(f"  ✗ {problem}")
        print(f"\n  проверка не пройдена: {len(problems)}")
        return 1
    print(
        f"\n  проверка пройдена: ключей {len(keys_data)}, политик {len(policy_data)}, "
        f"переопределений весов {len(weights_data)}"
    )
    return 0


# ────────────────────────────── запуск ──────────────────────────────────────


def groups() -> dict[str, list[Command]]:
    result: dict[str, list[Command]] = {}
    for cmd in COMMANDS.values():
        result.setdefault(cmd.group, []).append(cmd)
    return result


def print_commands() -> None:
    for group, commands in groups().items():
        print(f"\n  {_b(group)}")
        for cmd in commands:
            print(f"    {cmd.name:<20} {_d(cmd.title)}")


def run(cmd: Command, files: Files) -> int:
    try:
        return cmd.run(files) or 0
    except AbortedError:
        print("\n  прервано, ни один файл не изменён")
        return 1
    except BadValueError as exc:
        print(f"\n  ✗ {exc}")
        return 1


def menu(files: Files) -> int:
    numbered = list(COMMANDS.values())
    while True:
        print()
        print(f"  конфигурация: {_b(str(files.keys.path.parent))}")
        for store in (files.keys, files.policies, files.weights):
            state = "есть" if store.path.is_file() else _d("нет")
            print(f"    {store.path.name:<16} {state}")
        print_commands()
        print()
        raw = read_line("  команда (имя, номер по порядку или q): ").strip()
        if raw in {"q", "й", ""}:
            return 0
        cmd = COMMANDS.get(raw)
        if cmd is None and raw.isdigit() and 1 <= int(raw) <= len(numbered):
            cmd = numbered[int(raw) - 1]
        if cmd is None:
            print("  ✗ такой команды нет")
            continue
        run(cmd, files)


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.ERROR, format="  загрузчик: %(message)s")

    parser = argparse.ArgumentParser(
        prog="configure.py",
        description="Настройка keys.json, weights.json и policies.json с проверкой "
        "теми же загрузчиками, что и у сервиса.",
    )
    parser.add_argument("words", nargs="*", metavar="КОМАНДА", help="например: keys add")
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=DEFAULT_CONFIG_DIR,
        help=f"каталог с файлами конфигурации (по умолчанию {DEFAULT_CONFIG_DIR})",
    )
    args = parser.parse_args(argv)
    files = files_at(args.config_dir)

    name = " ".join(args.words)
    if not name:
        try:
            return menu(files)
        except AbortedError:
            print("  выход")
            return 0

    cmd = COMMANDS.get(name)
    if cmd is None:
        print(f"  ✗ неизвестная команда: {name}")
        print_commands()
        return 2
    return run(cmd, files)


if __name__ == "__main__":
    raise SystemExit(main())
