"""Образ получает то, что сервис импортирует.

Заведено по факту аварии. В M14.1 notifier начал читать копию из хранилища —
`build_store(settings)`, — а `boto3` в его группу зависимостей никто не
добавил. Прогон был зелёным: в тестах `boto3` стоит из группы `dev`, где есть
всё. Образ собрался. Сервис упал при старте на `ModuleNotFoundError`, в цикле
перезапуска, и увидели это только в логах стенда.

Отказ дорог не сам по себе, а расстоянием между причиной и симптомом: строка
не дописана в `pyproject.toml`, а падает импорт внутри контейнера. Между ними
сборка и выкат.

Проверка считает граф импортов от точки входа сервиса, идя только по нашим
модулям, и сверяет сторонние пакеты с тем, что **действительно поставит
образ** — с выгрузкой `uv export` по группам из его Dockerfile. Не с прямым
списком группы: транзитивные зависимости в образе тоже есть, и требовать
объявлять `starlette` рядом с `fastapi` значило бы заставить дублировать
работу разрешателя.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent

LOCAL_PACKAGES = frozenset(
    {"vscommon", "gateway_app", "worker_app", "botapp", "writerapp", "notifierapp"}
)
"""Наши пакеты: по ним граф идёт вглубь, чужие — записываются и не раскрываются."""

SEARCH_PATHS = [
    ROOT / "packages",
    *(ROOT / "services" / name for name in ("gateway", "worker", "bot", "writer", "notifier")),
]

SERVICES = {
    "gateway": ("gateway_app.main", "services/gateway/Dockerfile"),
    "worker": ("worker_app.main", "services/worker/Dockerfile"),
    "bot": ("botapp.main", "services/bot/Dockerfile"),
    "writer": ("writerapp.main", "services/writer/Dockerfile"),
    "notifier": ("notifierapp.main", "services/notifier/Dockerfile"),
}


def _module_path(module: str) -> Path | None:
    for base in SEARCH_PATHS:
        as_file = base / (module.replace(".", "/") + ".py")
        if as_file.exists():
            return as_file
        as_package = base / module.replace(".", "/") / "__init__.py"
        if as_package.exists():
            return as_package
    return None


def _imports_of(tree: ast.AST, package: str) -> list[str]:
    """Имена, которые модуль импортирует, включая относительные.

    Импорты внутри функций считаются наравне с верхнеуровневыми: именно так
    подключён `boto3` в `vscommon/storage.py` — лениво, чтобы тестам он был не
    нужен. Отсутствующий ленивый импорт падает не при старте, а при первом
    вызове, то есть ещё позже.
    """
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package if node.level == 1 else package.rsplit(".", node.level - 1)[0]
                found.append(f"{base}.{node.module}" if node.module else base)
            elif node.module:
                found.append(node.module)
    return found


def _third_party(entrypoint: str) -> set[str]:
    """Сторонние модули, достижимые от точки входа по нашему коду."""
    seen: set[str] = set()
    outside: set[str] = set()
    stack = [entrypoint]

    while stack:
        module = stack.pop()
        if module in seen:
            continue
        seen.add(module)
        path = _module_path(module)
        if path is None:
            continue

        package = module.rsplit(".", 1)[0] if "." in module else module
        for name in _imports_of(ast.parse(path.read_text()), package):
            top = name.split(".")[0]
            if top in LOCAL_PACKAGES:
                stack.append(name)
            elif top not in sys.stdlib_module_names:
                outside.add(top)
    return outside


def _distributions(module: str) -> set[str]:
    """Имена дистрибутивов, дающих этот модуль.

    Импортируется `opentelemetry`, а ставится `opentelemetry-api` и ещё
    четыре: у пространств имён имя модуля и имя пакета не совпадают, и
    сравнивать их напрямую — значит объявить недостающим то, что стоит.

    Карта берётся из локального окружения. Это не проверка наличия, а только
    перевод имени: наличие проверяется по выгрузке лока.
    """
    from importlib.metadata import packages_distributions

    known = packages_distributions().get(module) or [module]
    return {name.lower().replace("-", "_") for name in known}


def _groups_of(dockerfile: str) -> list[str]:
    return re.findall(r"--group (\S+)", (ROOT / dockerfile).read_text())


def _shipped(groups: list[str]) -> set[str]:
    """Что окажется в образе: полная выгрузка лока по группам Dockerfile.

    Через `uv export`, а не по списку группы: транзитивные зависимости в образе
    тоже есть. Сверяться со списком значило бы требовать объявить `starlette`
    рядом с `fastapi` — то есть повторить работу разрешателя руками.
    """
    command = ["uv", "export", "--frozen", "--no-default-groups", "--no-hashes"]
    for group in groups:
        command += ["--group", group]
    result = subprocess.run(command, capture_output=True, text=True, cwd=ROOT, check=True)
    return {
        match.group(1).lower().replace("-", "_")
        for match in re.finditer(r"^([a-zA-Z0-9_.-]+)==", result.stdout, re.M)
    }


@pytest.mark.parametrize("service", sorted(SERVICES))
def test_every_import_is_in_the_image(service: str) -> None:
    """Всё, что сервис импортирует, попадёт в его образ.

    Регрессия, ради которой: notifier начал читать копию из хранилища, а
    `boto3` в его группу не добавили. Тесты зелёные — в окружении разработки
    стоит группа `dev` со всем сразу; образ собран; сервис падает при старте.
    """
    import shutil

    assert shutil.which("uv"), "без uv состав образа не узнать — это не повод пропустить проверку"

    entrypoint, dockerfile = SERVICES[service]
    shipped = _shipped(_groups_of(dockerfile))
    missing = sorted(
        module
        for module in _third_party(entrypoint)
        if not _distributions(module) & shipped
    )

    assert not missing, (
        f"{service} импортирует то, чего в образе не будет: {missing}. "
        f"Допишите в группу «{service}» в pyproject.toml и сделайте `make lock`."
    )


def test_the_graph_actually_walks() -> None:
    """Проверка проверки: обход находит то, что заведомо есть.

    Пустой граф сделал бы все проверки выше вечно зелёными — тот же класс
    подмены, что и пустая панель или тест, проходящий на удалённой
    инструментации.
    """
    found = _third_party("worker_app.main")

    assert "pikepdf" in found, "обход не дошёл до стадий разбора"
    assert "boto3" in found, "обход не видит ленивые импорты внутри функций"
    assert "redis" in found


def test_parsers_reach_only_the_worker() -> None:
    """Библиотеки разбора недоверенного ввода импортирует один сервис.

    Дополняет проверку групп в `test_build_context.py`: там смотрят, что
    объявлено, здесь — что действительно импортируется. Объявить можно
    аккуратно, а импортировать всё равно из общего модуля.
    """
    parsers = {"pikepdf", "PIL", "yara", "magic"}
    leaked = {
        service: sorted(_third_party(entrypoint) & parsers)
        for service, (entrypoint, _) in SERVICES.items()
        if service != "worker" and _third_party(entrypoint) & parsers
    }

    assert not leaked, f"разбор недоверенного ввода тянется в чужой сервис: {leaked}"
