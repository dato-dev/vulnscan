"""Всё, что образ копирует, должно быть в контексте сборки.

Регрессия: файлы закрепления версий положили в `deploy/`, а `deploy/` целиком
исключён `.dockerignore`. Сборка упала на `COPY ... not found` — уже после
того, как локальные тесты были зелёными и образ поехал собираться.

Ошибка громкая, но узнать о ней можно было только запустив сборку, а сборка
требует сети и десятков секунд на образ. Проверка статическая: она стоит
миллисекунды и падает там же, где остальные.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
DOCKERFILES = sorted([*ROOT.glob("services/*/Dockerfile"), *ROOT.glob("examples/*/Dockerfile")])


def _patterns() -> list[tuple[str, bool]]:
    """Шаблоны `.dockerignore`: (шаблон, это ли исключение из исключения)."""
    found = []
    for line in (ROOT / ".dockerignore").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        found.append((line.lstrip("!").rstrip("/"), negated))
    return found


def _ignored(path: str) -> bool:
    """Исключён ли путь. Побеждает последнее совпадение — как в Docker.

    Правила упрощены до того, что мы реально используем: имена, шаблоны с
    `*` и каталоги. Полную семантику воспроизводить незачем — на ней держится
    Docker, а здесь нужно поймать «положили в исключённый каталог».
    """
    verdict = False
    parts = Path(path).parts
    for pattern, negated in _patterns():
        prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
        if any(fnmatch.fnmatch(prefix, pattern) for prefix in prefixes):
            verdict = not negated
    return verdict


def _copied(dockerfile: Path) -> list[str]:
    """Источники всех `COPY` — без флагов и без последнего аргумента-приёмника.

    `COPY --from=<образ>` пропускается: там путь внутри чужого образа, а не в
    нашем контексте сборки. Именно так приезжает uv.
    """
    sources: list[str] = []
    for line in dockerfile.read_text().splitlines():
        if not line.startswith("COPY "):
            continue
        if "--from=" in line:
            continue
        args = [a for a in line.split()[1:] if not a.startswith("--")]
        sources += args[:-1]
    return sources


def _uv_images(dockerfile: Path) -> list[str]:
    """Образы, из которых копируется uv: `COPY --from=ghcr.io/astral-sh/uv:X`."""
    return re.findall(r"COPY --from=(ghcr\.io/astral-sh/uv:\S+)", dockerfile.read_text())


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.parent.name)
def test_copied_paths_exist(dockerfile: Path) -> None:
    """Путь из COPY существует в репозитории."""
    missing = [src for src in _copied(dockerfile) if not (ROOT / src).exists()]

    assert not missing, f"{dockerfile.parent.name}: COPY несуществующего пути: {missing}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.parent.name)
def test_copied_paths_are_not_excluded(dockerfile: Path) -> None:
    """Путь из COPY не исключён `.dockerignore`.

    Файл может лежать в репозитории и всё равно отсутствовать в контексте —
    тогда сборка падает с «not found», и выглядит это как пропавший файл, а не
    как правило исключения.
    """
    excluded = [src for src in _copied(dockerfile) if _ignored(src)]

    assert not excluded, (
        f"{dockerfile.parent.name}: COPY того, что исключено .dockerignore: {excluded}"
    )


def test_ignore_matcher_actually_matches() -> None:
    """Проверка самой проверки.

    Матчер, который ничего не находит, сделал бы оба теста выше вечно
    зелёными — тот же класс подмены, что и пустая панель.
    """
    assert _ignored("deploy/docker-compose.yml"), "каталог deploy обязан быть исключён"
    assert _ignored("tests/test_writer.py"), "tests исключён"
    assert not _ignored("uv.lock"), "файлы в корне не исключены"
    assert not _ignored("packages/vscommon"), "общий код едет в образ"


def test_lock_is_reachable_from_context() -> None:
    """`uv.lock` и `pyproject.toml` лежат там, откуда их можно скопировать.

    Отдельно от параметризованных проверок выше: на этом сборка однажды и
    упала — файлы закрепления версий положили в `deploy/`, а он исключён
    целиком. Теперь на их месте лок, и грабли те же.
    """
    for name in ("uv.lock", "pyproject.toml"):
        assert (ROOT / name).exists(), f"{name} нет в корне"
        assert not _ignored(name), f"{name} исключён из контекста сборки"


def test_images_install_from_the_lock() -> None:
    """Образ ставит зависимости из `uv.lock`, а не перечисляет их сам.

    Перечисленный в Dockerfile список — это второй источник правды рядом с
    локом, и расходятся такие пары молча: пересборка приносит другую версию,
    а какая именно работает на стенде, выясняется уже изнутри контейнера.
    """
    for dockerfile in DOCKERFILES:
        text = dockerfile.read_text()
        assert "uv export --frozen" in text, (
            f"{dockerfile.parent.name}: ставит не из лока — где `uv export --frozen`?"
        )
        copied = {Path(src).name for src in _copied(dockerfile)}
        assert {"uv.lock", "pyproject.toml"} <= copied, (
            f"{dockerfile.parent.name}: ставит из лока, но не копирует его"
        )


def test_no_dockerfile_names_a_package_version() -> None:
    """Версии живут в `pyproject.toml` и `uv.lock`, а не в Dockerfile.

    Регрессия, ради которой: версии SDK наблюдаемости жили в семи местах —
    pyproject и шесть Dockerfile, — и разъезжались молча. Разошедшиеся версии
    клиента метрик дают разный формат экспозиции, и Prometheus перестаёт
    разбирать часть рядов, ничего об этом не сообщая.
    """
    offenders = {}
    for dockerfile in DOCKERFILES:
        named = [
            line.strip()
            for line in dockerfile.read_text().splitlines()
            if not line.lstrip().startswith("#")
            # Версия самого uv — исключение: он приезжает из образа, и тег
            # обязан быть точным, иначе состав меняется от пересборки.
            and "astral-sh/uv" not in line
            and re.search(r'"[a-z][a-z0-9_.-]+(\[[a-z,]+\])?[<>=]=', line)
        ]
        if named:
            offenders[dockerfile.parent.name] = named

    assert not offenders, f"Dockerfile называет версии сам: {offenders}"


def test_makefile_knows_where_every_image_lives() -> None:
    """Путь до Dockerfile в Makefile существует для каждого собираемого образа.

    Регрессия: правило собирало всё из `services/$*/Dockerfile`, а пример
    подключения лежит в `examples/feedback-site`. Команда падала с «no such
    file or directory» — после того, как я её же и продиктовал.
    """
    import subprocess

    makefile = (ROOT / "Makefile").read_text()
    services = re.search(r"^SERVICES\s*\?=\s*(.+)$", makefile, re.M)
    assert services, "не нашлось списка сервисов"

    for name in [*services.group(1).split(), "demo-site"]:
        result = subprocess.run(
            ["make", "-n", f"push-{name}", "NAMESPACE=x", "TAG=y"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        )
        path = re.search(r"-f (\S+)", result.stdout)
        assert path, f"{name}: правило не печатает путь до Dockerfile"
        assert (ROOT / path.group(1)).exists(), (
            f"{name}: Makefile собирает из {path.group(1)}, а файла нет"
        )


# --- пакеты ставит uv ----------------------------------------------------


def test_pip_is_gone_from_the_repository() -> None:
    """`pip` не вызывается нигде: ни в образах, ни в Makefile, ни в CI.

    Один установщик на локальную разработку и на сборку означает, что «у меня
    работает» и «в образе работает» перестают быть разными утверждениями:
    разрешение зависимостей одно и то же.

    Раньше исключением была установка самого uv — его надо было чем-то
    поставить. Теперь он приезжает готовым бинарником из своего образа, и
    исключения не осталось.
    """
    watched = [
        *DOCKERFILES,
        ROOT / "Makefile",
        *sorted((ROOT / ".github/workflows").glob("*.yml")),
    ]
    offenders = {}
    for path in watched:
        calls = [
            line.strip()
            for line in path.read_text().splitlines()
            if not line.lstrip().startswith("#")
            and re.search(r"(?<!uv )\bpip install\b", line)
        ]
        if calls:
            offenders[str(path.relative_to(ROOT))] = calls

    assert not offenders, f"вызов pip: {offenders}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.parent.name)
def test_uv_arrives_before_it_is_used(dockerfile: Path) -> None:
    """uv появляется в образе раньше первого применения.

    Регрессия при прошлом переезде: в одном образе установка не вставилась,
    потому что вызов был внутри цепочки `&&`, а не в начале строки. Собралось
    бы это ровно до первого `uv: not found`.
    """
    text = dockerfile.read_text()
    first_use = text.find("uv export")
    if first_use == -1:
        return

    arrival = text.find("COPY --from=ghcr.io/astral-sh/uv:")

    assert arrival != -1, "uv используется, но в образ не копируется"
    assert arrival < first_use, "uv применяется раньше, чем появляется"


def test_uv_version_is_the_same_everywhere() -> None:
    """Все образы берут одну версию uv.

    Разъехавшиеся установщики — это разные деревья зависимостей при одном и
    том же локе, и обнаруживается такое не ошибкой сборки, а поведением на
    стенде.
    """
    versions = {
        dockerfile.parent.name: {image.split(":", 1)[1].removesuffix("-alpine")
                                 for image in _uv_images(dockerfile)}
        for dockerfile in DOCKERFILES
    }
    named = {name: found for name, found in versions.items() if found}
    distinct = set().union(*named.values())

    assert len(named) == len(DOCKERFILES), f"образ без uv: {sorted(set(versions) - set(named))}"
    assert len(distinct) == 1, f"версии uv разошлись: {named}"


def test_uv_version_is_pinned_exactly() -> None:
    """Никаких `latest`: тег установщика — часть состава образа.

    Плавающий тег означает, что при неизменных исходниках пересборка может
    дать другое дерево зависимостей.
    """
    loose = {
        dockerfile.parent.name: images
        for dockerfile in DOCKERFILES
        for images in [_uv_images(dockerfile)]
        if any(not re.fullmatch(r"\d+\.\d+\.\d+(-alpine)?", i.split(":", 1)[1]) for i in images)
    }

    assert not loose, f"версия uv задана не точно: {loose}"


def test_local_environment_uses_the_lock() -> None:
    """`make venv` собирает окружение из того же лока, что и образы.

    Прежний вариант падал в запасной путь — `uv pip install` со списком
    пакетов руками, — когда основная установка не проходила. Молча ставился
    урезанный набор, и локальный прогон переставал быть тем же, что в образе:
    так `yara-python` не стоял ни у кого, правила не компилировал никто, а
    тесты оставались зелёными.
    """
    makefile = (ROOT / "Makefile").read_text()
    recipe = makefile.split("venv:")[1].split("\n\n")[0]
    # Комментарии рецепта — не команды. Без этого тест ловил бы собственное
    # объяснение того, почему запасного пути больше нет.
    commands = "\n".join(
        line for line in recipe.splitlines() if not line.strip().startswith("#")
    )

    assert "uv sync --frozen" in commands, "окружение собирается не из лока"
    assert "||" not in commands, "запасной путь ставит не то, что в локе, и делает это молча"


# --- лок и группы --------------------------------------------------------


def _groups_of(dockerfile: Path) -> set[str]:
    """Группы зависимостей, которые ставит образ."""
    return set(re.findall(r"--group (\S+)", dockerfile.read_text()))


def _groups() -> dict[str, list[str]]:
    """Группы зависимостей: имя → список требований (без `include-group`).

    Через `tomllib`, а не регулярками. Разбор руками здесь уже соврал молча:
    тело группы резалось по первому `]`, а он есть внутри
    `"uvicorn[standard]>=0.32"` — проверка осматривала огрызок и проходила.
    Ровно тот класс отказа, который этот файл и ловит.
    """
    import tomllib

    raw = tomllib.loads((ROOT / "pyproject.toml").read_text())["dependency-groups"]
    return {
        name: [item for item in items if isinstance(item, str)] for name, items in raw.items()
    }


def _declared_groups() -> set[str]:
    """Группы, объявленные в `pyproject.toml`."""
    return set(_groups())


def test_lock_is_in_sync_with_pyproject() -> None:
    """`uv.lock` пересчитан после правки зависимостей.

    Забытый `make lock` не ломается заметно: локально всё стоит с прошлого
    раза, а образ собирается `--frozen` и просто не получит новую библиотеку —
    падение будет на `ImportError` внутри контейнера, далеко от причины.
    """
    import shutil
    import subprocess

    assert shutil.which("uv"), "без uv проект не собрать — это не повод пропустить проверку"

    result = subprocess.run(
        ["uv", "lock", "--check", "--offline"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )

    assert result.returncode == 0, f"лок разошёлся с pyproject, нужен `make lock`:\n{result.stderr}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.parent.name)
def test_image_installs_groups_that_exist(dockerfile: Path) -> None:
    """Образ ставит объявленную группу.

    Опечатка в имени не ломает сборку: `uv export --group нет-такой` отдаст
    пустой список, установка пройдёт, и образ поедет без зависимостей —
    падение случится на первом импорте уже в бою.
    """
    unknown = _groups_of(dockerfile) - _declared_groups()

    assert not unknown, f"{dockerfile.parent.name}: нет таких групп в pyproject: {sorted(unknown)}"


def test_every_group_belongs_to_some_image() -> None:
    """Группа без образа — мёртвый список, который продолжают править.

    Кроме `dev`: он собирает локальное окружение и в образы не едет намеренно.
    """
    used = {group for dockerfile in DOCKERFILES for group in _groups_of(dockerfile)}
    orphans = _declared_groups() - used - {"dev"}

    assert not orphans, f"группа не ставится ни одним образом: {sorted(orphans)}"


def test_parsers_do_not_leak_into_other_images() -> None:
    """Библиотеки разбора живут только в воркере.

    Это не гигиена зависимостей, а периметр: pikepdf, pillow и yara-python —
    код на C, которому скармливают недоверенный ввод. Воркер за то и заперт
    без сетевого выхода. В gateway или notifier они означали бы ту же
    поверхность атаки в процессе, который смотрит наружу.
    """
    parsers = ("pikepdf", "pillow", "yara-python", "python-magic")
    groups = _groups()

    def _named(items: list[str]) -> set[str]:
        return {re.split(r"[<>=\[]", item)[0] for item in items}

    assert "pikepdf" in _named(groups["worker"]), (
        "проверка смотрит не туда: у воркера пропал pikepdf"
    )

    leaked = {
        name: sorted(_named(items) & set(parsers))
        for name, items in groups.items()
        if name not in {"worker", "dev"} and _named(items) & set(parsers)
    }

    assert not leaked, f"разбор недоверенного ввода попал в чужой образ: {leaked}"
