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
import pathlib
import re
import subprocess
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
            if not line.lstrip().startswith("#") and re.search(r"(?<!uv )\bpip install\b", line)
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
        dockerfile.parent.name: {
            image.split(":", 1)[1].removesuffix("-alpine") for image in _uv_images(dockerfile)
        }
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
    commands = "\n".join(line for line in recipe.splitlines() if not line.strip().startswith("#"))

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
    return {name: [item for item in items if isinstance(item, str)] for name, items in raw.items()}


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
    Группу может ставить и конвейер, а не образ (`docs` — сайт документации):
    это тоже живое использование.
    """
    used = {group for dockerfile in DOCKERFILES for group in _groups_of(dockerfile)}
    for workflow in (ROOT / ".github/workflows").glob("*.yml"):
        used |= set(re.findall(r"--group[ =]([\w-]+)", workflow.read_text()))
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


# --- стенд сквозного прогона ----------------------------------------------

E2E = ROOT / "tests" / "e2e"


def _e2e_compose() -> dict:
    import yaml

    return yaml.safe_load((E2E / "docker-compose.yml").read_text())


def _stand_expects() -> dict[str, pathlib.Path]:
    """Файлы, которые сервисы стенда ищут по своим переменным окружения.

    Список берётся из compose, а не пишется руками: новая переменная с путём
    внутри смонтированного каталога попадает под проверку сама. Руками список
    отстал бы ровно тогда, когда появился бы новый файл, — то есть в момент,
    когда проверка нужнее всего.
    """
    wanted: dict[str, pathlib.Path] = {}
    for name, service in _e2e_compose()["services"].items():
        mounts = {
            str(volume).split(":")[1]: pathlib.Path(str(volume).split(":")[0])
            for volume in (service.get("volumes") or [])
            if str(volume).startswith("./")
        }
        for key, value in (service.get("environment") or {}).items():
            if not key.endswith("_FILE") or not isinstance(value, str):
                continue
            for inside, outside in mounts.items():
                if value.startswith(inside + "/"):
                    wanted[f"{name}:{key}"] = E2E / outside / value[len(inside) + 1 :]
    return wanted


def test_stand_generates_every_file_it_needs() -> None:
    """Всё, что сервисы стенда ищут, генератор создаёт.

    Регрессия, ради которой: `keys.json` и `delivery.json` исключены
    `.gitignore` — правило защищает боевые ключи от попадания в git, и трогать
    его нельзя. Файлы стенда попали под то же правило: локально прогон шёл, на
    раннере падал `FileNotFoundError`. Лечится не исключением в правиле, а тем,
    что стенд готовит конфигурацию сам.
    """
    import subprocess

    expected = _stand_expects()
    assert expected, "из compose не извлеклось ни одного файла — проверка смотрит не туда"

    for path in expected.values():
        path.unlink(missing_ok=True)

    subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python"), str(E2E / "configure_stand.py")],
        check=True,
        capture_output=True,
        cwd=ROOT,
    )

    missing = {name: str(path) for name, path in expected.items() if not path.is_file()}

    assert not missing, f"сервис ищет файл, которого генератор не создаёт: {missing}"


def test_stand_config_is_not_committed() -> None:
    """Сгенерированное не должно попадать в репозиторий.

    Иначе однажды туда уедет настоящий ключ: файл с тем же именем в том же
    месте, только с боевым секретом.
    """
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files", "tests/e2e/config", "tests/e2e/secrets"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    ).stdout.split()

    assert not tracked, f"конфигурация стенда попала в git: {tracked}"


def test_stand_config_is_readable_by_the_service_user() -> None:
    """Сгенерированное читается процессом внутри контейнера.

    Контейнеры работают под uid 10001, а файлы создаёт пользователь раннера с
    другим uid. Права «только владельцу» означают, что сервис их не прочитает,
    — и проявляется это не ошибкой доступа, а `degraded` в реестре ключей и
    `503` на каждой загрузке, то есть далеко от причины.

    Секрета в этих файлах нет: они сгенерированы, живут минуты и не выходят за
    пределы сети стенда. В бою правило другое — там владельца меняют вместе с
    правами, об этом говорит `make config-check`.
    """
    import subprocess

    subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python"), str(E2E / "configure_stand.py")],
        check=True,
        capture_output=True,
        cwd=ROOT,
    )

    unreadable = {
        str(path.relative_to(ROOT)): oct(path.stat().st_mode & 0o777)
        for path in _stand_expects().values()
        if not path.stat().st_mode & 0o004
    }

    assert not unreadable, f"сервис не сможет прочитать конфигурацию стенда: {unreadable}"


# --- конвейер проверок безопасности ----------------------------------------

SECURITY_WORKFLOW = ROOT / ".github/workflows/security.yml"
IMAGES_WORKFLOW = ROOT / ".github/workflows/images.yml"


def _security_triggers() -> dict:
    import yaml

    loaded = yaml.safe_load(SECURITY_WORKFLOW.read_text())
    # `on` в YAML 1.1 — булево, и safe_load превращает ключ в True.
    return loaded.get("on") or loaded[True]


def test_security_runs_on_every_push_to_main() -> None:
    """Проверки идут на каждый коммит в основную ветку, а не только по неделям.

    Еженедельный прогон означает, что утечка секрета живёт в репозитории в
    среднем три с половиной дня, прежде чем о ней узнают. За это время её
    успевают склонировать, а ключ — использовать.
    """
    triggers = _security_triggers()

    assert "push" in triggers, "security.yml не запускается на push"
    assert triggers["push"]["branches"] == ["main"]


def test_the_secret_hunt_looks_at_the_whole_repository() -> None:
    """У push-триггера нет фильтра по путям — и не должно появиться.

    Соблазн понятный: не гонять проверку на правку README. Но секрет попадает
    в репозиторий каким угодно файлом — примером конфигурации, вставкой в
    документацию, дампом в комментарии. Список путей означал бы, что утечку
    ищут только там, где её и так не ждут, и отказ был бы молчаливым: прогон
    зелёный, потому что не запускался.
    """
    push = _security_triggers()["push"]

    assert "paths" not in push and "paths-ignore" not in push, (
        "фильтр по путям в security.yml: gitleaks перестанет видеть часть репозитория"
    )


def test_images_are_scanned_on_a_schedule_not_on_push() -> None:
    """Образы проверяются по расписанию, а не на коммит.

    Образ собирается отдельно от коммита: на push его ещё нет, а лежащий в
    реестре под `latest` собран из другого кода. Прогон по нему давал бы
    находки, не относящиеся к отправленному изменению, — то есть приучал бы к
    красному, которое ничего не значит.

    И наоборот: уязвимость в базовом образе появляется без единого коммита,
    поэтому расписание здесь обязательно.
    """
    import yaml

    loaded = yaml.safe_load(IMAGES_WORKFLOW.read_text())
    triggers = loaded.get("on") or loaded[True]

    assert "push" not in triggers, "образы не имеет смысла проверять на каждый коммит"
    assert "schedule" in triggers


def test_the_common_pipeline_is_pinned() -> None:
    """Вызов общего пайплайна указывает версию, а не ветку.

    `@main` означал бы, что набор проверок и пороги меняются у нас без нашего
    участия — в том числе в сторону «стало пропускать». Тег мажорной версии
    двигается, но в пределах совместимости, как принято у actions.
    """
    import yaml

    job = yaml.safe_load(SECURITY_WORKFLOW.read_text())["jobs"]["security"]
    ref = job["uses"].rsplit("@", 1)[1]

    assert ref != "main", "общий пайплайн подключён по ветке"
    assert re.fullmatch(r"v\d+(\.\d+)*|[0-9a-f]{40}", ref), f"непонятная версия: {ref}"


def test_images_keep_their_own_defectdojo_targets() -> None:
    """Шесть образов перечислены явно, а не выводятся из умолчания скрипта.

    `dd-push.sh` без аргументов идёт по ВСЕМ целям, включая исходники и SAST, —
    а их теперь проверяет общий пайплайн. Молчаливое совпадение двух списков
    означало бы двойную заливку в один и тот же engagement DefectDojo, где
    `reimport` одного закрывает находки другого.
    """
    import yaml

    steps = yaml.safe_load(IMAGES_WORKFLOW.read_text())["jobs"]["scan"]["steps"]
    targets = next(s["env"]["TARGETS"] for s in steps if "TARGETS" in s.get("env", {}))

    services = re.search(r'SERVICES_ALL="([^"]+)"', (ROOT / "deploy/dd-push.sh").read_text())

    assert services, "список сервисов в dd-push.sh изменил форму"
    assert services.group(1) in targets, f"состав образов разошёлся со скриптом: {targets}"
    for source_target in ("repo", "sast", "secrets"):
        assert f"'{source_target}" not in targets and f" {source_target} " not in targets, (
            f"«{source_target}» проверяется и здесь, и в общем пайплайне"
        )


# --- версия сборки ---------------------------------------------------------


def test_the_version_is_the_same_in_all_three_places() -> None:
    """Версия объявлена трижды, и расходятся эти объявления молча.

    `pyproject.toml` — источник для установленного пакета. `vscommon.__version__`
    — то, что видит код. Запасное значение в `version.py` — то, что читает
    ОБРАЗ: пакет в нём не устанавливается, метаданных нет, и берётся именно оно.

    Поэтому забытая строчка выглядит так: локально всё говорит `1.0.0`, а
    выкаченный сервис до конца жизни пишет в лог старую версию. Вопрос «какая
    версия сейчас работает» возникает ровно тогда, когда что-то сломалось, и
    неверный ответ на него стоит часа поисков не в том коде.
    """
    import tomllib

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]

    init = (ROOT / "packages/vscommon/__init__.py").read_text()
    in_init = re.search(r'__version__ = "([^"]+)"', init)

    # Из текста, а не из импорта: в тестовом окружении пакет установлен, и
    # `VERSION` придёт из метаданных — то есть запасное значение проверено не
    # будет, хотя именно оно и уезжает в образ.
    source = (ROOT / "packages/vscommon/version.py").read_text()
    fallback = re.search(r'VERSION = "([^"]+)"', source)

    assert in_init and fallback, "объявление версии изменило форму — проверка ослепла"
    assert in_init.group(1) == declared, "vscommon.__version__ разошёлся с pyproject.toml"
    assert fallback.group(1) == declared, (
        "запасное значение в version.py разошлось с pyproject.toml — "
        "образ будет писать в лог старую версию"
    )


# --- откуда берутся образы -------------------------------------------------

GONE_FROM_DOCKER_HUB = ("minio/minio", "minio/mc")
"""Образы, которых на Docker Hub больше нет.

`minio/minio` и `minio/mc` удалены целиком — api хаба отвечает 404, и это не
отказ в доступе и не лимит частоты. Официальный источник теперь quay.io.

Ловушка в том, что ссылка на удалённый образ не ломает ничего, пока он лежит в
кэше машины: боевой сервер работает, конвейер зелёный. Обнаруживается это на
первой машине с пустым кэшем — то есть на новом сервере или в новом кластере,
в самый неудачный момент.
"""


def _image_lines() -> dict[str, list[str]]:
    watched = [
        ROOT / "deploy/docker-compose.yml",
        ROOT / "tests/e2e/docker-compose.yml",
        *sorted((ROOT / "deploy/k8s").rglob("*.yaml")),
    ]
    found = {}
    for path in watched:
        lines = [
            line.strip()
            for line in path.read_text().splitlines()
            if not line.lstrip().startswith("#") and re.search(r"^\s*-?\s*image:", line)
        ]
        if lines:
            found[str(path.relative_to(ROOT))] = lines
    return found


def test_no_image_comes_from_a_deleted_repository() -> None:
    """Ни один манифест не ссылается на образ, которого больше нет."""
    offenders = {}
    for where, lines in _image_lines().items():
        bad = [
            line
            for line in lines
            for gone in GONE_FROM_DOCKER_HUB
            if re.search(rf"image:\s*{re.escape(gone)}[:@]", line)
        ]
        if bad:
            offenders[where] = bad

    assert not offenders, f"образ удалён из Docker Hub: {offenders}"


def test_stateful_images_are_pinned() -> None:
    """У хранилищ состояния тег конкретный, а не плавающий.

    `latest` под данными означает, что мажорная версия хранилища меняется
    сама, в момент, который выбрали не мы, — например при пересоздании пода
    ночью. Для наших сервисов плавающий тег допустим: их состояние снаружи.
    """
    stateful = ("minio", "postgres", "redis", "clamav")
    offenders = {}

    for where, lines in _image_lines().items():
        bad = [
            line
            for line in lines
            if line.endswith(":latest") and any(name in line for name in stateful)
        ]
        if bad:
            offenders[where] = bad

    assert not offenders, f"хранилище состояния на плавающем теге: {offenders}"


def test_the_makefile_calls_files_that_exist() -> None:
    """Цели Makefile ссылаются на существующие скрипты.

    Поймано на живом прогоне: `make test-e2e` звал `configure_sink.py`, хотя
    файл давно переименован в `configure_stand.py`. Не всплывало это потому,
    что конвейер зовёт скрипт напрямую, а через `make` его никто не запускал —
    та же история, что с `corpus/check.py`, пролежавшим сломанным от D1 до M7.1.
    """
    text = (ROOT / "Makefile").read_text()
    called = re.findall(r"\$\(PY\)\s+([\w./-]+\.py)", text)

    missing = sorted({path for path in called if not (ROOT / path).is_file()})

    assert called, "вызовы скриптов из Makefile перестали находиться — проверка ослепла"
    assert not missing, f"Makefile зовёт несуществующие файлы: {missing}"


MUST_REACH_A_CLONE = (
    "deploy/k8s/base/secrets.example.yaml",
    "deploy/k8s/bot/secrets.example.yaml",
    "deploy/.env.example",
    "deploy/proxy.env.example",
)
"""Файлы, без которых свежий клон неполон.

Правила в `.gitignore` намеренно широкие: перечислять пути по одному — способ
однажды завести секрет в новом месте и закоммитить его. Цена широты в том, что
под правило попадает и ПРИМЕР: `secrets.example.yaml` содержит «secret» в
имени, и шаблон, на который ссылаются README и тест, до клона не доезжал.

Обнаруживается это далеко от причины — файл есть локально, в CI его нет. Ровно
так упал первый прогон сквозного стенда.
"""


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="нужен git-репозиторий")
@pytest.mark.parametrize("relative", MUST_REACH_A_CLONE)
def test_examples_are_not_swallowed_by_gitignore(relative: str) -> None:
    """Пример не должен исчезать вместе с секретом, который он показывает."""
    path = ROOT / relative
    assert path.is_file(), f"{relative}: файла нет вовсе"

    ignored = subprocess.run(
        ["git", "check-ignore", "-q", relative],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )

    assert ignored.returncode != 0, (
        f"{relative} игнорируется .gitignore — в свежем клоне его не будет"
    )


def test_the_config_helper_checks_before_it_uploads() -> None:
    """Скрипт заливки конфигурации сначала проверяет, потом применяет.

    `kubectl create configmap --from-file` принимает что угодно. Битый JSON
    уезжает в кластер молча, сервис не падает — пишет ERROR и работает на
    значениях по умолчанию. То есть файлы проверяются по чужим порогам, копии
    не выгружаются, а `kubectl get pods` показывает зелёное.

    Ровно это и произошло: незакрытая скобка в `policies.json` пролежала в
    ConfigMap, gateway каждые полминуты писал «файл политик не читается», а
    причину искали в notifier.
    """
    script = (ROOT / "deploy/k8s/config.sh").read_text()
    # Только исполняемые строки: слово `kubectl` встречается и в пояснении,
    # почему обёртка вообще нужна, — сравнивать надо не с ним.
    code = [line for line in script.splitlines() if not line.lstrip().startswith("#")]

    check = next(i for i, line in enumerate(code) if "build_policy(" in line)
    upload = next(i for i, line in enumerate(code) if line.startswith("kubectl"))

    assert check < upload, "конфигурация заливается раньше, чем проверяется"
    assert "set -eu" in script, "без -e падение проверки не остановит заливку"
