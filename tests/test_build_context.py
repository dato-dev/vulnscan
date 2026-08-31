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
    """Источники всех `COPY` — без флагов и без последнего аргумента-приёмника."""
    sources: list[str] = []
    for line in dockerfile.read_text().splitlines():
        if not line.startswith("COPY "):
            continue
        args = [a for a in line.split()[1:] if not a.startswith("--")]
        sources += args[:-1]
    return sources


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
    assert not _ignored("requirements-telemetry.txt"), "файлы в корне не исключены"
    assert not _ignored("packages/vscommon"), "общий код едет в образ"


def test_requirements_are_reachable_from_context() -> None:
    """Файлы закрепления версий лежат там, откуда их можно скопировать.

    Отдельно от параметризованных проверок выше: это то самое место, на
    котором сборка и упала, и оно стоит отдельной строки в выводе.
    """
    for name in ("requirements-telemetry.txt", "requirements-metrics.txt"):
        assert (ROOT / name).exists(), f"{name} нет в корне"
        assert not _ignored(name), f"{name} исключён из контекста сборки"


def test_pip_install_targets_are_copied() -> None:
    """`pip install -r` ссылается на файл, который образ действительно копирует.

    Включая вложенную ссылку: `requirements-telemetry.txt` тянет
    `-r requirements-metrics.txt`, и без второго файла установка падает уже
    внутри сборки — там, где ошибка дороже.
    """
    nested = {
        line.split()[1]
        for line in (ROOT / "requirements-telemetry.txt").read_text().splitlines()
        if line.startswith("-r ")
    }

    for dockerfile in DOCKERFILES:
        text = dockerfile.read_text()
        installed = set(re.findall(r"pip install[^\n]*-r\s+(\S+)", text))
        if not installed:
            continue
        copied = {Path(src).name for src in _copied(dockerfile)}
        for target in installed:
            name = Path(target).name
            assert name in copied, f"{dockerfile.parent.name}: ставит {name}, но не копирует его"
            if name == "requirements-telemetry.txt":
                for extra in nested:
                    assert extra in copied, (
                        f"{dockerfile.parent.name}: {name} тянет {extra}, "
                        "а он в образ не копируется"
                    )
