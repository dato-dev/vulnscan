"""Версия сборки видна в логах каждого сервиса.

Вопрос «какая версия сейчас работает» возникает ровно тогда, когда что-то
сломалось, и ответ на него нужен быстрее всего. Выводить его косвенно — из тега
в compose, из памяти о том, выкатывали ли этот тег, из истории git — значит
тратить время на восстановление того, что процесс знал про себя с самого
начала.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def restore_logging() -> object:
    """Настройка логов глобальна: вернём как было, иначе поедут чужие тесты."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def test_startup_line_carries_the_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Первая запись процесса содержит версию и тег образа."""
    from vscommon.logging import setup_logging

    setup_logging("gateway", fmt="json")
    record = json.loads(capsys.readouterr().out.strip().splitlines()[-1])

    assert record["service"] == "gateway"
    assert record["version"]
    assert "image_tag" in record


def test_unknown_tag_is_named_not_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Не заданный тег пишется как `unknown`, а не пустой строкой.

    Пустое значение читается как «версии нет», `unknown` — как «нам её не
    сказали». Разница существенная: во втором случае чинить надо выкат, а не
    код.
    """
    from vscommon.version import UNKNOWN, image_tag

    monkeypatch.delenv("IMAGE_TAG", raising=False)
    assert image_tag() == UNKNOWN

    monkeypatch.setenv("IMAGE_TAG", "   ")
    assert image_tag() == UNKNOWN, "пробелы — это тоже «не задан»"


def test_tag_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Тег приходит извне: в коде его знать неоткуда."""
    from vscommon.version import image_tag

    monkeypatch.setenv("IMAGE_TAG", "v1.2.1")
    assert image_tag() == "v1.2.1"


def test_version_and_tag_are_different_things() -> None:
    """Версия исходников и тег образа не подменяют друг друга.

    Они расходятся законно и постоянно: один и тот же исходник уезжает под
    тегами `v1.2.0` и `latest`. Поэтому в лог идут оба, а не один «главный».
    """
    from vscommon.version import build_info

    info = build_info()

    assert set(info) == {"version", "image_tag"}
    assert "service" not in info, "имя сервиса подставляет форматтер, дублировать нельзя"


def test_tracing_reports_the_same_version() -> None:
    """Трассировка берёт версию оттуда же, а не своей строкой.

    Раньше она была вписана в аргумент по умолчанию отдельно. Две константы с
    одинаковым смыслом расходятся молча, и обнаруживается это в Tempo, где
    версия сервиса вдруг отстаёт от логов.
    """
    import inspect

    from vscommon.telemetry import setup_tracing
    from vscommon.version import VERSION

    assert inspect.signature(setup_tracing).parameters["version"].default == VERSION


def test_every_service_logs_its_version() -> None:
    """Каждый сервис зовёт `setup_logging`, а значит сообщает версию.

    Строчка «залогируй версию», которую надо не забыть добавить в шесть мест,
    однажды не появится в седьмом — и обнаружится это при разборе аварии, у
    того самого сервиса, который сломался. Поэтому версия пишется внутри
    `setup_logging`, а проверяется здесь то, что его действительно зовут все.
    """
    missing = [
        path.relative_to(ROOT).parts[1]
        for path in ROOT.glob("services/*/*/main.py")
        if "setup_logging(" not in path.read_text()
    ]

    assert not missing, f"сервис не настраивает логи и не сообщает версию: {missing}"


def test_mirror_exporter_reports_its_version() -> None:
    """Экспортёр зеркала — тоже.

    Он собран на alpine вокруг чужой утилиты и общий код не тянет, поэтому
    логирует своими средствами. Вопрос «что сейчас работает» от этого не
    меняется.
    """
    source = (ROOT / "services/cvdmirror/exporter.py").read_text()

    assert "IMAGE_TAG" in source
    assert "запускается" in source


def test_image_tag_reaches_our_containers() -> None:
    """Тег доезжает до процесса через окружение.

    В compose он и так есть — в имени образа. Но имя образа знает Docker, а не
    процесс внутри него: без явной переменной сервис о своём теге не
    догадывается.
    """
    import yaml

    compose = yaml.safe_load((ROOT / "deploy/docker-compose.yml").read_text())
    ours = {
        path.relative_to(ROOT).parts[1]
        for path in ROOT.glob("services/*/*/main.py")
        if "setup_logging(" in path.read_text()
    } | {"deepscan", "cvdmirror"}

    missing = [
        name
        for name in ours
        if name in compose["services"]
        and "IMAGE_TAG" not in (compose["services"][name].get("environment") or {})
    ]

    assert not missing, f"сервисы не получают свой тег: {sorted(missing)}"
