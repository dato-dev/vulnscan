"""M10.1, M10.8: инвентарь метрик — контракт, а не описание.

Документ, который расходится с кодом, хуже отсутствующего: по нему принимают
решения, а он врёт. Здесь `docs/metrics.md` и `vscommon/metrics.py` сверяются
друг с другом, поэтому забыть строку в таблице так же нельзя, как забыть
объявить метрику.

Заодно проверяются договорённости об именах. Они не косметика: имя метрики —
публичный контракт панелей и алертов, и его нарушение обнаруживается не
ошибкой, а пустым графиком.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry

from vscommon.metrics import Metrics

DOC = Path(__file__).parent.parent / "docs/metrics.md"


def _declared() -> dict[str, tuple[str, tuple[str, ...]]]:
    """Метрики из кода: имя → (тип, метки).

    Имя приводится к тому виду, в каком метрика видна в `/metrics`: клиент
    хранит счётчик без суффикса, а отдаёт с `_total`, и в таблице должно
    стоять то, что пишут в запросах.
    """
    metrics = Metrics(CollectorRegistry())
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    for attr, obj in vars(metrics).items():
        if attr == "registry":
            continue
        name = obj._name + "_total" if obj._type == "counter" else obj._name
        result[name] = (obj._type, tuple(obj._labelnames))
    return result


def _documented() -> dict[str, tuple[str, tuple[str, ...]]]:
    """Метрики из таблицы инвентаря: имя → (тип, метки)."""
    rows: dict[str, tuple[str, tuple[str, ...]]] = {}
    for line in DOC.read_text().splitlines():
        match = re.match(r"^\|\s*`(vs_[a-z_]+)`\s*\|\s*(\w+)\s*\|\s*(.*?)\s*\|", line)
        if not match:
            continue
        name, kind, labels_cell = match.groups()
        labels = tuple(sorted(re.findall(r"`([a-z_]+)`", labels_cell)))
        rows[name] = (kind, labels)
    return rows


def test_inventory_lists_every_metric() -> None:
    """Каждая метрика кода есть в таблице.

    Иначе документ отвечает на вопрос «что мы меряем» неполно, а именно за
    этим в него и приходят — критерий M10.1 звучит как «видно, какой метрики
    не хватает, без чтения кода».
    """
    missing = set(_declared()) - set(_documented())

    assert not missing, f"метрики есть в коде, но не в docs/metrics.md: {sorted(missing)}"


def test_inventory_has_no_ghosts() -> None:
    """И наоборот: строка в таблице без метрики в коде.

    Такая строка опаснее пропуска. По ней напишут запрос, запрос вернёт
    пустоту, и пустота будет выглядеть как отсутствие событий.
    """
    ghosts = set(_documented()) - set(_declared())

    assert not ghosts, f"в таблице есть, в коде нет: {sorted(ghosts)}"


def test_inventory_types_and_labels_match() -> None:
    """Тип и метки в таблице совпадают с объявленными.

    Метки важнее типа: по ним пишут `sum by (...)`, и лишняя метка в
    документе даёт запрос, который молча схлопывает не то.
    """
    declared, documented = _declared(), _documented()
    mismatched = {
        name: {"код": declared[name], "документ": documented[name]}
        for name in declared.keys() & documented.keys()
        if declared[name][0] != documented[name][0]
        or set(declared[name][1]) != set(documented[name][1])
    }

    assert not mismatched, f"таблица разошлась с кодом: {mismatched}"


# --- договорённости об именах -------------------------------------------


@pytest.mark.parametrize("name", sorted(_declared()))
def test_metric_name_follows_conventions(name: str) -> None:
    """Префикс, суффикс счётчика, единица в имени.

    Секунды, а не миллисекунды: набор корзин у нас разный, а единица — общая,
    иначе один и тот же `rate(...)` на двух панелях означает разное.
    """
    kind, _labels = _declared()[name]

    assert name.startswith("vs_"), "префикс vs_ обязателен: он отделяет наш код от чужого"

    if kind == "counter":
        assert name.endswith("_total"), "счётчик обязан заканчиваться на _total"
    else:
        assert not name.endswith("_total"), "_total только у счётчиков"

    assert "_ms" not in name and not name.endswith("_millis"), "время меряется в секундах"


@pytest.mark.parametrize("name", sorted(_declared()))
def test_labels_are_closed_sets(name: str) -> None:
    """Метка не должна быть тем, что приходит снаружи.

    Метка с растущим набором значений — это ряд на запрос: `scan_id`, sha256,
    имя файла, сырой путь URL. Для тенанта есть `tenant_label()`, он
    схлопывает незнакомого в `other`; сюда он проходит именно поэтому.
    """
    forbidden = {"scan_id", "sha256", "filename", "file", "url", "path", "key_id", "user"}
    _kind, labels = _declared()[name]

    banned = set(labels) & forbidden
    assert not banned, f"метка с неограниченным набором значений: {sorted(banned)}"


def test_seconds_metrics_are_histograms() -> None:
    """`_seconds` в имени означает измерение длительности.

    Счётчик с таким именем читался бы как «сумма секунд» и ломал бы
    привычный `histogram_quantile`. Исключение — gauge: возраст и отставание
    это тоже секунды, но мгновенные.
    """
    wrong = {
        name: kind
        for name, (kind, _labels) in _declared().items()
        if name.endswith("_seconds") and kind not in {"histogram", "gauge"}
    }

    assert not wrong, f"метрика в секундах не гистограмма и не gauge: {wrong}"


def test_metrics_are_declared_in_one_place() -> None:
    """Метрика, заведённая мимо `vscommon/metrics.py`, не попадёт в реестр.

    И не отдастся — молча, потому что процесс отдаёт свой реестр, а не
    глобальный. Исключения: экспортёр зеркала и пример подключения, у них
    свои процессы и свои префиксы.
    """
    root = Path(__file__).parent.parent
    allowed = {
        root / "packages/vscommon/metrics.py",
        root / "services/cvdmirror/exporter.py",
        root / "examples/feedback-site/feedback_site.py",
    }
    pattern = re.compile(r"^\s*(?!#)\w*\s*=?\s*(Counter|Gauge|Histogram|Summary)\(", re.M)

    offenders = [
        str(path.relative_to(root))
        for path in [*root.glob("packages/**/*.py"), *root.glob("services/**/*.py")]
        if path not in allowed and pattern.search(path.read_text())
    ]

    assert not offenders, f"метрика объявлена вне реестра процесса: {offenders}"


# --- обратное покрытие: метрику должно быть где видно --------------------

# Метрики, у которых панели нет намеренно: имя → почему. Пусто, и таким должно
# остаться. Множество существует, чтобы пропуск нельзя было принять молча —
# только вписав объяснение.
NO_PANEL_NEEDED: dict[str, str] = {}


def _shown_metrics() -> set[str]:
    """Имена `vs_*`, встречающиеся в панелях и в правилах алертов."""
    root = Path(__file__).parent.parent
    text = "\n".join(
        path.read_text()
        for path in [
            *root.glob("deploy/grafana/dashboards/*.json"),
            *root.glob("deploy/lgtp/prometheus/rules/*.yml"),
            *root.glob("deploy/config/alerts.yml"),
        ]
    )
    # Ищем по тексту файла, а не по разобранной структуре: запросы лежат
    # внутри строк, и в JSON, и в YAML. Суффиксы гистограмм Prometheus
    # добавляет сам — приводим к базовому имени.
    names = set(re.findall(r"\bvs_[a-z_]+\b", text))
    return {re.sub(r"_(bucket|count|sum|created)$", "", name) for name in names}


def test_every_metric_is_visible_somewhere() -> None:
    """Метрика без панели и без алерта существует только в `/metrics`.

    То есть о её поломке никто не узнает — а метрики заводятся ровно затем,
    чтобы узнать. Это обратная сторона проверки инвентаря: та следит, чтобы
    метрику описали, эта — чтобы на неё смотрели.
    """
    invisible = set(_declared()) - _shown_metrics() - set(NO_PANEL_NEEDED)

    assert not invisible, (
        f"метрика есть, но её нигде не видно: {sorted(invisible)}. "
        "Заведите панель или впишите в NO_PANEL_NEEDED с объяснением."
    )


def test_no_panel_exceptions_are_real() -> None:
    """Исключение, у которого появилась панель, вычёркивается.

    Иначе список переживает свою причину и начинает прятать новые пропуски.
    """
    stale = set(NO_PANEL_NEEDED) & _shown_metrics()

    assert not stale, f"панель появилась, уберите из NO_PANEL_NEEDED: {sorted(stale)}"


# --- версии SDK (M4.16) --------------------------------------------------

ROOT = Path(__file__).parent.parent
PYPROJECT = ROOT / "pyproject.toml"
LOCK = ROOT / "uv.lock"

SDK = re.compile(r"^(opentelemetry-[a-z-]+|prometheus-client)$")
"""Библиотеки, чью версию мало закрепить локом: она правится осознанно."""


def _pinned() -> dict[str, str]:
    """Точные версии SDK из групп `telemetry` и `metrics`: пакет → версия.

    Раньше они лежали в `requirements-telemetry.txt` и
    `requirements-metrics.txt` — отдельных файлах рядом с `pyproject.toml`.
    После переезда на `uv.lock` такая пара стала вторым источником правды при
    одном локе, и файлы убраны: группа в `pyproject.toml` и есть закрепление.
    """
    text = PYPROJECT.read_text()
    return {
        name: version
        for name, version in re.findall(r'"([a-z][a-z0-9-]*)==([0-9][^"]*)"', text)
        if SDK.fullmatch(name)
    }


def test_sdk_versions_are_pinned_exactly() -> None:
    """У SDK наблюдаемости — `==`, а не `>=`, несмотря на наличие лока.

    Лок обеспечивает воспроизводимость: пересборка не принесёт другую версию.
    Но он же обновляется одной командой, и `>=` означал бы, что версия
    телеметрии меняется заодно с любым другим обновлением. Расхождение версий
    телеметрии проявляется не ошибкой, а молча изменившимися именами
    атрибутов спанов, поэтому её правка должна быть отдельным действием —
    строкой в `pyproject.toml`, написанной руками.
    """
    text = PYPROJECT.read_text()
    loose = re.findall(r'"((?:opentelemetry-[a-z-]+|prometheus-client)[<>~]=[^"]*)"', text)

    assert not loose, f"версия SDK задана не точно: {loose}"
    assert _pinned(), "в pyproject не нашлось закреплённых версий SDK"


def test_pins_cover_the_whole_sdk() -> None:
    """Закреплены все три библиотеки трассировки и клиент метрик.

    Забытая строка не ломается заметно: недостающая библиотека приезжает
    транзитивно, версией по вкусу разрешателя.
    """
    assert set(_pinned()) == {
        "opentelemetry-api",
        "opentelemetry-sdk",
        "opentelemetry-exporter-otlp-proto-http",
        "prometheus-client",
    }


def test_lock_agrees_with_the_pins() -> None:
    """`uv.lock` содержит ровно закреплённые версии.

    Лок — это то, что действительно поедет в образ. Разойдясь с
    `pyproject.toml`, он собрал бы образ на версии, которой никто не называл,
    и заметить это можно было бы только изнутри контейнера.
    """
    lock = LOCK.read_text()
    missing = {
        name: version
        for name, version in _pinned().items()
        if f'name = "{name}"\nversion = "{version}"' not in lock
    }

    assert not missing, (
        f"лок не содержит закреплённых версий: {missing}. "
        "После правки pyproject нужен `make lock`."
    )


def test_installed_matches_the_pins() -> None:
    """Установленное в окружении совпадает с закреплённым.

    Иначе зелёные тесты ничего не говорят о том, что поедет в образ.
    """
    import importlib.metadata as md

    mismatched = {}
    for name, expected in _pinned().items():
        try:
            actual = md.version(name)
        except md.PackageNotFoundError:
            mismatched[name] = "не установлен"
            continue
        if actual != expected:
            mismatched[name] = f"закреплено {expected}, установлено {actual}"

    assert not mismatched, f"окружение разошлось с закреплением: {mismatched}"
