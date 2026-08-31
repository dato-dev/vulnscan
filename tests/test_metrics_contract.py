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
PINS = ROOT / "requirements-telemetry.txt"
METRIC_PINS = ROOT / "requirements-metrics.txt"


def _pinned() -> dict[str, str]:
    """Закреплённые версии из обоих файлов: пакет → версия."""
    pins: dict[str, str] = {}
    for path in (PINS, METRIC_PINS):
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-r")):
                continue
            name, version = line.split("==")
            pins[name] = version
    return pins


def test_versions_are_pinned_exactly() -> None:
    """Никаких `>=` в файлах закрепления.

    Нижняя граница означает, что каждая пересборка образа могла принести
    другую версию, а какая работает на стенде — выяснялось бы `pip freeze`
    внутри контейнера.
    """
    loose = [
        line
        for path in (PINS, METRIC_PINS)
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith(("#", "-r")) and "==" not in line
    ]

    assert not loose, f"версия задана не точно: {loose}"


def test_dockerfiles_do_not_name_versions() -> None:
    """Dockerfile ставит SDK по файлу, а не перечисляет версии сам.

    Регрессия, ради которой: версии жили в семи местах — pyproject и шесть
    Dockerfile, — и разъезжались молча. Разошедшиеся версии клиента метрик
    дают разный формат экспозиции, и Prometheus перестаёт разбирать часть
    рядов, ничего об этом не сообщая.
    """
    offenders = {}
    for path in [*ROOT.glob("services/*/Dockerfile"), *ROOT.glob("examples/*/Dockerfile")]:
        named = [
            line.strip()
            for line in path.read_text().splitlines()
            if not line.lstrip().startswith("#")
            and re.search(r'"(opentelemetry-[a-z-]+|prometheus-client)[<>=]', line)
        ]
        if named:
            offenders[str(path.relative_to(ROOT))] = named

    assert not offenders, f"версия SDK названа в Dockerfile мимо общего файла: {offenders}"


def test_pyproject_matches_the_pins() -> None:
    """Локальные тесты и образ работают на одном и том же SDK.

    Разъехавшись, они проверяли бы разный код: расхождение версий телеметрии
    проявляется не ошибкой, а изменившимися именами атрибутов спанов.
    """
    text = (ROOT / "pyproject.toml").read_text()
    declared = dict(re.findall(r'"((?:opentelemetry|prometheus)[a-z-]*)==([0-9][^"]*)"', text))

    assert declared, "в pyproject не нашлось закреплённых версий телеметрии"
    assert declared == _pinned(), (
        f"pyproject и файлы закрепления разошлись: "
        f"pyproject={declared}, файлы={_pinned()}"
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
