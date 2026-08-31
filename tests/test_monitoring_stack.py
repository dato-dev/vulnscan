"""Проверки стека мониторинга (`deploy/lgtp`).

M10.4, M10.5. Всё здесь написано под один класс сбоев: **отсутствие метрики
выглядит как отсутствие событий.** Prometheus без цели стартует без ошибок,
Grafana рисует пустую панель, а пустая панель неотличима от «ничего не
происходило». Ни один из трёх случаев, ради которых написан файл, не проявился
ошибкой — все три нашлись глазами по пустому графику.

Стек лежит в рабочем каталоге, но в репозиторий пока не закоммичен, поэтому
проверки пропускаются, если каталога нет: `make test` обязан проходить без него.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).parent.parent
LGTP = ROOT / "deploy/lgtp"

pytestmark = pytest.mark.skipif(not LGTP.is_dir(), reason="стек мониторинга не в репозитории")


def _load(path: Path) -> dict[str, Any]:
    return dict(yaml.safe_load(path.read_text()))


def _compose() -> dict[str, Any]:
    return _load(LGTP / "docker-compose.yml")


def _prometheus() -> dict[str, Any]:
    return _load(LGTP / "prometheus/prometheus.yml")


def _scraped_hosts() -> set[str]:
    """Хосты из всех заданий: `localhost` приводим к имени самого Prometheus."""
    hosts: set[str] = set()
    for job in _prometheus()["scrape_configs"]:
        for static in job.get("static_configs", []):
            for entry in static["targets"]:
                host = entry.rsplit(":", 1)[0]
                hosts.add("prometheus" if host == "localhost" else host)
    return hosts


# --- цели ---------------------------------------------------------------

# Сервисы стека, у которых собственных метрик нет. Список закрытый и пустой:
# все восемь компонентов их отдают. Он существует, чтобы исключение нельзя
# было добавить молча — только правкой этого множества.
NO_METRICS: frozenset[str] = frozenset()


def test_every_stack_service_is_scraped() -> None:
    """Каждый компонент стека мониторинга сам находится под наблюдением.

    Регрессия: при переписывании `prometheus.yml` под цели vulnscantg в файле
    остались только они — цели самого стека (node-exporter, loki, tempo,
    alloy, grafana, alertmanager, сам Prometheus) исчезли вместе со старым
    содержимым. Prometheus стартовал нормально и собирал половину.

    Отдельно про Loki и Tempo: когда они перестают принимать данные, узнать
    об этом больше неоткуда — молчат они ровно так же, как при отсутствии
    трафика.
    """
    expected = set(_compose()["services"]) - NO_METRICS
    missing = expected - _scraped_hosts()

    assert not missing, f"компоненты стека никем не скрейпятся: {sorted(missing)}"


def test_vulnscan_services_are_scraped_by_the_stack() -> None:
    """Сервисы vulnscantg — тоже цели этого Prometheus.

    Их нет в compose стека: они живут в `deploy/docker-compose.yml` и
    подключены к общей сети. Поэтому проверка отдельная — источник ожиданий
    здесь код, а не compose.
    """
    serving = {
        path.relative_to(ROOT).parts[1]
        for path in ROOT.glob("services/*/*/main.py")
        if "serve_metrics(" in path.read_text()
    } | {"gateway"}

    missing = serving - _scraped_hosts()
    assert not missing, f"сервисы отдают метрики, но стек их не собирает: {sorted(missing)}"


# --- алерты -------------------------------------------------------------


def test_alerting_has_an_addressee() -> None:
    """Правила должны кому-то отправляться.

    Регрессия: блока `alerting` в файле не было вовсе. Alertmanager в стеке
    стоял, десять правил загружались и срабатывали — и уходили в пустоту.
    Prometheus про это не жалуется: конфигурация без адресата валидна.
    """
    alerting = _prometheus().get("alerting") or {}
    targets = {
        entry
        for manager in alerting.get("alertmanagers", [])
        for static in manager.get("static_configs", [])
        for entry in static["targets"]
    }
    assert targets, "правила есть, а Alertmanager в конфигурации не указан"

    hosts = {t.rsplit(":", 1)[0] for t in targets}
    assert hosts <= set(_compose()["services"]), f"адресат не из этого стека: {hosts}"


def test_rule_files_resolve_to_real_rules() -> None:
    """Маска `rule_files` указывает на смонтированный каталог, и он не пуст.

    Регрессия: маска ссылалась на путь, которого в контейнере не было. Файл с
    правилами лежал рядом и выглядел рабочим, но не загружался ни разу —
    Prometheus молча стартует и с нулём правил.
    """
    config = _prometheus()
    patterns = config.get("rule_files") or []
    assert patterns, "правила не подключены"

    mounts = _compose()["services"]["prometheus"]["volumes"]
    # `./prometheus/rules:/etc/prometheus/rules:ro,z` → куда смотрит контейнер.
    mounted = {m.split(":")[1]: m.split(":")[0] for m in mounts if m.startswith("./")}

    for pattern in patterns:
        directory = str(Path(pattern).parent)
        assert directory in mounted, f"маска {pattern} указывает на несмонтированный путь"
        local = LGTP / mounted[directory].removeprefix("./")
        found = list(local.glob(Path(pattern).name))
        assert found, f"по маске {pattern} в {local} нет ни одного файла"


def test_alert_rules_are_valid() -> None:
    """Каждое правило — с выражением, длительностью и пояснением.

    Алерт без `for` срабатывает на одиночном выбросе, алерт без описания
    заставляет дежурного искать смысл в имени метрики.
    """
    for path in (LGTP / "prometheus/rules").glob("*.yml"):
        for group in _load(path)["groups"]:
            for rule in group["rules"]:
                name = rule.get("alert") or rule.get("record")
                assert rule.get("expr"), f"{name}: нет выражения"
                if "alert" not in rule:
                    continue
                assert rule.get("for"), f"{name}: нет `for` — сработает на одиночном выбросе"
                annotations = rule.get("annotations") or {}
                assert annotations.get("summary") or annotations.get(
                    "description"
                ), f"{name}: нечего показать дежурному"


# --- монтируемые файлы --------------------------------------------------

# Пусто, и таким должно остаться: стек разворачивается из репозитория целиком.
# Множество существует, чтобы отсутствующий файл нельзя было принять молча —
# Docker создаёт на его месте каталог, и компонент падает на разборе
# конфигурации, а выглядит это как ошибка конфигурации, а не как пропажа.
KNOWN_MISSING: set[str] = set()


def _config_mounts() -> dict[str, list[str]]:
    """Сервис → его монтирования конфигурации.

    Только `ro`: конфигурация обязана существовать заранее, а каталоги данных
    (`./tempo/data`) контейнер создаёт сам, и требовать их в репозитории
    неверно — там им и не место.
    """
    return {
        name: [
            v.split(":")[0]
            for v in (svc.get("volumes") or [])
            if v.startswith("./") and "ro" in v.split(":")[-1].split(",")
        ]
        for name, svc in _compose()["services"].items()
    }


def test_mounted_paths_exist() -> None:
    """Каждый монтируемый путь есть в репозитории.

    Отсутствующий файл Docker подменяет каталогом — компонент падает на
    разборе конфигурации, и выглядит это как ошибка конфигурации, а не как
    отсутствие файла. Мы наступали на это трижды: `freshclam.conf`,
    `prometheus.yml`, конфигурация прокси.
    """
    missing = {
        path
        for paths in _config_mounts().values()
        for path in paths
        if not (LGTP / path.removeprefix("./")).exists()
    }
    unexpected = missing - KNOWN_MISSING

    assert not unexpected, f"compose монтирует то, чего нет в репозитории: {sorted(unexpected)}"


def test_known_missing_is_not_stale() -> None:
    """Файл появился — убери его из списка исключений.

    Иначе список переживёт свою причину и начнёт прятать новые пропажи.
    """
    resurrected = {path for path in KNOWN_MISSING if (LGTP / path.removeprefix("./")).exists()}

    assert not resurrected, f"эти пути уже на месте, вычеркни их из KNOWN_MISSING: {resurrected}"


# --- маршрутизация ссылается на существующие имена -----------------------


def _alert_names() -> set[str]:
    return {
        rule["alert"]
        for path in (LGTP / "prometheus/rules").glob("*.yml")
        for group in _load(path)["groups"]
        for rule in group["rules"]
        if "alert" in rule
    }


def _alertmanager() -> dict[str, Any]:
    return _load(LGTP / "alertmanager/alertmanager.yml")


def _referenced_alertnames() -> set[str]:
    """Имена алертов, упомянутые в маршрутах и правилах подавления."""
    import re

    pattern = re.compile(r'alertname\s*=\s*"([^"]+)"')
    config = _alertmanager()
    blobs: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str):
            blobs.append(node)

    walk(config)
    return {m for blob in blobs for m in pattern.findall(blob)}


def test_routing_references_existing_alerts() -> None:
    """Маршрут по имени алерта, которого нет, не ошибка — он просто не сработает.

    Регрессия: конфигурация ссылалась на `Watchdog` и `TargetDown` — правило
    подавления и отдельный маршрут, — а таких правил не существовало. Обе
    записи выглядели работающими и не делали ничего.
    """
    unknown = _referenced_alertnames() - _alert_names()

    assert not unknown, f"маршрутизация ссылается на несуществующие алерты: {sorted(unknown)}"


def test_watchdog_is_always_firing() -> None:
    """Watchdog обязан быть безусловным.

    Это единственное правило, которое доказывает, что путь доставки жив.
    Молчащий Alertmanager неотличим от спокойной системы — отличить можно
    только тем, что обязано шуметь всегда.
    """
    watchdog = [
        rule
        for path in (LGTP / "prometheus/rules").glob("*.yml")
        for group in _load(path)["groups"]
        for rule in group["rules"]
        if rule.get("alert") == "Watchdog"
    ]
    assert watchdog, "нет правила Watchdog — сбой самого оповещения будет незаметен"
    assert watchdog[0]["expr"].strip() == "vector(1)", "Watchdog должен гореть безусловно"


def test_every_severity_has_a_route() -> None:
    """Каждое значение severity доходит до получателя.

    Незнакомый severity не ошибка: алерт уедет в маршрут по умолчанию и
    смешается с остальными — либо разбудит дежурного, либо потеряется среди
    предупреждений.
    """
    used = {
        rule.get("labels", {}).get("severity")
        for path in (LGTP / "prometheus/rules").glob("*.yml")
        for group in _load(path)["groups"]
        for rule in group["rules"]
        if "alert" in rule
    } - {None}

    config = _alertmanager()
    routed = {"none"}  # severity: none — Watchdog, он уходит в blackhole по имени
    for route in config["route"].get("routes", []):
        for matcher in route.get("matchers", []):
            if matcher.startswith("severity"):
                routed.add(matcher.split("=", 1)[1].strip().strip('"'))

    assert used <= routed, f"severity без своего маршрута: {sorted(used - routed)}"


# --- дашборд дежурного ---------------------------------------------------

DUTY = ROOT / "deploy/grafana/dashboards/vulnscan-duty.json"

# Watchdog горит всегда по построению: график из единиц ничего не объясняет,
# его место — в статусной панели, и она есть.
NO_PANEL_NEEDED = {"Watchdog"}


def _duty() -> dict[str, Any]:
    import json

    return dict(json.loads(DUTY.read_text()))


def test_every_alert_has_a_panel() -> None:
    """Сработавший алерт должен вести на картинку, а не на поиск нужной панели.

    Дашборд собирается из тех же файлов правил, поэтому разойтись они могут
    только если забыть пересобрать — что и ловится здесь.
    """
    titled = {panel["title"].split(" · ")[0] for panel in _duty()["panels"]}
    missing = _alert_names() - NO_PANEL_NEEDED - titled

    assert not missing, f"алерт без панели: {sorted(missing)}"


def test_duty_panels_match_alert_expressions() -> None:
    """Панель показывает ровно то выражение, по которому срабатывает алерт.

    Похожий, но другой запрос хуже отсутствия панели: он выглядит объяснением
    и объясняет не то.
    """
    expressions = {
        rule["alert"]: " ".join(rule["expr"].split())
        for path in (LGTP / "prometheus/rules").glob("*.yml")
        for group in _load(path)["groups"]
        for rule in group["rules"]
        if "alert" in rule
    }

    mismatched = {}
    for panel in _duty()["panels"]:
        name = panel["title"].split(" · ")[0]
        if name not in expressions:
            continue
        shown = " ".join(panel["targets"][0]["expr"].split())
        if shown != expressions[name]:
            mismatched[name] = {"правило": expressions[name], "панель": shown}

    assert not mismatched, f"панель показывает не то, по чему срабатывает алерт: {mismatched}"


# --- второго стека наблюдаемости больше нет ------------------------------


def test_main_compose_has_no_second_monitoring_stack() -> None:
    """В `deploy/docker-compose.yml` не должно быть своего коллектора и Prometheus.

    Они там были под профилем `observability` — на случай возврата изоляции
    воркера, когда телеметрию придётся выносить из `internal: true` сети. Пока
    изоляция снята, профиль не поднимался ни разу, а конфигурация
    неиспользуемого сервиса устаревает молча: версия образа отстала на
    сорок релизов, и заметили это только при сверке.

    Хуже другое: два коллектора с похожими именами — это готовая ошибка в
    `OTEL_ENDPOINT`. Адрес неработающего приёмника не вызывает отказа,
    экспортёр просто пишет в никуда.

    Вернётся вместе с изоляцией — тогда и заведём заново, под текущие версии.
    """
    import re

    compose = (ROOT / "deploy/docker-compose.yml").read_text()
    images = set(re.findall(r"^\s*image:\s*(\S+)", compose, re.M))

    offenders = {
        image
        for image in images
        if "opentelemetry-collector" in image or image.startswith("prom/prometheus")
    }

    assert not offenders, (
        f"в основном compose снова появился свой стек наблюдения: {sorted(offenders)}. "
        "Метрики и трейсы собирает стек в deploy/lgtp."
    )
