"""Дашборды Grafana ссылаются только на метрики, которые сервис отдаёт.

Панель с опечаткой в имени метрики выглядит исправной и молча показывает
«нет данных» — заметить это можно только когда дашборд действительно
понадобился, то есть во время инцидента.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DASHBOARDS = sorted((Path(__file__).parent.parent / "deploy/grafana/dashboards").glob("*.json"))

# Суффиксы, которые Prometheus добавляет сам.
_SUFFIXES = ("_total", "_bucket", "_count", "_sum", "_created")

EXTERNAL_METRICS = {
    # Их считает OTel Collector коннекторами `spanmetrics` и `servicegraph`.
    # Не генератор Tempo: у того модуль стартует, но в кольце нет участников,
    # и спаны до него не доходят (grafana/tempo issue #5479, без решения).
    #
    # Проверить существование этих метрик мы не можем, но опечатку поймать
    # обязаны — список закреплён здесь и заодно документирует зависимость.
    "traces_service_graph_request_total",
    "traces_service_graph_request_failed_total",
    "traces_span_metrics_duration_seconds_bucket",
    "traces_span_metrics_calls_total",
}


def _expression(target: dict[str, object]) -> str:
    """Запрос панели. У Prometheus и Loki он в `expr`, у Tempo — в `query`."""
    return str(target.get("expr") or target.get("query") or "")


def _exposed_metrics() -> set[str]:
    """Имена, которые реально появляются в /metrics."""
    from vscommon.metrics import metrics, render, setup_metrics

    setup_metrics(known_tenants=("t",))
    m = metrics()
    # Метрику видно в выводе только после первого наблюдения.
    m.scans.labels(verdict="clean", tenant="t", mode="both").inc()
    m.observe_stage("clamav", 0.1, ok=True)
    m.observe_cache("av", hit=True)
    m.verdict_seconds.labels(profile="standard", cached="false").observe(1.0)
    m.cdr_seconds.labels(profile="strict", ok="true").observe(0.5)
    m.stage_failures.labels(stage="yara", reason="timeout").inc()
    m.http_requests.labels(method="POST", route="/v1/scan", status="200").inc()
    m.http_seconds.labels(method="POST", route="/v1/scan").observe(1.0)
    m.callbacks.labels(outcome="delivered").inc()
    m.deliveries.labels(source="вебхук", verdict="clean").inc()
    m.queue_depth.labels(stream="scan.jobs").set(0)
    m.rules_age.labels(kind="av_db").set(0)
    m.dlq_size.set(0)
    m.inflight.set(0)

    body, _ = render()
    return {
        line.split("{")[0].split(" ")[0]
        for line in body.decode().splitlines()
        if line and not line.startswith("#")
    }


def _referenced_metrics() -> dict[str, set[str]]:
    """Имена `vs_*`, встречающиеся в выражениях панелей."""
    found: dict[str, set[str]] = {}
    for path in DASHBOARDS:
        board = json.loads(path.read_text())
        names: set[str] = set()
        for panel in board["panels"]:
            for tgt in panel.get("targets", []):
                names |= set(re.findall(r"\bvs_[a-z_]+\b", _expression(tgt)))
        found[path.name] = names
    return found


def test_dashboards_exist() -> None:
    assert DASHBOARDS, "дашборды не найдены"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_dashboard_is_valid_json(path: Path) -> None:
    board = json.loads(path.read_text())
    assert board["uid"] and board["title"]
    assert board["panels"], "дашборд без панелей"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_every_panel_has_a_query(path: Path) -> None:
    """Панель без запроса — место, где кто-то собирался что-то показать."""
    board = json.loads(path.read_text())
    for panel in board["panels"]:
        if panel["type"] == "row":
            continue
        assert panel.get("targets"), f"панель без запроса: {panel['title']}"
        for tgt in panel["targets"]:
            # Граф сервисов рисуется самим Tempo и запроса не требует.
            if tgt.get("queryType") == "serviceMap":
                continue
            assert _expression(tgt).strip(), f"пустое выражение в «{panel['title']}»"


def test_dashboards_reference_only_existing_metrics() -> None:
    """Главная проверка: опечатка в имени метрики даёт молчаливое «нет данных»."""
    exposed = _exposed_metrics()
    bare = {
        name[: -len(suffix)] for name in exposed for suffix in _SUFFIXES if name.endswith(suffix)
    } | exposed

    unknown: dict[str, set[str]] = {}
    for board, names in _referenced_metrics().items():
        missing = {n for n in names if n not in bare and n not in exposed}
        if missing:
            unknown[board] = missing

    assert not unknown, f"панели ссылаются на несуществующие метрики: {unknown}"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_panels_are_explained(path: Path) -> None:
    """У панели должно быть описание.

    Дашборд смотрят во время инцидента, и тогда некогда выяснять, что именно
    означает линия. Особенно это касается панелей, которые ловят молчаливые
    отказы: по одному названию не понять, почему возраст баз важнее остального.
    """
    board = json.loads(path.read_text())
    without = [
        p["title"] for p in board["panels"] if p["type"] != "row" and not p.get("description")
    ]
    assert not without, f"панели без описания: {without}"


def test_external_metrics_are_declared() -> None:
    """Метрики Tempo нельзя проверить, но можно закрепить их список.

    Опечатка в имени внешней метрики так же молчалива, как и в своей: панель
    выглядит исправной и показывает «нет данных».
    """
    referenced: set[str] = set()
    for path in DASHBOARDS:
        board = json.loads(path.read_text())
        for panel in board["panels"]:
            for tgt in panel.get("targets", []):
                referenced |= set(re.findall(r"\btraces_[a-z_]+\b", _expression(tgt)))

    unknown = referenced - EXTERNAL_METRICS
    assert not unknown, (
        f"метрики Tempo не в списке: {unknown}. Если имя верное — впишите его "
        "в EXTERNAL_METRICS, чтобы зависимость была видна."
    )


# --- цели Prometheus совпадают с портами сервисов ------------------------


def _compose() -> dict[str, object]:
    import yaml

    path = Path(__file__).parent.parent / "deploy/docker-compose.yml"
    return dict(yaml.safe_load(path.read_text()))


def _scrape_targets() -> dict[str, str]:
    """Цели из prometheus.yml: сервис → порт."""
    import yaml

    path = Path(__file__).parent.parent / "deploy/config/prometheus.yml"
    config = yaml.safe_load(path.read_text())
    targets: dict[str, str] = {}
    for job in config["scrape_configs"]:
        for static in job["static_configs"]:
            for entry in static["targets"]:
                host, port = entry.rsplit(":", 1)
                targets[host] = port
    return targets


def test_metrics_ports_match_scrape_targets() -> None:
    """Порт, на котором сервис слушает, и порт, куда ходит Prometheus.

    Регрессия: общий `.env` задаёт `METRICS_PORT` всем сервисам сразу и
    перекрывает умолчание из кода. Бот из-за этого слушал 9100, Prometheus
    ходил на 9102 и получал отказ соединения — метрик от бота не было вовсе,
    а заметить это можно было только в self-метриках самого Prometheus.
    """
    services = _compose()["services"]  # type: ignore[index]
    targets = _scrape_targets()

    mismatched: dict[str, tuple[str, str]] = {}
    for name, port in targets.items():
        svc = services.get(name)  # type: ignore[union-attr]
        if svc is None or name == "gateway":
            # gateway отдаёт /metrics своим HTTP-портом, отдельного нет.
            continue
        declared = str((svc.get("environment") or {}).get("METRICS_PORT", ""))
        if declared and declared != port:
            mismatched[name] = (declared, port)

    assert not mismatched, f"сервис слушает один порт, Prometheus ходит на другой: {mismatched}"


def test_services_with_metrics_are_scraped() -> None:
    """Сервис, поднимающий эндпоинт метрик, должен быть в целях.

    Регрессия: notifier и writer не скрейпились вовсе. Панель «Коллбэки»
    считает `vs_callbacks_total`, который отдаёт именно notifier, — она была
    пуста не из-за отсутствия коллбэков, а из-за отсутствия цели.
    """
    services = _compose()["services"]  # type: ignore[index]
    scraped = set(_scrape_targets())

    # Источник истины — КОД, а не тот же compose-файл, который мы проверяем.
    # Вывод списка из проверяемого файла делал тест круговым: убери сервису
    # порт — он исчезнет и из ожиданий, и проверка останется зелёной.
    root = Path(__file__).parent.parent
    serves_metrics = {
        # relative_to обязателен: на абсолютном пути parts[1] это «Users»,
        # и множество молча наполнялось мусором — тест проходил всегда.
        path.relative_to(root).parts[1]
        for path in root.glob("services/*/*/main.py")
        if "serve_metrics(" in path.read_text()
    }
    # deepscan — тот же образ воркера в другой роли; gateway отдаёт /metrics
    # своим HTTP-портом и `serve_metrics` не зовёт.
    serving = serves_metrics | {"deepscan", "gateway"}
    serving &= set(services)  # type: ignore[arg-type]

    missing = serving - scraped
    assert not missing, f"сервисы отдают метрики, но не скрейпятся: {missing}"
