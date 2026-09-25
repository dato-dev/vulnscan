"""Сборка дашборда дежурного из правил алертов.

Панели порождаются из `deploy/lgtp/prometheus/rules/*.yml`, а не пишутся руками:
M10.14 требует панель на каждый алерт, и единственный способ не разойтись — не
держать второй список.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages"))

from vscommon.models import UNSCANNABLE_VERDICTS  # noqa: E402

GRID = 24
"""Ширина сетки Grafana в колонках. Панель за её краем не падает с ошибкой —
Grafana молча переносит её, и верхняя строка перестаёт читаться как строка."""

RULES = ROOT / "deploy/lgtp/prometheus/rules"
OUT = ROOT / "deploy/grafana/dashboards/vulnscan-duty.json"

PROM = {"type": "prometheus", "uid": "prometheus"}

# Алерты, которым панель не нужна: Watchdog горит всегда по построению, и
# график из единиц ничего не объясняет. Его место — в статусной панели.
SKIP = {"Watchdog"}

# Чего ждать от панели, когда всё хорошо. Текст важнее графика: пустая панель и
# сломанный запрос выглядят одинаково, и подпись — единственное, что их
# различает (M10.15).
NORMAL = "В норме здесь ровная линия по нулю. Пустота означает, что метрика не собирается."


def alerts() -> list[dict]:
    found = []
    for path in sorted(RULES.glob("*.yml")):
        for group in yaml.safe_load(path.read_text())["groups"]:
            for rule in group["rules"]:
                if "alert" in rule and rule["alert"] not in SKIP:
                    found.append(rule)
    return found


def panel(rule: dict, x: int, y: int, pid: int) -> dict:
    name = rule["alert"]
    severity = rule.get("labels", {}).get("severity", "—")
    annotations = rule.get("annotations", {})
    summary = annotations.get("summary", "")
    description = " ".join(annotations.get("description", "").split())

    # Порог из выражения показываем отдельной линией, если он вычислим.
    expr = " ".join(rule["expr"].split())
    return {
        "id": pid,
        "type": "timeseries",
        "title": f"{name} · {severity}",
        "description": (
            f"{summary}\n\n{description}\n\n"
            f"Условие: `{expr}` держится {rule.get('for', '?')}.\n\n{NORMAL}"
        ),
        "datasource": PROM,
        "gridPos": {"h": 7, "w": 12, "x": x, "y": y},
        "targets": [{"refId": "A", "expr": expr, "legendFormat": name}],
        "fieldConfig": {
            "defaults": {
                "custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 10},
                "noValue": "Нет данных — метрика не собирается",
                "color": {"mode": "palette-classic"},
            },
            "overrides": [],
        },
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
    }


def row(title: str, y: int, pid: int) -> dict:
    return {
        "id": pid,
        "type": "row",
        "title": title,
        "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
        "collapsed": False,
        "panels": [],
    }


def status_panels(pid: int, y: int) -> tuple[list[dict], int]:
    """Верхняя строка: ответ на вопрос «всё ли хорошо» без чтения графиков."""
    specs = [
        (
            "Путь оповещения",
            "sum(ALERTS{alertname=\"Watchdog\"})",
            "Watchdog горит всегда. Ноль или пустота означают, что сломался сам "
            "механизм оповещения, а не наблюдаемая система — то есть молчанию "
            "остальных панелей верить нельзя.",
            {"0": "red", "1": "green"},
        ),
        (
            "Активных алертов",
            'sum(ALERTS{alertstate="firing",severity=~"warning|critical"})',
            "Сколько правил сработало прямо сейчас. Пустота здесь — это ноль "
            "алертов, но убедитесь по панели слева, что правила вообще вычисляются.",
            None,
        ),
        (
            "Компонентов в урезанном режиме",
            "sum(vs_degraded)",
            "Сервис отвечает, но проверка не полная: не прочитан файл политик "
            "либо нет libmagic. Ноль обязателен к отображению — отсутствие ряда "
            "означает, что метрика не выставляется вовсе.",
            None,
        ),
        (
            "Правил выключено вручную",
            "sum(vs_rules_disabled) or vector(0)",
            "Выключенное правило — временная мера, которая живёт ровно до тех "
            "пор, пока её видно: по вердиктам она неотличима от правила, "
            "которому просто не попадаются подходящие файлы. Не ноль — детект "
            "ослаблен, и у этого есть автор и причина в GET /v1/ops/rules.",
            None,
        ),
        (
            "Целей не отвечает",
            "count(up == 0) or vector(0)",
            "Незаскрейпленная цель даёт пустые панели, а пустая панель "
            "неотличима от отсутствия событий. Именно так из наблюдения "
            "выпадали notifier, writer и бот.",
            None,
        ),
    ]
    # Ширина делится на число плашек, остаток раздаётся первым. Было
    # `w=6, x=6*i`: пока плашек было четыре, это совпадало с сеткой; пятая
    # («Целей не отвечает») встала в x=24, то есть за край, — и никто не
    # заметил, потому что Grafana такую панель не отвергает, а переносит.
    base, extra = divmod(GRID, len(specs))
    widths = [base + (1 if i < extra else 0) for i in range(len(specs))]
    offsets = [sum(widths[:i]) for i in range(len(specs))]

    panels = []
    for i, (title, expr, desc, mapping) in enumerate(specs):
        field: dict = {
            "defaults": {
                "noValue": "нет данных",
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        {"color": "green", "value": None},
                        {"color": "orange", "value": 1},
                    ],
                },
            },
            "overrides": [],
        }
        if mapping:
            options = {
                key: {"color": color, "index": index}
                for index, (key, color) in enumerate(mapping.items())
            }
            field["defaults"]["mappings"] = [{"type": "value", "options": options}]
            field["defaults"]["thresholds"] = {
                "mode": "absolute",
                "steps": [{"color": "red", "value": None}, {"color": "green", "value": 1}],
            }
        panels.append(
            {
                "id": pid + i,
                "type": "stat",
                "title": title,
                "description": desc,
                "datasource": PROM,
                "gridPos": {"h": 5, "w": widths[i], "x": offsets[i], "y": y},
                "targets": [{"refId": "A", "expr": expr}],
                "fieldConfig": field,
                "options": {
                    "reduceOptions": {"calcs": ["lastNotNull"]},
                    "colorMode": "background",
                    "graphMode": "none",
                },
            }
        )
    return panels, pid + len(specs)


def unscannable_panel(pid: int, y: int) -> dict:
    """Доля файлов, которые не проверены вовсе (M10.2).

    Выражение собирается из `UNSCANNABLE_VERDICTS`, а не пишется руками:
    появится новый непроверяемый вердикт — он окажется на панели сам, а не
    останется за её пределами до первого разбора.
    """
    verdicts = "|".join(sorted(v.value for v in UNSCANNABLE_VERDICTS))
    expr = (
        f'sum by (verdict) (rate(vs_scans_total{{verdict=~"{verdicts}"}}[$__rate_interval]))'
        " / ignoring(verdict) group_left"
        " clamp_min(sum(rate(vs_scans_total[$__rate_interval])), 0.001)"
    )
    return {
        "id": pid,
        "type": "timeseries",
        "title": "Доля непроверенного",
        "description": (
            "Файлы, содержимое которых проверить невозможно: `unsupported` — "
            "формат не поддерживается, `encrypted` — защищён паролем. Сервис при "
            "этом отвечает штатно: коды 200, ошибок нет. Поэтому рост этой доли "
            "— единственный видимый признак того, что проверка перестала "
            "происходить.\n\n"
            "Две причины роста выглядят одинаково, и различать их надо сразу. "
            "Клиенты начали присылать новый формат — `unsupported` растёт у "
            "одного тенанта, `vs_degraded{component=\"libmagic\"}` в нуле. "
            "Сломалось определение типа — растёт у всех сразу, и обычно "
            "вместе с деградацией libmagic.\n\n"
            "Алерта нет намеренно: порог без знания фона либо шумит, либо "
            "молчит. Нормальную долю берём отсюда же после недели наблюдения "
            "— и тогда эта панель переедет в раздел алертов."
        ),
        "datasource": PROM,
        "gridPos": {"h": 8, "w": GRID, "x": 0, "y": y},
        "targets": [{"refId": "A", "expr": expr, "legendFormat": "{{verdict}}"}],
        "fieldConfig": {
            "defaults": {
                "unit": "percentunit",
                "min": 0,
                "custom": {
                    "drawStyle": "line",
                    "lineWidth": 2,
                    "fillOpacity": 20,
                    "stacking": {"mode": "normal", "group": "A"},
                },
                "noValue": "Нет данных — сканов не было или метрика не собирается",
                "color": {"mode": "palette-classic"},
            },
            "overrides": [],
        },
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
    }


def build() -> dict:
    panels: list[dict] = []
    pid = 1
    y = 0

    panels.append(row("Всё ли хорошо", y, pid))
    pid += 1
    y += 1
    status, pid = status_panels(pid, y)
    panels += status
    y += 5

    by_severity: dict[str, list[dict]] = {"critical": [], "warning": [], "none": []}
    for rule in alerts():
        by_severity.setdefault(rule.get("labels", {}).get("severity", "none"), []).append(rule)

    titles = {
        "critical": "Критичные: будят человека",
        "warning": "Предупреждения: разобраться в рабочее время",
        "none": "Прочее",
    }
    for severity in ("critical", "warning", "none"):
        rules = by_severity.get(severity) or []
        if not rules:
            continue
        panels.append(row(titles[severity], y, pid))
        pid += 1
        y += 1
        for i, rule in enumerate(rules):
            panels.append(panel(rule, x=(i % 2) * 12, y=y + (i // 2) * 7, pid=pid))
            pid += 1
        y += ((len(rules) + 1) // 2) * 7

    # Метрики, у которых алерта ещё нет, но смотреть на них дежурному нужно.
    # Отдельной строкой, чтобы не путать с разделами алертов: здесь не
    # «сработало», а «вот как это выглядит, пока мы учимся понимать норму».
    panels.append(row("Наблюдаем: порог ещё не выбран", y, pid))
    pid += 1
    y += 1
    panels.append(unscannable_panel(pid, y))
    pid += 1
    y += 8

    return {
        "uid": "vulnscan-duty",
        "title": "vulnscantg — дежурному",
        "tags": ["vulnscantg", "дежурство"],
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "refresh": "1m",
        "time": {"from": "now-6h", "to": "now"},
        "description": (
            "Одна страница на вопрос «всё ли хорошо». Верхняя строка отвечает "
            "без чтения графиков; ниже — по панели на каждое правило алертов, "
            "чтобы сработавший алерт вёл на картинку, а не на поиск нужной "
            "панели. Панели порождены из правил Prometheus, поэтому новое "
            "правило без панели не останется."
        ),
        "panels": panels,
    }


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n")
    print(f"записано {OUT}")
