"""M10.3: то, что ломается без единой ошибки, обязано быть видно в метриках.

Общее у всех случаев здесь — сервис продолжает работать и отвечать. Правила не
скомпилировались, но старые на месте; правил нет вообще, но стадия отрабатывает;
история копится в памяти, но приём идёт. Ни один из этих сбоев не виден ни по
вердиктам, ни по времени ответа, ни по количеству ошибок.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from vscommon.metrics import render, setup_metrics


@pytest.fixture(autouse=True)
def fresh_metrics() -> None:
    """Свой реестр на тест: счётчики глобальны и переживают тесты."""
    setup_metrics()


def _value(name: str, **labels: str) -> float:
    """Значение метрики из `/metrics`; отсутствие ряда — это провал теста.

    Возвращать ноль для ненайденного ряда нельзя, и это не придирка: первая
    версия этой функции так и делала, и проверка «правил ноль» проходила даже
    после удаления метрики из кода — отсутствующий ряд и ряд со значением
    ноль давали одинаковый ответ. Тот же класс, что и весь этот файл, только
    внутри самой проверки.
    """
    body, _ = render()
    selector = ",".join(f'{k}="{v}"' for k, v in labels.items())
    prefix = f"{name}{{{selector}}}" if selector else name
    for line in body.decode().splitlines():
        if line.startswith(prefix + " "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError(f"ряда {prefix} нет в /metrics — метрика не выставляется")


# --- правила YARA -------------------------------------------------------

RULE = 'rule sample : medium { strings: $a = "AAA" condition: $a }'


class _FakeRules:
    def match(self, path: str, timeout: int = 0) -> list[Any]:
        return []


@pytest.fixture()
def rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from worker_app.stages import yara_rules as module

    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "documents.yar").write_text(RULE)
    monkeypatch.setattr(module.settings, "yara_rules_dir", str(directory))
    return directory


def _stage(monkeypatch: pytest.MonkeyPatch, *, broken: bool = False) -> Any:
    from worker_app.stages.yara_rules import YaraStage

    stage = YaraStage()

    def compile_() -> Any:
        if broken:
            raise ValueError("правило не компилируется")
        return _FakeRules()

    monkeypatch.setattr(stage, "_compile", compile_)
    return stage


def test_broken_rules_are_counted(rules_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Правила не скомпилировались — воркер остаётся на прежних, и это видно.

    Поведение правильное: кривое правило не должно останавливать проверку
    файлов. Ровно поэтому оно и незаметно — сервис работает, вердикты идут,
    в логе одна строка, которую никто не читает.
    """
    stage = _stage(monkeypatch)
    stage._ensure_rules()

    broken = _stage(monkeypatch, broken=True)
    broken._stat_signature = ()
    (rules_dir / "documents.yar").write_text(RULE.replace("AAA", "BBB"))

    assert broken.reload_if_changed() is False
    assert _value("vs_config_reloads_total", kind="yara", outcome="failed") == 1.0


def test_applied_reload_is_counted(rules_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Успешная замена тоже считается: без неё «ноль отказов» ничего не значит."""
    stage = _stage(monkeypatch)
    stage._ensure_rules()
    (rules_dir / "documents.yar").write_text(RULE.replace("AAA", "BBB"))

    assert stage.reload_if_changed() is True
    assert _value("vs_config_reloads_total", kind="yara", outcome="applied") == 1.0


def test_empty_rules_are_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ноль правил — работающая стадия, которая ничего не находит.

    По вердиктам она неотличима от стадии, которой попадаются чистые файлы:
    и там и там признаков нет. Отличает только эта метрика.
    """
    from worker_app.stages import yara_rules as module

    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(module.settings, "yara_rules_dir", str(empty))

    stage = _stage(monkeypatch)
    stage._ensure_rules()

    assert _value("vs_rules_loaded", kind="yara") == 0.0


def test_rules_age_is_reported(rules_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Правила, не обновлявшиеся месяц, — тоже деградация, просто медленная."""
    old = time.time() - 30 * 24 * 3600
    import os

    os.utime(rules_dir / "documents.yar", (old, old))

    stage = _stage(monkeypatch)
    stage._ensure_rules()

    assert _value("vs_rules_age_seconds", kind="yara") > 29 * 24 * 3600


# --- отставание истории -------------------------------------------------


@pytest.mark.asyncio
async def test_history_lag_is_measured() -> None:
    """Отставание меряется в момент записи в базу, а не приёма из потока.

    До записи история существует только в памяти процесса. Именно так она
    однажды и жила: сброс шёл раз в 64 записи, при слабом потоке база
    оставалась пустой сутками, и выглядело это как работающий сервис — приём
    идёт, ошибок нет, вердикты отдаются.

    Проверяется настоящий `Writer._flush`, а не упрощённая копия из
    `test_writer.py`: копия не содержит инструментирования, и тест на ней
    прошёл бы при полностью снятой метрике.
    """
    from vscommon.models import ScanRecord, ScanResult, ScanStatus, Verdict
    from writerapp.main import Writer

    class _Stub:
        def __init__(self) -> None:
            import asyncio

            self._lock = asyncio.Lock()
            self._batch: list[Any] = []
            self._db = self
            self._stream = self

        async def store(self, records: list[Any]) -> int:
            return len(records)

        async def ack(self, entry_id: str) -> None:
            return None

    result = ScanResult(
        scan_id="a" * 32,
        sha256="b" * 64,
        status=ScanStatus.DONE,
        verdict=Verdict.CLEAN,
        score=0,
        created_at=time.time() - 120,
    )
    record = ScanRecord(result=result, tenant="telegram-bot", size=1024)

    await Writer._flush(_Stub(), [("1-0", record)])  # type: ignore[arg-type]

    assert _value("vs_history_lag_seconds_count") == 1.0
    assert _value("vs_history_lag_seconds_sum") > 100.0


# --- зеркало баз ---------------------------------------------------------


def test_mirror_reports_age(tmp_path: Path) -> None:
    """Отказ зеркала виден только по возрасту файлов.

    `cvd serve` продолжает раздавать уже скачанное, clamd продолжает отвечать,
    проверки идут. Не обновляются только базы — и по вердиктам это заметно
    ровно тогда, когда что-то уже пропущено.
    """
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent / "services/cvdmirror"))
    import exporter

    old = time.time() - 3 * 24 * 3600
    (tmp_path / "daily.cvd").write_bytes(b"x" * 10)
    import os

    os.utime(tmp_path / "daily.cvd", (old, old))
    (tmp_path / "main.cvd").write_bytes(b"y" * 20)

    exporter.collect(tmp_path)

    assert exporter.files._value.get() == 2
    assert exporter.size._value.get() == 30
    # Самый свежий файл только что создан: его возраст близок к нулю, и именно
    # он отвечает на вопрос «обновлялись ли базы вообще».
    assert exporter.newest._value.get() < 60


def test_mirror_reports_empty_directory(tmp_path: Path) -> None:
    """Пустой каталог — работающая раздача без единой базы.

    Ряд обязан существовать и быть нулём: отсутствие ряда неотличимо от
    неработающего экспортёра, а это ровно та подмена, ради которой всё здесь.
    """
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent / "services/cvdmirror"))
    import exporter

    exporter.collect(tmp_path)

    assert exporter.files._value.get() == 0
    assert exporter.newest._value.get() == 0


# --- деградированный режим -----------------------------------------------


def test_degraded_reports_both_states() -> None:
    """Признак урезанного режима выставляется и в единицу, и в ноль.

    Ноль важнее единицы: ряд, появляющийся только при поломке, неотличим от
    неработающего экспорта. «Всё хорошо» и «никто не проверял» обязаны
    выглядеть по-разному.
    """
    from vscommon.metrics import metrics

    metrics().report_degraded("policies", True)
    assert _value("vs_degraded", component="policies") == 1.0

    metrics().report_degraded("policies", False)
    assert _value("vs_degraded", component="policies") == 0.0


def test_degradation_is_reported_where_it_is_known() -> None:
    """Каждый источник деградации зовёт `report_degraded`.

    Проверка структурная, и это осознанный выбор: тест, повторяющий у себя ту
    же строку, что и продакшн, проходит при полностью снятой инструментации —
    он проверяет собственную копию. Здесь же утверждается, что вызов есть
    именно в том коде, который знает состояние.

    Политики знает gateway при загрузке, libmagic — воркер в периодической
    публикации версий. `/readyz` для этого не годится: ручку никто не
    опрашивает регулярно, у gateway нет даже healthcheck.
    """
    root = Path(__file__).parent.parent
    sources = {
        "policies": root / "services/gateway/gateway_app/state.py",
        "libmagic": root / "services/worker/worker_app/main.py",
    }

    missing = [
        component
        for component, path in sources.items()
        if f'report_degraded("{component}"' not in path.read_text()
    ]

    assert not missing, f"состояние известно, но в метрику не попадает: {missing}"


# --- трассировка: связность и имена спанов --------------------------------


def test_stage_spans_are_named_individually() -> None:
    """Каждая стадия — своё имя спана.

    Коннектор `spanmetrics` считает по `span.name`. С общим именем «stage» все
    стадии складывались в один ряд, и панель «p95 по спанам» показывала одну
    линию вместо шести — то есть ровно то, ради чего её заводили, было не
    видно, а выглядело это как работающая панель.
    """
    source = (Path(__file__).parent.parent / "services/worker/worker_app/pipeline.py").read_text()

    assert 'span(f"stage.{stage.name}"' in source, "имя стадии должно быть в имени спана"
    assert 'span("stage"' not in source, "общее имя складывает все стадии в один ряд"


def test_callback_carries_trace_context() -> None:
    """Доставка продолжает трейс скана, а не начинает свой.

    Без этого «сервис ответил» и «до клиента дошло» лежали в разных трейсах,
    связанных только `scan_id`, — а это ровно тот вопрос, ради которого в
    трассировку и лезут. Побочно граф сервисов не рисовал ребро
    воркер → notifier.
    """
    from vscommon.models import CallbackTask

    assert "traceparent" in CallbackTask.model_fields, "контексту негде ехать через очередь"

    root = Path(__file__).parent.parent
    worker = (root / "services/worker/worker_app/main.py").read_text()
    notifier = (root / "services/notifier/notifierapp/main.py").read_text()

    assert "traceparent=current_traceparent()" in worker, "воркер не кладёт контекст в задачу"
    assert "continue_trace(" in notifier, "notifier начинает новый корень вместо продолжения"
    assert 'span("callback.deliver"' not in notifier, "остался безусловно новый корень"


def test_trace_context_crosses_http() -> None:
    """Контекст трассировки едет и через HTTP, а не только через очередь.

    Через Redis Stream контекст протаскивался (`ScanJob.traceparent`), а через
    HTTP-границу — нет: бот делал спан `bot.submit`, gateway начинал свой
    корень, и получалось два несвязанных трейса на один файл. Снаружи это
    выглядело как «в Tempo видно только bot.submit».

    Заголовок не входит в подпись: подписывается канонический запрос (метод,
    путь, идентификатор ключа), поэтому добавление совместимо.
    """
    root = Path(__file__).parent.parent
    bot = (root / "services/bot/botapp/scanner.py").read_text()
    routes = (root / "services/gateway/gateway_app/routes/scan.py").read_text()
    ingest = (root / "services/gateway/gateway_app/ingest.py").read_text()
    sdk = (root / "packages/vulnscan_client/client.py").read_text()

    assert 'headers["traceparent"] = traceparent' in bot, "бот не шлёт контекст"
    assert 'request.headers.get("traceparent")' in routes, "gateway не читает заголовок"
    joins = "continue_trace(\n                traceparent,"
    assert joins in ingest, "gateway начинает новый корень вместо продолжения"
    assert "trace_context" in sdk, "в SDK нечем передать контекст"


def test_sdk_stays_free_of_opentelemetry() -> None:
    """Библиотека для сторонней команды не тянет OpenTelemetry.

    Подключение не должно навязывать ничего, кроме httpx. Контекст приходит
    функцией снаружи — кто трассировку ведёт, тот её и передаёт.
    """
    sdk_dir = Path(__file__).parent.parent / "packages/vulnscan_client"

    offenders = [
        path.name
        for path in sdk_dir.glob("*.py")
        if "opentelemetry" in path.read_text() or "vscommon" in path.read_text()
    ]

    assert not offenders, f"SDK потянул лишнюю зависимость: {offenders}"
