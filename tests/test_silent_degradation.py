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
    # Метки сортируются по имени: prometheus_client отдаёт их в этом порядке, а
    # не в том, в каком они объявлены или переданы сюда. Собрав селектор по
    # порядку аргументов, помощник не находил существующий ряд и сообщал
    # «метрика не выставляется» — то есть врал ровно тем способом, против
    # которого написан.
    selector = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
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

    Политики и ключи знает gateway при загрузке, libmagic и веса — воркер в
    периодической публикации версий, учётки приёмников — notifier при старте.
    `/readyz` для этого не годится: ручку никто не опрашивает регулярно, у
    gateway нет даже healthcheck.

    Список закрытый намеренно. Каждый флаг `degraded` в коде обязан здесь
    появиться: `WeightTable.degraded` полгода не читал никто, и «файл весов не
    прочитан, считаем по встроенным» не проявлялось вообще ничем — стадии
    отрабатывают, признаки находятся, вердикт выдаётся по чужим порогам.
    """
    root = Path(__file__).parent.parent
    sources = {
        "policies": root / "services/gateway/gateway_app/state.py",
        "keys": root / "services/gateway/gateway_app/state.py",
        "libmagic": root / "services/worker/worker_app/main.py",
        "weights": root / "services/worker/worker_app/main.py",
        "delivery": root / "services/notifier/notifierapp/main.py",
    }

    missing = [
        component
        for component, path in sources.items()
        if f'report_degraded("{component}"' not in path.read_text()
    ]

    assert not missing, f"состояние известно, но в метрику не попадает: {missing}"


# --- покрытие потока вердиктами -------------------------------------------
#
# Метрика, считающая часть потока, — тот же класс сбоя, что и все остальные в
# этом файле: график не пустой, алерт настроен, а описывают они не то, что
# происходит. Счёт вёлся в gateway после ожидания результата, поэтому мимо шли
# оба края: ответы из кэша (быстрые) и ушедшие в `202` с коллбэком (медленные).
# Тяжёлые файлы уходят в `202` чаще лёгких, а вердикт у них чаще не `clean` —
# алерт на долю вредоносных делил одно смещённое число на другое.


def _job(**overrides: Any) -> Any:
    from vscommon.models import CdrProfile, ObjectRef, ScanJob

    fields: dict[str, Any] = {
        "scan_id": "01J-скан",
        "sha256": "a" * 64,
        "source": ObjectRef(bucket="vulnscan-raw", key="aa/файл.pdf"),
        "size": 4096,
        "tenant": "team-a",
        "profile": CdrProfile.STANDARD,
    }
    fields.update(overrides)
    return ScanJob(**fields)


def _done(verdict: str = "clean") -> Any:
    from vscommon.models import ScanResult, ScanStatus, Verdict

    return ScanResult(
        scan_id="01J-скан",
        sha256="a" * 64,
        status=ScanStatus.DONE,
        verdict=Verdict(verdict),
    )


def test_scan_finished_after_the_deadline_is_counted() -> None:
    """Скан, ушедший в коллбэк, обязан попасть в `vs_scans_total`.

    Клиент получил вердикт — значит услуга оказана, и в счётчике «что получает
    клиент» она должна быть. Gateway такой скан видит только как `202` без
    вердикта, поэтому считает его воркер.
    """
    from worker_app.main import Worker

    Worker._observe_verdict(_job(), _done("malicious"))

    assert _value("vs_scans_total", verdict="malicious", tenant="other", mode="both") == 1.0


def test_slow_scan_reaches_the_histogram() -> None:
    """Наблюдение длиннее `wait_ms` обязано попадать в гистограмму.

    Пока время меряли в gateway после ожидания результата, туда не могло
    попасть ничего длиннее дедлайна: всё, что дольше, уходило в ветку без
    измерения. Цель «p95 ≤ 0.7 с» выполнялась по построению, а корзины до 10 с
    существовали для наблюдений, которых не бывало.
    """
    from worker_app.main import Worker

    Worker._observe_verdict(_job(enqueued_at=time.time() - 30.0), _done())

    assert _value("vs_verdict_duration_seconds_count", profile="standard", cached="none") == 1.0
    assert _value("vs_verdict_duration_seconds_sum", profile="standard", cached="none") >= 30.0


def test_full_cache_hit_is_counted() -> None:
    """Ответ из кэша — тоже оказанная услуга.

    Воркер его не видит вовсе, поэтому считает gateway. Метка `cached="full"`
    отделяет его от `structural`: там разбор переиспользован, но антивирус
    прогнан заново, и цена ответа другая.
    """
    from gateway_app.ingest import Ingestor
    from vscommon.metrics import CACHED_FULL
    from vscommon.models import ScanRequest

    Ingestor._observe_verdict(_done(), ScanRequest(tenant="team-a"), "standard", CACHED_FULL, 0.02)

    assert _value("vs_scans_total", verdict="clean", tenant="other", mode="both") == 1.0
    assert _value("vs_verdict_duration_seconds_count", profile="standard", cached="full") == 1.0


class _StubWorker:
    """Ровно те поля `Worker`, которых касается `_deliver`.

    Метод вызывается несвязанным: поднимать настоящий `Worker` значит поднять
    Redis, хранилище и конвейер. `_observe_verdict` при этом настоящий — иначе
    проверялась бы копия инструментации, а не она сама.
    """

    def __init__(self) -> None:
        self._concurrency = _StubConcurrency()
        self._results = _StubResults()

    @staticmethod
    def _observe_verdict(job: Any, result: Any) -> None:
        from worker_app.main import Worker

        Worker._observe_verdict(job, result)

    async def _record_history(self, job: Any, result: Any) -> None:
        return None

    async def _deliver_deep(self, job: Any, result: Any) -> None:
        return None

    async def _store_cache(self, job: Any, result: Any) -> None:
        return None

    async def _maybe_enqueue_deep(self, job: Any, result: Any) -> None:
        return None


class _StubResults:
    async def publish(self, result: Any, status_ttl_s: int | None = None) -> None:
        return None


class _StubConcurrency:
    async def release(self, tenant: str, scan_id: str) -> None:
        return None


async def test_completed_scan_is_actually_counted() -> None:
    """Вызов `_deliver`, а не проверка того, что счётчик умеет считать.

    Проверки выше зовут `_observe_verdict` напрямую — так видно, что метрика
    работает, но не видно, подключена ли она. Ровно эта разница и была
    пропущена: `vs_scans_total` считался исправно, просто не на том пути.
    """
    from worker_app.main import Worker

    await Worker._deliver(_StubWorker(), _job(), _done("malicious"))

    assert _value("vs_scans_total", mode="both", tenant="other", verdict="malicious") == 1.0


async def test_deep_scan_does_not_double_the_stream() -> None:
    """Углублённая проверка не удваивает поток.

    Клиент получил один ответ на файл. Второй вердикт приходит отдельным
    коллбэком и уточняет первый, а не добавляет ещё один скан в статистику.
    Считать его здесь значило бы завысить знаменатель доли вредоносных ровно
    на выборку чистых, которую углублённая проверка и берёт.
    """
    from worker_app.main import Worker

    await Worker._deliver(_StubWorker(), _job(deep=True), _done("clean"))

    with pytest.raises(AssertionError):
        _value("vs_scans_total", mode="both", tenant="other", verdict="clean")


def test_input_size_is_measured_on_accept() -> None:
    """Размер снимается на приёме, а не рядом с вердиктом.

    Рядом с вердиктом в метрику попадали только файлы, успевшие ответить
    синхронно, — то есть заведомо лёгкие. Метрика заведена (M10.11) объяснять
    уехавший p95, а объясняют его тяжёлые.
    """
    from gateway_app.ingest import Ingestor

    Ingestor._observe_accepted("strict", 4_000_000)

    assert _value("vs_input_bytes_count", profile="strict") == 1.0


def test_unknown_size_is_not_an_observation() -> None:
    """Приём по ссылке: размер знает воркер, gateway тело не тянет.

    Ноль в гистограмме — не наблюдение, а испорченная нижняя корзина: он
    занижает и p50, и среднее, притом молча.
    """
    from gateway_app.ingest import Ingestor

    Ingestor._observe_accepted("standard", 0)

    with pytest.raises(AssertionError):
        _value("vs_input_bytes_count", profile="standard")


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
    sdk = (root / "packages/vulnscan_client/client.py").read_text()

    assert 'headers["traceparent"] = traceparent' in bot, "бот не шлёт контекст"
    assert "trace_context" in sdk, "в SDK нечем передать контекст"
    # Приёмную сторону проверяет `test_server_span_*` ниже — вызовом, а не
    # чтением исходника.


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


# --- M10.17: то, что было видно только в логах ----------------------------
#
# Общее у всего ниже: событие редкое, пишется одной строкой, и «строк стало
# больше» замечает лишь тот, кто в этот момент читает логи. По метрике это
# ступенька на графике, по логам — ничего.


async def test_reclaimed_jobs_are_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Подхват задач мёртвого воркера — всегда чужая авария.

    Всплеск подхватов это самый ранний признак цикла «падаем на файле — задача
    уходит следующему воркеру». `vs_dlq_size` покажет то же самое позже и
    только после того, как лимит доставок исчерпан.
    """
    from worker_app.main import Worker
    from worker_app.reclaim import ClaimedJob, SweepResult

    job = _job()
    sweep = SweepResult(
        reclaimed=[ClaimedJob(entry_id="1-0", job=job, delivered=1)],
        abandoned=[ClaimedJob(entry_id="2-0", job=job, delivered=9)],
    )
    worker = _StubReclaimWorker(sweep)
    monkeypatch.setattr("worker_app.main.settings.reclaim_interval_s", 0)

    await Worker._reclaim_loop(worker)

    assert _value("vs_jobs_reclaimed_total", outcome="reclaimed") == 1.0
    assert _value("vs_jobs_reclaimed_total", outcome="abandoned") == 1.0


class _StubReclaimWorker:
    def __init__(self, sweep: Any) -> None:
        import asyncio

        self._sweep = sweep
        self._stopping = asyncio.Event()
        self._reclaimer = self
        self.spawned: list[str] = []

    async def sweep(self) -> Any:
        # Один проход: дальше цикл увидит выставленный флаг и выйдет.
        self._stopping.set()
        return self._sweep

    async def _observe_queues(self) -> None:
        return None

    async def _spawn(self, entry_id: str, job: Any, **kwargs: Any) -> None:
        self.spawned.append(entry_id)


async def test_deep_scan_reason_is_counted() -> None:
    """Чем занята дорогая роль: серой зоной, повторами или выборкой чистых."""
    from vscommon.models import ScanStatus, Verdict
    from worker_app.main import Worker

    result = _done("suspicious")
    result.status = ScanStatus.DONE
    result.verdict = Verdict.SUSPICIOUS
    worker = _StubDeepWorker()

    await Worker._maybe_enqueue_deep(worker, _job(), result)

    assert _value("vs_deep_scans_total", reason="grey_zone") == 1.0
    assert len(worker.published) == 1


class _StubDeepWorker:
    def __init__(self) -> None:
        self._deep_mode = False
        self._deep_queue = self
        self.published: list[Any] = []

    async def publish(self, job: Any) -> None:
        self.published.append(job)


@pytest.mark.parametrize(
    ("fast", "deep", "change"),
    [
        ("clean", "clean", "agree"),
        ("clean", "malicious", "stricter"),
        ("malicious", "clean", "looser"),
        ("unsupported", "clean", "resolved"),
        (None, "clean", "unknown"),
    ],
)
async def test_deep_disagreement_is_counted(fast: str | None, deep: str, change: str) -> None:
    """Сравнение двух вердиктов — единственное, ради чего есть выборка чистых.

    Файл проверялся дважды и до M10.17 результат сравнения не оседал нигде.
    `stricter` — пропуск быстрой проверки, то есть цена бюджета в сотни
    миллисекунд. `unknown` — отдельное значение, а не «совпало»: статус быстрой
    проверки живёт по TTL, и посчитать несравнимое совпадением значит занизить
    долю пропусков.
    """
    from worker_app.main import Worker

    worker = _StubDeepResults(_done(fast) if fast else None)

    await Worker._observe_deep_change(worker, _job(parent_scan_id="01J-родитель"), _done(deep))

    assert _value("vs_deep_verdict_changes_total", change=change) == 1.0


class _StubDeepResults:
    def __init__(self, parent: Any) -> None:
        self._parent = parent
        self._results = self

    async def load_status(self, scan_id: str) -> Any:
        return self._parent

    @staticmethod
    def _verdict_change(fast: Any, deep: Any) -> str:
        from worker_app.main import Worker

        return Worker._verdict_change(fast, deep)


async def test_shadow_ratio_leaves_redis() -> None:
    """Доля «заблокировали бы» — на графике, а не только в админском API.

    По этому числу принимают решение включать блокировки, и смотреть на него
    надо неделю, а не в моменте.
    """
    from vscommon.models import TenantPolicy
    from worker_app.main import Worker

    worker = _StubWorker()
    worker._shadow = _StubShadow()
    job = _job(policy=TenantPolicy(tenant="team-a", shadow_mode=True))

    await Worker._deliver(worker, job, _done("malicious"))

    assert _value("vs_shadow_records_total", tenant="other", would_block="true") == 1.0


class _StubShadow:
    async def record(self, **kwargs: Any) -> None:
        return None


def test_storage_calls_are_timed() -> None:
    """Единственный сетевой вызов в горячем пути, не видный ни в чём.

    Медленный S3 проявляется размазанным ростом времени до вердикта без
    указания на причину: конвейер выглядит медленным, хотя ждёт он сеть.
    """
    from vscommon.storage import _measured

    with _measured("put"):
        pass
    with pytest.raises(RuntimeError), _measured("get"):
        raise RuntimeError("хранилище недоступно")

    assert _value("vs_storage_duration_seconds_count", ok="true", op="put") == 1.0
    assert _value("vs_storage_duration_seconds_count", ok="false", op="get") == 1.0


def test_storage_labels_carry_no_object_key() -> None:
    """Ключ объекта содержит sha256 — это ряд на каждый файл.

    Что именно не читается, видно по `scan_id` в логе, а не в метке метрики:
    `/metrics` оседает в Prometheus на весь срок хранения.
    """
    import inspect

    from vscommon import storage

    source = inspect.getsource(storage.S3Store)

    assert "_measured" in source
    assert "labels(op=" not in source, "метка собирается по месту, мимо обёртки"


async def test_retention_run_is_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Неработающая чистка не проявляется ничем.

    Сервис отвечает, история пишется, а срок хранения тихо перестаёт
    соблюдаться — и обнаруживается это по месту на диске либо по вопросу о
    персональных данных, которые полагалось удалить.
    """
    import writerapp.main as writer_main

    monkeypatch.setattr(writer_main, "PRUNE_INTERVAL_S", 0)
    writer = _StubWriter(fails=True)

    await writer_main.Writer._prune_loop(writer)

    assert _value("vs_retention_runs_total", outcome="failed") == 1.0


class _StubWriter:
    def __init__(self, fails: bool) -> None:
        import asyncio

        self._fails = fails
        self._stopping = asyncio.Event()
        self._db = self

    async def prune(self, days: int) -> None:
        self._stopping.set()
        if self._fails:
            raise RuntimeError("база недоступна")


def test_every_rejection_reason_is_counted() -> None:
    """Каждый отказ на входе назван своей причиной.

    Проверка структурная: точки отказа разбросаны по middleware, приёму и
    маршрутам, и поднимать ради каждой полноценное приложение дороже пользы.
    Утверждение при этом содержательное — в `vs_http_requests_total` все они
    один и тот же `429`, а действия оператора у них разные: поднять предел
    частоты, добавить воркеров или объяснить клиенту суточную квоту.
    """
    root = Path(__file__).parent.parent
    sources = {
        "rate_limit": root / "services/gateway/gateway_app/throttle.py",
        "concurrency": root / "services/gateway/gateway_app/ingest.py",
        "too_large": root / "services/gateway/gateway_app/ingest.py",
        "quota": root / "services/gateway/gateway_app/routes/scan.py",
        "ticket_rate": root / "services/gateway/gateway_app/routes/scan.py",
    }

    missing = [
        reason
        for reason, path in sources.items()
        if f'rejections.labels(reason="{reason}")' not in path.read_text()
    ]

    assert not missing, f"отказ есть, но в метрику не попадает: {missing}"


# --- M10.18: серверный спан gateway ----------------------------------------


@pytest.fixture()
def tracing() -> Any:
    """Настоящий провайдер OTEL с экспортом в память.

    Такой же, как в `test_telemetry.py`: спаны здесь проверяются по факту
    экспорта, а не по наличию вызова в исходнике.
    """
    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    export = pytest.importorskip("opentelemetry.sdk.trace.export.in_memory_span_exporter")
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    from vscommon import telemetry

    exporter = export.InMemorySpanExporter()
    provider = sdk.TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    previous = otel_trace._TRACER_PROVIDER
    otel_trace._TRACER_PROVIDER = provider
    telemetry._enabled = True
    try:
        yield exporter
    finally:
        telemetry._enabled = False
        otel_trace._TRACER_PROVIDER = previous


CLIENT_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
CLIENT_TRACEPARENT = f"00-{CLIENT_TRACE}-00f067aa0ba902b7-01"


def _http_request(path: str, template: str, traceparent: str | None) -> Any:
    """Запрос без приложения: middleware читает из scope только своё."""
    from fastapi import Request

    headers = [(b"traceparent", traceparent.encode())] if traceparent else []
    route = type("Route", (), {"path": template})()
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers,
            "route": route,
            "query_string": b"",
        }
    )


async def _call_middleware(request: Any) -> Any:
    """Middleware напрямую: здесь проверяется имя и контекст спана.

    Вложенность так проверять нельзя — прямой вызов обходит `BaseHTTPMiddleware`
    с его отдельной задачей. Для неё есть тест поверх настоящего приложения.
    """
    from fastapi import Response

    from gateway_app.observability import tracing_middleware

    async def call_next(_: Any) -> Any:
        return Response(status_code=200)

    return await tracing_middleware(request, call_next)


async def test_server_span_continues_the_client_trace(tracing: Any) -> None:
    """Трейс клиента и трейс gateway — один трейс, а не два.

    Бот делает спан `bot.submit` и шлёт `traceparent`. Пока заголовок читал
    обработчик, всё, что происходило до него, оставалось вне дерева; теперь его
    принимает middleware, и приём попадает в трейс целиком.
    """
    await _call_middleware(_http_request("/v1/scan", "/v1/scan", CLIENT_TRACEPARENT))

    spans = tracing.get_finished_spans()
    assert len(spans) == 1
    assert f"{spans[0].context.trace_id:032x}" == CLIENT_TRACE, "gateway начал свой корень"


async def test_server_span_is_named_by_route_template(tracing: Any) -> None:
    """Имя спана — шаблон маршрута, а не сырой путь.

    Сырой путь даёт имя на каждый скан: в Tempo это не сгруппировать, а
    коннектор `spanmetrics` построил бы по нему ряд метрик на скан.
    """
    await _call_middleware(
        _http_request("/v1/scan/abc123", "/v1/scan/{scan_id}", CLIENT_TRACEPARENT)
    )

    (recorded,) = tracing.get_finished_spans()
    assert recorded.name == "POST /v1/scan/{scan_id}"
    assert "abc123" not in recorded.name


async def test_routes_without_their_own_spans_are_traced(tracing: Any) -> None:
    """`/v1/ops/*` и `/v1/admin/*` спанов не заводили вовсе.

    Заведение тенанта, отзыв ключа и снятие блокировки — редкие операции, о
    которых потом спрашивают «когда это произошло». Серверный спан покрывает их
    без единой строки в самих маршрутах.
    """
    await _call_middleware(_http_request("/v1/admin/tenants", "/v1/admin/tenants", None))

    (recorded,) = tracing.get_finished_spans()
    assert recorded.name == "POST /v1/admin/tenants"


def test_work_nests_under_the_server_span(tracing: Any) -> None:
    """Спан приёма — потомок серверного, а не его брат.

    Через настоящее приложение, а не вызовом middleware напрямую, и это
    существенно: `app.middleware("http")` — это `BaseHTTPMiddleware`, а он
    запускает обработчик отдельной задачей. Задача копирует контекст в момент
    создания, так что спан до неё доходит, — но проверка, обходящая этот
    механизм, ничего об этом не сказала бы.

    Само утверждение: `continue_trace` в середине обработки ставит родителя
    заново, из заголовка, и спан оказывается братом — чтение тела и заливка в
    S3 висят в дереве отдельно от запроса, внутри которого выполняются.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from gateway_app.observability import tracing_middleware
    from vscommon.telemetry import span

    app = FastAPI()
    app.middleware("http")(tracing_middleware)

    @app.get("/v1/scan/{scan_id}")
    def handler(scan_id: str) -> dict[str, bool]:
        with span("scan.accept", scan_id=scan_id):
            pass
        return {"ok": True}

    response = TestClient(app).get("/v1/scan/abc123", headers={"traceparent": CLIENT_TRACEPARENT})
    assert response.status_code == 200

    by_name = {s.name: s for s in tracing.get_finished_spans()}
    accept, server = by_name["scan.accept"], by_name["GET /v1/scan/{scan_id}"]

    assert accept.parent is not None, "спан приёма остался корневым"
    assert accept.parent.span_id == server.context.span_id, "приём стал братом, а не потомком"
    assert f"{accept.context.trace_id:032x}" == CLIENT_TRACE


async def test_history_write_lands_in_the_scan_trace(tracing: Any) -> None:
    """Writer перестал быть тупиком трейса.

    Трассировка в нём настраивалась, но ни одного спана он не отдавал:
    `ScanRecord` не нёс контекст, и трейс скана обрывался на публикации в
    поток. На вопрос «запись доехала до базы?» трейс не отвечал — при том что
    `vs_history_lag_seconds` заведён ровно про это, а разбирают отставание
    всегда по одному конкретному файлу.

    Спан на запись, а не только на сброс пачки: пачка общая, а трейсы у записей
    разные, и спан вокруг сброса ответил бы «пачка доехала».
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

    record = ScanRecord(
        result=ScanResult(
            scan_id="a" * 32,
            sha256="b" * 64,
            status=ScanStatus.DONE,
            verdict=Verdict.CLEAN,
            created_at=time.time() - 5,
        ),
        tenant="team-a",
        traceparent=CLIENT_TRACEPARENT,
    )

    await Writer._flush(_Stub(), [("1-0", record)])  # type: ignore[arg-type]

    by_name = {s.name: s for s in tracing.get_finished_spans()}
    assert "history.write" in by_name, "запись в историю не попала в трейс"
    assert f"{by_name['history.write'].context.trace_id:032x}" == CLIENT_TRACE, (
        "спан записи ушёл в собственный трейс, а не в трейс скана"
    )
    assert by_name["history.write"].attributes["lag_s"] >= 5.0


async def test_history_write_survives_a_record_without_context(tracing: Any) -> None:
    """Запись без контекста пишется, а не теряется.

    Контекст мог не доехать: трассировка выключена, запись пришла из старой
    версии сервиса или из потока, лежавшего с прошлого выката. Телеметрия не
    повод не записать историю.
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
            self.stored = 0

        async def store(self, records: list[Any]) -> int:
            self.stored += len(records)
            return len(records)

        async def ack(self, entry_id: str) -> None:
            return None

    stub = _Stub()
    record = ScanRecord(
        result=ScanResult(
            scan_id="c" * 32, sha256="d" * 64, status=ScanStatus.DONE, verdict=Verdict.CLEAN
        ),
        traceparent="",
    )

    await Writer._flush(stub, [("1-0", record)])  # type: ignore[arg-type]

    assert stub.stored == 1
    assert _value("vs_history_writes_total", outcome="applied") == 1.0


def test_foreign_context_is_accepted_only_at_boundaries() -> None:
    """`continue_trace` — только там, где чужой контекст действительно входит.

    Проверка структурная, и это тот случай, когда иначе нельзя: утверждение
    здесь не про поведение одной функции, а про то, что во всей кодовой базе
    таких мест ровно четыре. Поведенческий тест на «нигде больше» пришлось бы
    писать по одному на каждый будущий вызов.

    Смысл ограничения. `continue_trace` ставит родителя явно, из заголовка или
    из поля задачи. В середине обработки это даёт не потомка, а брата: спан
    приёма висел бы в дереве отдельно от серверного спана, внутри которого он
    на самом деле выполняется, — и время, потраченное до него, объяснить было
    бы нечем. Внутри процесса нужен обычный `span()`, он вкладывается сам.

    Четыре границы: HTTP на входе в gateway, очередь задач у воркера, очереди
    коллбэков и выгрузки у notifier, поток истории у writer. За каждой —
    настоящий разрыв во времени и в процессах, через который контекст иначе не
    проходит.
    """
    root = Path(__file__).parent.parent
    boundaries = {
        "services/gateway/gateway_app/observability.py",
        "services/notifier/notifierapp/main.py",
        "services/worker/worker_app/main.py",
        "services/writer/writerapp/main.py",
    }

    callers = {
        str(path.relative_to(root))
        for path in [*root.glob("services/**/*.py"), *root.glob("packages/**/*.py")]
        if path.name != "telemetry.py" and "continue_trace(" in path.read_text()
    }

    assert callers == boundaries, (
        "чужой контекст принимается не на границе: "
        f"лишние {sorted(callers - boundaries)}, потерянные {sorted(boundaries - callers)}"
    )
