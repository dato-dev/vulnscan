"""M2.8: разделяемые движки под параллельной нагрузкой.

Стадии выполняются в пуле потоков (`asyncio.to_thread`), а объекты движков
хранят состояние. Здесь проверяется, что на каждый такой объект есть либо
блокировка, либо экземпляр на поток.
"""

from __future__ import annotations

import threading
from pathlib import Path

from vscommon.models import ObjectRef, ScanJob
from vscommon.weights import WeightTable
from worker_app.stages.base import ScanContext
from worker_app.stages.clamav import ClamavStage
from worker_app.stages.filetype_detect import TypeDetector
from worker_app.stages.yara_rules import YaraStage

THREADS = 8


def _job() -> ScanJob:
    return ScanJob(scan_id="t", sha256="a" * 64, source=ObjectRef(bucket="b", key="k"), size=1)


def _ctx(path: Path) -> ScanContext:
    return ScanContext(job=_job(), path=path, weights=WeightTable())


def _run_parallel(target, count: int = THREADS) -> None:
    threads = [threading.Thread(target=target) for _ in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


class OverlapDetector:
    """Ловит перекрытие вызовов внутри одного объекта движка."""

    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.calls = 0
        self._guard = threading.Lock()

    def enter(self) -> None:
        with self._guard:
            self.active += 1
            self.calls += 1
            self.peak = max(self.peak, self.active)

    def leave(self) -> None:
        with self._guard:
            self.active -= 1


# --- clamd: экземпляр на поток ---


class FakeClamd:
    """Повторяет опасное место настоящего клиента: сокет — поле экземпляра."""

    def __init__(self, detector: OverlapDetector) -> None:
        self._detector = detector
        self.socket: str | None = None

    def version(self) -> str:
        return "ClamAV 1.4.1/27100"

    def instream(self, buff) -> dict[str, tuple[str, None]]:
        self._detector.enter()
        try:
            self.socket = threading.current_thread().name
            for _ in range(500):
                pass
            # Если клиент общий, здесь окажется имя чужого потока.
            assert self.socket == threading.current_thread().name, "сокет перехвачен"
            return {"stream": ("OK", None)}
        finally:
            self._detector.leave()


def test_each_thread_gets_own_clamd_client(tmp_path: Path) -> None:
    """Клиент clamd хранит сокет в себе — общий экземпляр перепутал бы файлы."""
    path = tmp_path / "f.bin"
    path.write_bytes(b"data")
    created: list[FakeClamd] = []
    detector = OverlapDetector()
    lock = threading.Lock()

    def factory() -> FakeClamd:
        client = FakeClamd(detector)
        with lock:
            created.append(client)
        return client

    stage = ClamavStage(factory=factory)
    _run_parallel(lambda: stage.run(_ctx(path)))

    assert detector.calls == THREADS
    # Экземпляров столько же, сколько потоков: общего клиента нет.
    assert len({id(c) for c in created}) == THREADS


def test_clamd_client_reused_within_thread(tmp_path: Path) -> None:
    """Соединение на каждый файл открывать незачем — клиент живёт на поток."""
    path = tmp_path / "f.bin"
    path.write_bytes(b"data")
    created: list[FakeClamd] = []
    detector = OverlapDetector()

    def factory() -> FakeClamd:
        client = FakeClamd(detector)
        created.append(client)
        return client

    stage = ClamavStage(factory=factory)
    for _ in range(5):
        stage.run(_ctx(path))

    assert len(created) == 1
    assert detector.calls == 5


def test_clamd_version_read_once(tmp_path: Path) -> None:
    """Версия баз входит в ключ AV-кэша — читаем её один раз на процесс."""
    path = tmp_path / "f.bin"
    path.write_bytes(b"data")
    detector = OverlapDetector()
    stage = ClamavStage(factory=lambda: FakeClamd(detector))

    _run_parallel(lambda: stage.run(_ctx(path)))

    assert stage.engine_version == "ClamAV 1.4.1/27100"


# --- YARA: общий объект, вызовы сериализованы ---


class FakeRules:
    def __init__(self, detector: OverlapDetector) -> None:
        self._detector = detector

    def match(self, path: str, timeout: int = 0) -> list:
        self._detector.enter()
        try:
            for _ in range(500):
                pass
            return []
        finally:
            self._detector.leave()


def test_yara_matches_are_serialised(tmp_path: Path) -> None:
    """Гарантий потокобезопасности `yara.Rules` между версиями нет."""
    path = tmp_path / "f.bin"
    path.write_bytes(b"data")
    detector = OverlapDetector()
    stage = YaraStage(rules=FakeRules(detector))

    _run_parallel(lambda: stage.run(_ctx(path)))

    assert detector.calls == THREADS
    assert detector.peak == 1


def test_yara_compiled_once_under_concurrency(tmp_path: Path, monkeypatch) -> None:
    """Двойная компиляция при старте — лишние секунды и лишняя память."""
    path = tmp_path / "f.bin"
    path.write_bytes(b"data")
    detector = OverlapDetector()
    compiles = []

    stage = YaraStage()
    monkeypatch.setattr(stage, "_compile", lambda: (compiles.append(1), FakeRules(detector))[1])

    _run_parallel(lambda: stage.run(_ctx(path)))

    assert len(compiles) == 1


# --- libmagic: общий объект под блокировкой (закрыто в M2.1) ---


class FakeMagic:
    def __init__(self, detector: OverlapDetector) -> None:
        self._detector = detector

    def from_buffer(self, buf: bytes) -> str:
        self._detector.enter()
        try:
            for _ in range(500):
                pass
            return "application/pdf"
        finally:
            self._detector.leave()


def test_libmagic_calls_are_serialised() -> None:
    detector = OverlapDetector()
    api = TypeDetector(magic_impl=FakeMagic(detector))

    _run_parallel(lambda: api.detect(b"%PDF-1.7\n"))

    assert detector.calls == THREADS
    assert detector.peak == 1


# --- таблица весов: общая, но мутация безобидна ---


def test_weight_table_survives_parallel_reads() -> None:
    """`unknown_codes` пополняется из потоков; `set.add` атомарен."""
    table = WeightTable()

    def hammer() -> None:
        for i in range(50):
            table.rule_for("PDF_JS")
            table.rule_for(f"НЕИЗВЕСТНЫЙ_{i % 5}")

    _run_parallel(hammer)

    assert len(table.unknown_codes) == 5
    assert table.rule_for("PDF_JS").score > 0
