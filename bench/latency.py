"""Замер латентности конвейера на синтетическом корпусе (ROADMAP M2.7).

Корпус собирается на месте: реальные документы пользователей в репозиторий
не попадают. Профиль нагрузки подобран под поток чат-бота — сканы паспортов и
договоров, то есть PDF на одну-пять страниц и фотографии с телефона.

Запуск: python bench/latency.py [--runs N]
"""

from __future__ import annotations

import argparse
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "worker"))

from vscommon.logging import setup_logging
from vscommon.models import CdrProfile, ObjectRef, ScanJob
from vscommon.weights import WeightTable
from worker_app.cdr.base import SanitizeError
from worker_app.cdr.registry import sanitize
from worker_app.stages.base import ScanContext
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.structure import StructureStage


@dataclass
class Series:
    name: str
    samples: list[float] = field(default_factory=list)

    def add(self, seconds: float) -> None:
        self.samples.append(seconds * 1000)

    def quantile(self, q: float) -> float:
        if not self.samples:
            return 0.0
        ordered = sorted(self.samples)
        index = min(len(ordered) - 1, int(q * len(ordered)))
        return ordered[index]

    @property
    def p50(self) -> float:
        return statistics.median(self.samples) if self.samples else 0.0


def build_corpus(root: Path) -> dict[str, Path]:
    """Профиль, близкий к реальному потоку бота."""
    import pikepdf
    from PIL import Image

    corpus: dict[str, Path] = {}

    def pdf(name: str, pages: int, payload: int) -> None:
        doc = pikepdf.Pdf.new()
        for _ in range(pages):
            doc.add_blank_page(page_size=(595, 842))
        if payload:
            # Несжимаемые данные: иначе «10 МБ» превратятся в десяток килобайт.
            doc.Root["/VSBallast"] = doc.make_indirect(
                pikepdf.Stream(doc, _incompressible(payload))
            )
        path = root / name
        doc.save(path)
        corpus[name] = path

    def image(name: str, size: tuple[int, int], fmt: str) -> None:
        path = root / name
        Image.frombytes("RGB", size, _incompressible(size[0] * size[1] * 3)).save(path, fmt)
        corpus[name] = path

    pdf("pdf-1стр-скан.pdf", pages=1, payload=180_000)
    pdf("pdf-5стр-договор.pdf", pages=5, payload=900_000)
    pdf("pdf-20стр-крупный.pdf", pages=20, payload=4_000_000)
    pdf("pdf-100стр-тяжёлый.pdf", pages=100, payload=9_000_000)
    image("jpeg-фото-3мп.jpg", (2048, 1536), "JPEG")
    image("png-скан-a4.png", (1240, 1754), "PNG")
    return corpus


def _incompressible(size: int) -> bytes:
    """Псевдослучайные байты без внешних зависимостей."""
    chunk = bytearray()
    value = 0x2545F491
    while len(chunk) < size:
        value = (value * 1103515245 + 12345) & 0xFFFFFFFF
        chunk += value.to_bytes(4, "little")
    return bytes(chunk[:size])


def _cell(series: Series) -> str:
    return f"{series.p50:.1f}" if series.samples else "н/д"


def _job(path: Path) -> ScanJob:
    return ScanJob(
        scan_id="bench",
        sha256="0" * 64,
        source=ObjectRef(bucket="b", key="k"),
        size=path.stat().st_size,
        filename_ext=path.suffix,
    )


def measure(label: str, fn: Callable[[], None], runs: int) -> Series:
    series = Series(label)
    for _ in range(runs):
        started = time.perf_counter()
        fn()
        series.add(time.perf_counter() - started)
    return series


def run(runs: int) -> None:
    setup_logging("bench", "CRITICAL", "console")
    root = Path(tempfile.mkdtemp(prefix="vsbench-"))
    corpus = build_corpus(root)
    weights = WeightTable()
    out = root / "clean"
    out.mkdir()

    print(f"\nкорпус в {root}, прогонов на файл: {runs}\n")
    print(
        f"{'файл':26}{'размер':>9}{'filetype':>10}{'structure':>11}"
        f"{'CDR standard':>14}{'CDR strict':>12}{'итого p50':>11}"
    )
    print("-" * 93)

    totals: dict[str, Series] = {}
    unavailable: set[str] = set()

    for name, path in corpus.items():
        size_mb = path.stat().st_size / 1024 / 1024

        def scan_stage(stage, p=path):
            ctx = ScanContext(job=_job(p), path=p, weights=weights)
            FiletypeStage().safe_run(ctx)
            if stage == "structure":
                StructureStage().safe_run(ctx)
            return ctx

        ft = measure(
            "filetype",
            lambda p=path: FiletypeStage().safe_run(
                ScanContext(job=_job(p), path=p, weights=weights)
            ),
            runs,
        )
        st = measure("structure", lambda: scan_stage("structure"), runs)

        ctx = scan_stage("structure")
        mime = ctx.detected_mime

        cdr: dict[str, Series] = {}
        for profile in (CdrProfile.STANDARD, CdrProfile.STRICT):
            target = out / f"{name}-{profile.value}"
            target.mkdir(exist_ok=True)

            failures: list[str] = []

            def sanitize_once(p=path, d=target, pr=profile, m=mime, f=failures):
                try:
                    sanitize(p, d, m, pr)
                except SanitizeError as exc:
                    f.append(str(exc))

            series = measure(f"cdr-{profile.value}", sanitize_once, max(runs // 2, 1))
            if failures:
                # Замер провалившегося профиля — это замер ветки отказа.
                # Выдавать его за латентность CDR нельзя.
                series.samples.clear()
                unavailable.add(profile.value)
            cdr[profile.value] = series

        total = st.p50 + cdr["standard"].p50
        totals[name] = Series(name, [total])
        print(
            f"{name:26}{size_mb:8.1f}М{ft.p50:10.2f}{st.p50:11.1f}"
            f"{_cell(cdr['standard']):>14}{_cell(cdr['strict']):>12}{total:11.1f}"
        )

    print("-" * 93)
    print("\nВсе значения — миллисекунды, p50. `structure` включает `filetype`.")
    print("Стадии clamav и yara не измеряются: движков нет в этом окружении.")
    if unavailable:
        print(
            f"Профили CDR {', '.join(sorted(unavailable))} не измерены: "
            "нужного инструмента нет в системе (для strict это ghostscript)."
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=15)
    args = parser.parse_args()
    run(args.runs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
