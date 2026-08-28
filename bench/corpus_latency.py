"""Время до вердикта на корпусе реальных документов (ROADMAP M4.7).

Отличие от `bench/latency.py`: тот меряет стадии по отдельности на документах,
которые мы сами и сгенерировали — то есть на слишком аккуратных. Здесь берётся
внешний корпус (`corpus/pdfs`) и меряется полный проход: сколько времени
проходит от файла до вердикта.

Именно эта величина обещана клиенту, и именно она отличается от «латентности
API»: ответ из кэша и полный проход — разные вещи, а middleware их не различает.

Запуск: python bench/corpus_latency.py [--limit N] [--profile standard]
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages"))
sys.path.insert(0, str(ROOT / "services" / "worker"))

from vscommon.logging import setup_logging
from vscommon.models import CdrProfile, ObjectRef, ScanJob
from vscommon.storage import LocalStore
from worker_app.pipeline import Pipeline


@dataclass
class Measurement:
    milliseconds: list[float] = field(default_factory=list)
    verdicts: Counter[str] = field(default_factory=Counter)
    failed_stages: Counter[str] = field(default_factory=Counter)

    def quantile(self, q: float) -> float:
        if not self.milliseconds:
            return 0.0
        ordered = sorted(self.milliseconds)
        index = min(int(q * len(ordered)), len(ordered) - 1)
        return ordered[index]


def _job(path: Path, key: str, profile: CdrProfile) -> ScanJob:
    return ScanJob(
        scan_id=f"bench{abs(hash(key)):024x}"[:32],
        sha256="ab" * 32,
        source=ObjectRef(backend="local", bucket="raw", key=key, size=path.stat().st_size),
        size=path.stat().st_size,
        profile=profile,
        filename_ext=".pdf",
    )


async def run(limit: int, profile: CdrProfile) -> int:
    corpus = sorted((ROOT / "corpus" / "pdfs").glob("*.pdf"))[:limit]
    if not corpus:
        print("корпус пуст — сначала python corpus/fetch.py")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "raw").mkdir(parents=True, exist_ok=True)
        pipeline = Pipeline(LocalStore(str(root)))
        pipeline.warmup()

        result = Measurement()
        for source in corpus:
            key = source.name
            (root / "raw" / key).write_bytes(source.read_bytes())

            started = time.perf_counter()
            scan = await pipeline.process(_job(source, key, profile))
            result.milliseconds.append((time.perf_counter() - started) * 1000)

            result.verdicts[scan.verdict.value] += 1
            for finding in scan.findings:
                if finding.code == "STAGE_FAILED":
                    result.failed_stages[finding.stage] += 1

    _report(result, profile, len(corpus))
    return 0


def _report(result: Measurement, profile: CdrProfile, total: int) -> None:
    print(f"\nВремя до вердикта, профиль {profile.value}, документов: {total}\n")
    print(f"  p50   {result.quantile(0.50):8.1f} мс")
    print(f"  p95   {result.quantile(0.95):8.1f} мс   ← цель ≤ 700")
    print(f"  p99   {result.quantile(0.99):8.1f} мс   ← цель ≤ 2000")
    print(f"  max   {max(result.milliseconds):8.1f} мс")
    print(f"  сред. {statistics.mean(result.milliseconds):8.1f} мс\n")

    print("Вердикты:")
    for verdict, count in result.verdicts.most_common():
        share = 100 * count / total
        print(f"  {verdict:12} {count:4}  ({share:5.1f}%)")

    if result.failed_stages:
        # Упавшая стадия вердикт почти не меняет, но означает, что проверка
        # фактически не выполнялась. На замере это надо видеть отдельно.
        print("\nСтадии, не отработавшие ни разу или падавшие:")
        for stage, count in result.failed_stages.most_common():
            print(f"  {stage:12} {count:4}")

    within = sum(1 for ms in result.milliseconds if ms <= 400)
    share = 100 * within / total
    print(f"\nУложились в синхронный ответ (wait_ms=400): {share:.1f}%  ← цель ≥ 80%")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--profile", default="standard", choices=[p.value for p in CdrProfile])
    args = parser.parse_args()

    setup_logging("bench", "WARNING", "console")
    return asyncio.run(run(args.limit, CdrProfile(args.profile)))


if __name__ == "__main__":
    raise SystemExit(main())
