"""Прогон корпуса: ложные срабатывания и полнота детекта (ROADMAP M3.8).

Две метрики, и первая важнее второй:

* **ложные срабатывания** — сколько чистых файлов сервис перестал считать
  чистыми. Заблокированный легитимный документ дороже пропущенного тестового
  образца, поэтому именно на этой метрике проверка и падает;
* **детект** — сколько файлов с инъекциями замечены, с разбивкой по типам.

Запуск:
    python corpus/check.py                        # только локальные стадии
    python corpus/check.py --api http://localhost:8080   # весь конвейер
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packages"))
sys.path.insert(0, str(ROOT.parent / "services" / "worker"))

from app.scoring import verdict_of
from app.stages.base import ScanContext
from app.stages.filetype import FiletypeStage
from app.stages.structure import StructureStage

from vscommon.logging import setup_logging
from vscommon.models import ObjectRef, ScanJob, TenantPolicy
from vscommon.weights import WeightTable

MANIFEST = ROOT / "manifest.csv"
EXPECTED = ROOT / "expected.json"
PDF_DIR = ROOT / "pdfs"
CLEAN_LABEL = "none"
CLEAN_VERDICTS = frozenset({"clean"})


@dataclass
class Bucket:
    total: int = 0
    flagged: int = 0
    blocked: int = 0
    codes: collections.Counter = field(default_factory=collections.Counter)
    examples: list[str] = field(default_factory=list)


def scan_locally(path: Path, weights: WeightTable) -> tuple[str, int, list[str]]:
    job = ScanJob(
        scan_id="corpus",
        sha256="0" * 64,
        source=ObjectRef(bucket="b", key="k"),
        size=path.stat().st_size,
        filename_ext=".pdf",
    )
    ctx = ScanContext(job=job, path=path, weights=weights)
    FiletypeStage().safe_run(ctx)
    StructureStage().safe_run(ctx)
    verdict, score = verdict_of(ctx, TenantPolicy())
    return verdict.value, score, [f.code for f in ctx.findings if f.score > 0]


def scan_via_api(path: Path, api: str) -> tuple[str, int, list[str]]:
    boundary = "----vscorpus"
    meta = json.dumps({"wait_ms": 9000}).encode()
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="file"; filename="doc.pdf"\r\n',
            b"Content-Type: application/pdf\r\n\r\n",
            path.read_bytes(),
            f"\r\n--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="meta"\r\n\r\n',
            meta,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    request = urllib.request.Request(
        f"{api}/v1/scan",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Vulnscan-Tenant": "corpus",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = json.loads(response.read())
    return (
        payload["verdict"],
        payload["score"],
        [f["code"] for f in payload.get("findings", []) if f.get("score", 0) > 0],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", help="прогнать через живой сервис, а не локальные стадии")
    args = parser.parse_args()

    setup_logging("corpus", "CRITICAL", "console")
    if not PDF_DIR.exists():
        print("нет файлов: сначала python corpus/fetch.py")
        return 1

    labels = {r["output_file"]: r["injection_type"] for r in csv.DictReader(MANIFEST.open())}
    expected = {
        name: reason
        for name, reason in json.loads(EXPECTED.read_text()).items()
        if not name.startswith("_")
    }
    weights = WeightTable()
    buckets: dict[str, Bucket] = collections.defaultdict(Bucket)

    for path in sorted(PDF_DIR.glob("*.pdf")):
        kind = labels.get(path.name)
        if kind is None:
            continue
        verdict, _score, codes = (
            scan_via_api(path, args.api) if args.api else scan_locally(path, weights)
        )

        bucket = buckets[kind]
        bucket.total += 1
        if verdict not in CLEAN_VERDICTS:
            bucket.flagged += 1
            bucket.codes.update(codes)
            if kind == CLEAN_LABEL and path.name not in expected:
                bucket.examples.append(f"{path.name}: {verdict} ({','.join(sorted(set(codes)))})")
        if verdict == "malicious":
            bucket.blocked += 1

    clean = buckets.get(CLEAN_LABEL, Bucket())
    unexpected = clean.examples

    print(f"источник: {'сервис ' + args.api if args.api else 'локальные стадии'}\n")
    print(f"{'тип':30}{'файлов':>8}{'замечено':>10}{'блок':>7}  ведущие признаки")
    print("-" * 96)
    for kind in sorted(buckets, key=lambda k: (k == CLEAN_LABEL, k)):
        b = buckets[kind]
        share = f"{b.flagged}/{b.total}"
        top = ", ".join(f"{c}×{n}" for c, n in b.codes.most_common(3))
        print(f"{kind:30}{b.total:8}{share:>10}{b.blocked:7}  {top[:44]}")

    injected = [b for k, b in buckets.items() if k != CLEAN_LABEL]
    caught = sum(b.flagged for b in injected)
    total_injected = sum(b.total for b in injected)
    print("-" * 96)
    if total_injected:
        print(f"\nдетект по инъекциям:   {caught}/{total_injected} "
              f"({caught / total_injected * 100:.0f}%)")
    known = clean.flagged - len(unexpected)
    print(f"чистых файлов:         {clean.total}")
    print(f"  срабатываний:        {clean.flagged} "
          f"(разобрано и признано верными: {known})")
    print(f"  НЕ разобрано:        {len(unexpected)}")

    if unexpected:
        print("\nновые срабатывания на чистых файлах:")
        for example in unexpected:
            print(f"  {example}")
        print("\nПРОВАЛ: это либо ложные срабатывания, либо разбор,")
        print("который надо занести в corpus/expected.json с объяснением.")
        return 1

    print("\nновых срабатываний на чистых файлах нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
