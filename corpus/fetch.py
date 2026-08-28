"""Загрузка тестового корпуса PDF.

Корпус в репозиторий не кладётся: он большой, а `.gitignore` бережёт нас от
привычки коммитить чужие файлы. Здесь только манифест с разметкой — по нему
выборка воспроизводится один в один на любой машине.

Источник: датасет Cyber-security-final-project/Generated_Injected_PDFs_HARMLESS
на Hugging Face. Файлы объявлены безвредными: инъекции состоят из тестовых
образцов вроде EICAR, а не из настоящего вредоносного кода.

Запуск: python corpus/fetch.py --budget-mb 150
"""

from __future__ import annotations

import argparse
import collections
import csv
import random
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent
MANIFEST = ROOT / "manifest.csv"
PDF_DIR = ROOT / "pdfs"
BASE_URL = (
    "https://huggingface.co/datasets/Cyber-security-final-project/"
    "Generated_Injected_PDFs_HARMLESS/resolve/main/Output_PDFs"
)
CLEAN_LABEL = "none"
SEED = 42


def stratified(rows: list[dict], clean: int, per_type: int) -> list[dict]:
    """Выборка с фиксированным зерном: один и тот же набор на любой машине."""
    random.seed(SEED)
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        grouped[row["injection_type"]].append(row)

    chosen: list[dict] = []
    for kind in sorted(grouped):
        quota = clean if kind == CLEAN_LABEL else per_type
        pool = sorted(grouped[kind], key=lambda r: r["output_file"])
        chosen += random.sample(pool, min(quota, len(pool)))
    return chosen


def download(name: str, dest: Path, budget_left: int) -> int:
    """Возвращает размер скачанного или 0, если файл пропущен."""
    if dest.exists():
        return dest.stat().st_size

    try:
        with urllib.request.urlopen(f"{BASE_URL}/{name}", timeout=60) as response:
            size = int(response.headers.get("Content-Length", 0))
            if size > budget_left:
                return 0
            dest.write_bytes(response.read())
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"  пропуск {name}: {type(exc).__name__}")
        return 0
    return dest.stat().st_size


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--budget-mb", type=int, default=150)
    parser.add_argument("--clean", type=int, default=80, help="сколько чистых файлов")
    parser.add_argument("--per-type", type=int, default=8, help="сколько на каждый тип инъекции")
    args = parser.parse_args()

    if not MANIFEST.exists():
        print(f"нет манифеста: {MANIFEST}")
        return 1

    PDF_DIR.mkdir(exist_ok=True)
    rows = list(csv.DictReader(MANIFEST.open()))
    selection = stratified(rows, args.clean, args.per_type)

    budget = args.budget_mb * 1024 * 1024
    downloaded = skipped = 0

    print(f"выбрано {len(selection)} файлов, бюджет {args.budget_mb} МБ")
    for row in selection:
        size = download(row["output_file"], PDF_DIR / row["output_file"], budget)
        if size:
            budget -= size
            downloaded += 1
        else:
            skipped += 1
        if budget <= 0:
            print("  бюджет исчерпан")
            break

    have = list(PDF_DIR.glob("*.pdf"))
    total = sum(p.stat().st_size for p in have)
    print(f"\nскачано {downloaded}, пропущено {skipped}")
    print(f"в каталоге {len(have)} файлов, {total / 1024 / 1024:.0f} МБ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
