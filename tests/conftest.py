from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Все пакеты сервисов: после переименования (долг D1) они не конфликтуют и
# живут в одном прогоне.
for extra in (
    ROOT / "packages",
    ROOT / "services" / "gateway",
    ROOT / "services" / "worker",
    ROOT / "services" / "bot",
    ROOT / "services" / "writer",
    ROOT / "services" / "notifier",
):
    sys.path.insert(0, str(extra))


@pytest.fixture()
def tmp_workspace(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    work.mkdir()
    return work
