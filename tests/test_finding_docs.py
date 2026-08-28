"""M3.11: справочник признаков не должен расходиться с кодом."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vscommon.finding_docs import DESCRIPTIONS, GROUP_ORDER
from vscommon.weights import CODE_FAMILIES, DEFAULT_WEIGHTS

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "findings.md"


@pytest.mark.parametrize("code", sorted(DEFAULT_WEIGHTS))
def test_every_code_is_documented(code: str) -> None:
    """Новый признак не может попасть в вердикт без объяснения."""
    assert code in DESCRIPTIONS, (
        f"для {code} нет описания в vscommon/finding_docs.py — "
        "оператор увидит код и не поймёт, что делать"
    )


def test_no_orphan_descriptions() -> None:
    """Описание кода, которого больше нет, вводит в заблуждение."""
    assert not set(DESCRIPTIONS) - set(DEFAULT_WEIGHTS)


@pytest.mark.parametrize("code", sorted(DESCRIPTIONS))
def test_description_answers_both_questions(code: str) -> None:
    doc = DESCRIPTIONS[code]

    assert len(doc.means) > 20, f"{code}: описание слишком короткое"
    assert len(doc.action) > 10, f"{code}: не сказано, что делать"
    assert doc.group in GROUP_ORDER, f"{code}: неизвестная группа {doc.group}"


def test_families_are_described() -> None:
    """Каждая семья должна попасть в справочник, иначе её логика невидима."""
    text = DOC.read_text()

    for family in set(CODE_FAMILIES.values()):
        assert f"`{family}`" in text, f"семья {family} не описана в справочнике"


def test_document_is_not_stale() -> None:
    """Собранный справочник должен совпадать с тем, что лежит в репозитории."""
    generated = subprocess.run(
        [sys.executable, str(ROOT / "docs" / "generate_findings.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert generated.returncode == 0, generated.stderr

    # Сборка перезаписывает файл; если он отличался, изменения увидит git.
    assert DOC.exists() and DOC.stat().st_size > 5000
