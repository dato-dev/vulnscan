"""Тексты для пользователя: понятность и отсутствие внутренней кухни."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "telegram-bot"))

from botapp import wording
from botapp.main import _clean_name
from vscommon.weights import DEFAULT_WEIGHTS

DYNAMIC = ("YARA:",)
"""Ключи весов, у которых нет фиксированного кода признака."""


def _described(code: str) -> bool:
    return wording.describe([code]) != "• необычное содержимое"


@pytest.mark.parametrize(
    "code",
    sorted(
        c for c, rule in DEFAULT_WEIGHTS.items() if rule.score > 0 and not c.startswith(DYNAMIC)
    ),
)
def test_every_meaningful_code_has_plain_description(code: str) -> None:
    """Новый признак не должен превращаться в «необычное содержимое»."""
    assert _described(code), f"для {code} нет человеческого описания в wording._CATEGORIES"


def test_yara_match_described_without_rule_name() -> None:
    """Имя правила — внутренняя кухня, наружу не отдаём."""
    text = wording.describe(["YARA_PDF_LAUNCH_ACTION"])

    assert "совпадение" in text
    assert "PDF_LAUNCH_ACTION" not in text


def test_unknown_code_does_not_claim_everything_is_fine() -> None:
    """Врать про «ничего не нашли» нельзя даже при неизвестном коде."""
    text = wording.describe(["СОВСЕМ_НОВЫЙ_ПРИЗНАК"])

    assert "необычное содержимое" in text


def test_no_findings_still_gives_a_hint() -> None:
    assert wording.describe([]) and wording.describe(None)


def test_long_list_is_trimmed() -> None:
    """Простыня из десяти пунктов человеку не помогает."""
    codes = ["PDF_JS", "PDF_EMBEDDED_FILE", "PDF_EXTERNAL_URI", "PDF_DAMAGED", "MIME_MISMATCH"]

    text = wording.describe(codes)

    assert text.count("•") == wording.MAX_LISTED + 1
    assert "и ещё" in text


def test_captions_explain_that_it_is_a_copy() -> None:
    """Главное, чего не хватало: человек получает копию, а не свой файл."""
    for text in (wording.CLEAN_CAPTION, wording.SUSPICIOUS_CAPTION, wording.GREETING):
        assert "копи" in text.lower()


def test_clean_caption_does_not_imply_something_was_found() -> None:
    """«Обезврежен» звучало так, будто в файле что-то было."""
    assert "обезвреж" not in wording.CLEAN_CAPTION.lower()


def test_blocked_message_reveals_nothing() -> None:
    """Что именно сработало — подсказка тому, кто подбирает обход."""
    lowered = wording.BLOCKED.lower()

    assert not any(word in lowered for word in ("javascript", "launch", "yara", "сигнатур"))


@pytest.mark.parametrize(
    ("filename", "suffix", "expected"),
    [
        ("Документ 1.pdf", ".pdf", "Документ 1-проверено.pdf"),
        ("фото.jpg", ".jpg", "фото-проверено.jpg"),
        ("картинка.gif", ".png", "картинка-проверено.png"),
        ("без-расширения", "", "без-расширения-проверено"),
    ],
)
def test_copy_name_keeps_real_extension(filename: str, suffix: str, expected: str) -> None:
    """Профиль CDR может сменить формат; раньше картинки шли без расширения."""
    assert _clean_name(filename, suffix) == expected


# --- сравнение вердиктов для второго ответа ---


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("clean", "malicious", True),
        ("clean", "suspicious", True),
        ("suspicious", "malicious", True),
        ("suspicious", "clean", False),
        ("malicious", "suspicious", False),
        ("clean", "clean", False),
    ],
)
def test_worse_verdict_detected(before: str, after: str, expected: bool) -> None:
    """Беспокоить человека стоит только если стало хуже."""
    assert wording.got_worse(before, after) is expected


def test_unknown_verdict_is_not_alarming() -> None:
    """«Кажется, что-то не так» — бесполезное сообщение."""
    assert not wording.got_worse("clean", "неизвестно")
    assert not wording.got_worse("", "malicious")


def test_followup_texts_reference_the_sent_copy() -> None:
    """Человек уже получил файл — сообщение должно сказать, что с ним делать."""
    for text in (wording.WORSE_AFTER_DEEP, wording.BLOCKED_AFTER_DEEP):
        assert "копию" in text.lower()
