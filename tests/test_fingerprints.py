"""Отпечатки, входящие в ключ структурного кэша (долг D2).

`POLICY_VERSION` был константой, которую правили руками: смену смысла вердиктов
надо было заметить и поднять версию. Забытая правка означала, что записи,
снятые по старой семантике, продолжали считаться действительными — ровно тот
способ, которым в этом проекте уже несколько раз протухали кэшированные факты.
"""

from __future__ import annotations

from vscommon import models
from vscommon.models import POLICY_VERSION
from vscommon.weights import CODE_FAMILIES, DEFAULT_WEIGHTS, Rule, Severity, WeightTable


def test_policy_version_is_computed_not_written() -> None:
    """Отпечаток, а не дата в строке."""
    assert models._policy_fingerprint() == POLICY_VERSION
    assert POLICY_VERSION.startswith("p")
    assert len(POLICY_VERSION) == 13


def test_policy_version_is_stable_between_calls() -> None:
    """Иначе каждый перезапуск обесценивал бы весь кэш."""
    assert models._policy_fingerprint() == models._policy_fingerprint()


def test_new_verdict_changes_the_fingerprint(monkeypatch) -> None:
    """Появление вердикта меняет смысл записи, значит и ключ.

    Старые записи снимались, когда такого исхода не существовало.
    """
    before = models._policy_fingerprint()
    monkeypatch.setattr(
        models, "UNSCANNABLE_VERDICTS", models.UNSCANNABLE_VERDICTS | {models.Verdict.MALICIOUS}
    )
    assert models._policy_fingerprint() != before


def test_request_derived_codes_change_the_fingerprint(monkeypatch) -> None:
    """Эти признаки зависят от того, что прислал клиент, а не от содержимого.

    Меняется их состав — меняется то, что вообще можно кэшировать по хэшу.
    """
    before = models._policy_fingerprint()
    monkeypatch.setattr(models, "REQUEST_DERIVED_CODES", frozenset({"MIME_MISMATCH"}))

    assert models._policy_fingerprint() != before


# --- отпечаток весов ------------------------------------------------------


def test_weight_change_invalidates_cache() -> None:
    """Признаки хранятся с уже посчитанными баллами."""
    base = WeightTable(DEFAULT_WEIGHTS)
    changed = dict(DEFAULT_WEIGHTS)
    code = next(iter(changed))
    changed[code] = Rule(score=changed[code].score + 1, severity=changed[code].severity)

    assert WeightTable(changed).fingerprint() != base.fingerprint()


def test_family_regrouping_invalidates_cache(monkeypatch) -> None:
    """Перегруппировка меняет балл при тех же весах.

    Внутри семейства в счёт идёт только сильнейший признак, поэтому иная
    группировка даёт иной результат — а старая запись пережила бы правку и
    отдала бы балл, посчитанный по прежним семьям.
    """
    import vscommon.weights as weights_module

    before = WeightTable(DEFAULT_WEIGHTS).fingerprint()
    monkeypatch.setitem(weights_module.CODE_FAMILIES, "выдуманное", frozenset({"PDF_JS"}))

    assert WeightTable(DEFAULT_WEIGHTS).fingerprint() != before


def test_severity_change_invalidates_cache() -> None:
    base = WeightTable(DEFAULT_WEIGHTS)
    changed = dict(DEFAULT_WEIGHTS)
    code = next(iter(changed))
    other = Severity.LOW if changed[code].severity is not Severity.LOW else Severity.HIGH
    changed[code] = Rule(score=changed[code].score, severity=other)

    assert WeightTable(changed).fingerprint() != base.fingerprint()


def test_fingerprints_are_independent() -> None:
    """Веса и семантика покрыты раздельно и не дублируют друг друга.

    Иначе один и тот же факт учитывался бы дважды, а связность модулей выросла
    бы до циклического импорта.
    """
    assert WeightTable(DEFAULT_WEIGHTS).fingerprint() != POLICY_VERSION
    assert CODE_FAMILIES, "семейства должны существовать — иначе тест выше бессмыслен"
