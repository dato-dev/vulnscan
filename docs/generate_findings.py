"""Сборка справочника кодов признаков из кода.

Справочник, написанный руками, расходится с реальностью на первом же новом
признаке. Здесь он собирается из таблицы весов и описаний рядом с ней —
разойтись не может.

Запуск: python docs/generate_findings.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages"))

from vscommon.finding_docs import DESCRIPTIONS, GROUP_ORDER
from vscommon.weights import CODE_FAMILIES, DEFAULT_WEIGHTS, FALLBACK

OUT = Path(__file__).parent / "findings.md"

HEADER = """# Справочник признаков

Каждая проверка возвращает признаки — это коды вида `PDF_LAUNCH`. Из их весов
складывается балл, из балла — вердикт. Коды видны в ответах API, в логах и в
отчёте теневого режима.

**Коды — часть публичного контракта.** Переименование ломает клиентов, которые
на них смотрят, поэтому старый код не переименовывают, а заводят новый.

Этот файл собирается из кода: `make findings-doc`. Правки вносите в
`packages/vscommon/finding_docs.py`, иначе они потеряются при следующей сборке.

## Как читать

У каждого признака указан **вес** — вклад в балл — и, если есть, **семья**.
Дальше сказано, что признак означает, а курсивом — что с ним делать.

Пороги по умолчанию: `suspicious` от {suspicious} баллов, `malicious` от
{block}. Признак весом 100 блокирует сам по себе, не складываясь. Вес `0` —
справочный: в балл не входит и пользователю не показывается.

Веса настраиваются через `WEIGHTS_FILE` и переопределяются на тенанта, так что
в вашей установке они могут отличаться от приведённых. Код, которого нет в
таблице весов, получает запасной вес {fallback} и попадает в `unknown_codes` —
забытый признак должен быть заметен, а не исчезать молча.

Подробнее о весах, порогах и семьях — в [policies.md](policies.md).
"""


def render() -> str:
    from vscommon.models import TenantPolicy

    policy = TenantPolicy()
    parts = [
        HEADER.format(
            suspicious=policy.suspicious_threshold,
            block=policy.block_threshold,
            fallback=FALLBACK.score,
        )
    ]

    grouped: dict[str, list[str]] = {group: [] for group in GROUP_ORDER}
    for code in sorted(DESCRIPTIONS):
        grouped[DESCRIPTIONS[code].group].append(code)

    for group in GROUP_ORDER:
        codes = grouped[group]
        if not codes:
            continue
        parts.append(f"\n## {group}\n")
        for code in codes:
            doc = DESCRIPTIONS[code]
            rule = DEFAULT_WEIGHTS.get(code, FALLBACK)
            family = CODE_FAMILIES.get(code)
            meta = f"вес **{rule.score}**, {rule.severity.value}"
            if family:
                meta += f", семья `{family}`"
            parts.append(f"### `{code}`\n\n{meta}\n\n{doc.means}\n\n*{doc.action}*\n")

    parts.append(_families_section())
    return "\n".join(parts)


def _families_section() -> str:
    families: dict[str, list[str]] = {}
    for code, family in sorted(CODE_FAMILIES.items()):
        families.setdefault(family, []).append(code)

    rows = "\n".join(
        f"| `{family}` | {', '.join(f'`{c}`' for c in codes)} |"
        for family, codes in sorted(families.items())
    )
    return (
        "\n## Семьи признаков\n\n"
        "Проверки, увидевшие одно и то же свойство файла с разных сторон, не "
        "должны складываться: внутри семьи в балл идёт только сильнейший.\n\n"
        "| Семья | Признаки |\n|---|---|\n" + rows + "\n"
    )


def main() -> int:
    OUT.write_text(render())
    print(f"{OUT}: {len(DESCRIPTIONS)} признаков, {OUT.stat().st_size // 1024} КБ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
