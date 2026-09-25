"""Шлюз для YARA-правил: компиляция и прогон по корпусу до выкатки (M7.1).

Зачем отдельный шлюз. Правило, которое не компилируется, воркер не роняет:
`YaraStage.reload_if_changed` пишет `WARNING`, оставляет прежний набор и
продолжает работать. Решение верное — кривое правило не должно останавливать
проверку файлов. Но цена у него такая: снаружи это неотличимо от исправной
работы. Файлы проверяются, вердикты выдаются, метрики растут, и только новое
правило не действует — до тех пор, пока кто-нибудь не станет разбирать, почему
не сработало то, что должно было.

Второе, ради чего это существует: заблокированный легитимный документ дороже
пропущенного тестового образца. Поэтому проверка падает на **ложных
срабатываниях**, а не на проценте детекта.

Запуск:
    python rules/check.py           # компиляция + оба прогона
    python rules/check.py --compile-only

Без корпуса (`make corpus`) прогон по чистым файлам пропускается — и об этом
сказано в выводе явно, потому что «нечего проверять» и «всё хорошо» должны
выглядеть по-разному.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# Каталог скрипта из путей поиска убираем, и это не перестраховка. Рядом лежит
# `rules/yara/` — каталог без `__init__.py`, то есть неявный namespace-пакет.
# `import yara` отсюда находит ЕГО, а не библиотеку: импорт проходит, модуль
# есть, и падает всё только на `yara.compile` — то есть ошибка выглядит как
# несовместимая версия библиотеки, которой на машине вовсе нет.
sys.path[:] = [entry for entry in sys.path if Path(entry or ".").resolve() != Path(__file__).parent]

ROOT = Path(__file__).resolve().parent.parent
# Что правило видит в работе, решает воркер (`worker_app.yara_views`), и шлюз
# обязан видеть то же самое — иначе он проверял бы правила не в тех условиях.
for extra in (ROOT / "packages", ROOT / "services/worker"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))
RULES_DIR = ROOT / "rules/yara"
CORPUS = ROOT / "corpus"
SAMPLES = ROOT / "samples/generated"

CLEAN_LABEL = "none"

MUST_MATCH = {
    # файл в samples/generated → правило, которое обязано его заметить
    "pdf_launch.pdf": "pdf_launch_action",
    "pdf_openaction_js.pdf": "pdf_js_with_autoexec",
    # Правила для Word видят только распакованные части — ровно так, как их
    # отдаёт стадия. Образец для docvar ещё и сторожит молчаливый предел
    # YARA на длину повтора в регулярке (см. office.yar).
    "equation_editor.docx": "docx_equation_editor",
    "docvar_payload.docm": "docx_docvar_payload",
}
"""Синтетика, на которой правила обязаны срабатывать.

Полнота детекта здесь не измеряется — для этого есть корпус. Это защита от
другого: правило, отредактированное «чтобы убрать ложные срабатывания», легко
перестаёт ловить и то, ради чего написано, а на чистых файлах такая правка
выглядит улучшением.
"""


def compile_rules() -> object:
    """Компилирует весь набор. Отказ здесь — отказ выкатки."""
    try:
        import yara
    except ImportError:
        print(
            "yara-python не установлен: компилировать правила нечем.\n"
            "Это не «проверка пройдена» — это «проверка не выполнялась».\n"
            "  uv pip install yara-python",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    sources = {path.stem: str(path) for path in sorted(RULES_DIR.glob("*.yar"))}
    if not sources:
        print(f"в {RULES_DIR} нет ни одного файла правил", file=sys.stderr)
        raise SystemExit(2)

    from worker_app.yara_views import EXTERNALS

    compiled = yara.compile(filepaths=sources, externals=EXTERNALS)
    print(f"скомпилировано файлов правил: {len(sources)}")
    return compiled


def matched(rules: object, path: Path) -> set[str]:
    """Сработавшие правила — по всем видам файла, как в стадии YARA."""
    from worker_app.stages.filetype_detect import sniff
    from worker_app.yara_views import views

    hit: set[str] = set()
    for part, data in views(path, sniff(path)):
        if data is None:
            found = rules.match(str(path), externals={"part": ""})  # type: ignore[attr-defined]
        else:
            found = rules.match(data=data, externals={"part": part})  # type: ignore[attr-defined]
        hit.update(match.rule for match in found)
    return hit


def check_detection(rules: object) -> list[str]:
    """Правила ловят то, ради чего написаны."""
    problems = []
    for name, expected in sorted(MUST_MATCH.items()):
        path = SAMPLES / name
        if not path.exists():
            problems.append(f"{name}: нет файла — сначала `make samples`")
            continue
        hit = matched(rules, path)
        if expected not in hit:
            problems.append(f"{name}: правило {expected} не сработало (сработали: {hit or '—'})")
    return problems


def check_false_positives(rules: object) -> tuple[list[str], int]:
    """Прогон по чистым файлам корпуса. Возвращает (находки, сколько проверено).

    «Чистый» здесь означает метку `none` в датасете — «мы ничего не внедряли»,
    а не «проверено и безобидно». Поэтому разобранные вручную случаи вынесены
    в `corpus/expected.json`: проверка падает на **новых** срабатываниях.
    """
    pdfs = CORPUS / "pdfs"
    if not pdfs.exists():
        return [], 0

    labels = {
        row["output_file"]: row["injection_type"]
        for row in csv.DictReader((CORPUS / "manifest.csv").open())
    }
    expected = {
        name
        for name in json.loads((CORPUS / "expected.json").read_text())
        if not name.startswith("_")
    }

    problems: list[str] = []
    checked = 0
    for path in sorted(pdfs.glob("*.pdf")):
        if labels.get(path.name) != CLEAN_LABEL:
            continue
        checked += 1
        hit = matched(rules, path)
        if hit and path.name not in expected:
            problems.append(f"{path.name}: {', '.join(sorted(hit))}")
    return problems, checked


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--compile-only", action="store_true", help="только компиляция, без прогонов"
    )
    args = parser.parse_args()

    rules = compile_rules()
    if args.compile_only:
        return 0

    missed = check_detection(rules)
    if missed:
        print("\nПРОВАЛ: правила перестали ловить свою синтетику:", file=sys.stderr)
        for line in missed:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"синтетика ловится: {len(MUST_MATCH)}/{len(MUST_MATCH)}")

    false_positives, checked = check_false_positives(rules)
    if not checked:
        # Отдельная ветка, а не тихий успех: разница между «проверено, чисто»
        # и «проверять было нечего» — это разница между выкаткой и её
        # видимостью.
        print("\nкорпуса нет, прогон по чистым файлам ПРОПУЩЕН: `make corpus`")
        return 0

    if false_positives:
        print(f"\nПРОВАЛ: срабатывания на чистых файлах ({len(false_positives)}):", file=sys.stderr)
        for line in false_positives:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nЛибо правило слишком широкое — чинить правило,\n"
            "либо разбор показал верное срабатывание — занести файл\n"
            "в corpus/expected.json с объяснением.",
            file=sys.stderr,
        )
        return 1

    print(f"чистых файлов проверено: {checked}, срабатываний нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
