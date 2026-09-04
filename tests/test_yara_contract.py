"""M7.1: контракт на YARA-правила. Проверяется до выкатки, а не в бою.

Почему это отдельная забота. Правило, которое не компилируется, воркер не
роняет: `reload_if_changed` пишет `WARNING`, оставляет прежний набор и
продолжает работать. Решение правильное — кривое правило не должно
останавливать проверку файлов, — но у него есть цена: **снаружи это выглядит
как исправная работа**. Файлы проверяются, вердикты выдаются, счётчики растут,
и только новое правило не действует.

Отсюда два уровня проверки, и здесь только первый.

Здесь — структура: теги, описания, имена, отсутствие двойников. `yara-python`
для этого не нужен, а значит проверка идёт в каждом `make test`, включая
машины, где библиотека не собралась (`make venv` падает на ней и ставит
урезанный набор — то есть локально правила не компилировал никто).

Компиляция и прогон по корпусу — второй уровень, `make rules-check`. Он
требует настоящей библиотеки и потому живёт в CI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from vscommon.weights import DEFAULT_WEIGHTS
from worker_app.stages.yara_rules import WEIGHT_TAGS

RULES_DIR = Path(__file__).parent.parent / "rules/yara"

RULE_HEADER = re.compile(
    r"^rule\s+(?P<name>\w+)\s*(?::\s*(?P<tags>[\w\s]+?))?\s*\{",
    re.MULTILINE,
)
NAME_FORMAT = re.compile(r"^[a-z][a-z0-9_]*$")


class Rule:
    __slots__ = ("body", "file", "name", "tags")

    def __init__(self, name: str, tags: list[str], body: str, file: str) -> None:
        self.name = name
        self.tags = tags
        self.body = body
        self.file = file

    @property
    def code(self) -> str:
        """Код признака, который увидит клиент."""
        return f"YARA_{self.name.upper()}"

    def __repr__(self) -> str:
        return f"{self.file}:{self.name}"


def _parse(path: Path) -> list[Rule]:
    """Разбор заголовков правил без `yara-python`.

    Полноценный парсер здесь не нужен и вреден: он повторял бы работу
    компилятора и расходился бы с ним. Нужны только имя, теги и границы тела —
    всё, о чём этот файл спрашивает.
    """
    text = path.read_text()
    matches = list(RULE_HEADER.finditer(text))
    rules = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        rules.append(
            Rule(
                name=match.group("name"),
                tags=(match.group("tags") or "").split(),
                body=text[match.end() : end],
                file=path.name,
            )
        )
    return rules


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    found = [rule for path in sorted(RULES_DIR.glob("*.yar")) for rule in _parse(path)]
    assert found, "правил не найдено — разбор сломан или каталог пуст"
    return found


# --- вес ------------------------------------------------------------------


def test_every_rule_declares_its_weight(rules: list[Rule]) -> None:
    """Ровно один тег веса на правило.

    Без тега правило получает `medium` (`DEFAULT_TAG`), и это самая тихая из
    возможных поломок: опечатка в теге `critical` превращает вес 95 в 35, то
    есть вердикт `malicious` в `suspicious`. Ни ошибки, ни предупреждения —
    файл просто перестаёт блокироваться.

    Отдельной проверки «тегов нет вовсе» здесь нет намеренно: она не падала
    бы ни разу без этой. Тест, который не может провалиться в одиночку, — не
    вторая гарантия, а лишний повод считать набор проверенным.
    """
    for rule in rules:
        weights = [tag for tag in rule.tags if tag in WEIGHT_TAGS]
        assert len(weights) == 1, (
            f"{rule}: ожидается ровно один тег веса из {WEIGHT_TAGS}, "
            f"а объявлено {rule.tags or 'ничего'}"
        )


def test_every_weight_tag_has_a_weight(rules: list[Rule]) -> None:
    """Тег из правил есть в таблице весов.

    Новый тег в правилах и забытая строка в `weights.py` — снова тихий
    `medium`, и снова без единой записи в логе.
    """
    for rule in rules:
        for tag in rule.tags:
            if tag not in WEIGHT_TAGS:
                continue
            assert f"YARA:{tag}" in DEFAULT_WEIGHTS, f"{rule}: нет веса для ключа YARA:{tag}"


def test_weight_tags_and_the_table_agree() -> None:
    """Список тегов стадии и таблица весов описывают одно и то же.

    Разъехавшись, они не ломаются заметно: тег из `WEIGHT_TAGS` без строки в
    таблице даёт запасной вес, строка без тега — недостижимую настройку.
    """
    from_stage = {f"YARA:{tag}" for tag in WEIGHT_TAGS}
    from_table = {key for key in DEFAULT_WEIGHTS if key.startswith("YARA:")}

    assert from_stage == from_table


# --- код признака как публичный контракт ---------------------------------


def test_rule_names_produce_valid_codes(rules: list[Rule]) -> None:
    """Имя правила становится кодом признака, а код — контракт API."""
    for rule in rules:
        assert NAME_FORMAT.fullmatch(rule.name), (
            f"{rule}: имя правила должно быть в нижнем snake_case — "
            f"из него собирается код {rule.code}"
        )


def test_rule_names_are_unique(rules: list[Rule]) -> None:
    """Двойник имени — отказ компиляции всего набора.

    Ценой ошибается не то правило, которое добавили, а все: компилятор
    отвергает набор целиком, воркер остаётся на прежнем, и новых правил в
    работе нет — при исправных вердиктах и чистых метриках.
    """
    seen: dict[str, Rule] = {}
    for rule in rules:
        assert rule.name not in seen, f"{rule} повторяет имя из {seen[rule.name]}"
        seen[rule.name] = rule


def test_every_rule_explains_itself(rules: list[Rule]) -> None:
    """`meta.description` обязателен.

    По коду `YARA_PDF_JS_WITH_AUTOEXEC` дежурный должен понять, что нашли,
    не открывая исходник правила: описание уезжает в `detail` признака.
    """
    for rule in rules:
        assert "description" in rule.body, f"{rule}: нет meta.description"


def test_rules_carry_conditions(rules: list[Rule]) -> None:
    """Правило без `condition` не компилируется.

    Проверка дешёвая и ловит самую частую опечатку до того, как набор уедет в
    образ, где отказ компиляции виден только строчкой `WARNING`.
    """
    for rule in rules:
        assert "condition:" in rule.body, f"{rule}: нет секции condition"


# --- сам шлюз не должен протухать ----------------------------------------


def test_corpus_gate_is_importable() -> None:
    """`corpus/check.py` импортируется.

    Не педантизм. После переименования пакетов воркера (`app` → `worker_app`)
    скрипт перестал запускаться и пролежал сломанным до M7: `make corpus-check`
    падал на импорте, но его никто не звал, а раз никто не звал — никто и не
    видел. Проверка на ложные срабатывания, ради которой всё затевалось, всё
    это время не выполнялась ни разу.
    """
    import importlib.util
    import sys

    path = Path(__file__).parent.parent / "corpus/check.py"
    spec = importlib.util.spec_from_file_location("corpus_check", path)
    assert spec is not None and spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    sys.modules["corpus_check"] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop("corpus_check", None)

    assert hasattr(module, "scan_locally")


# --- сам шлюз выкатки ----------------------------------------------------

WORKFLOW = Path(__file__).parent.parent / ".github/workflows/rules.yml"
MAKEFILE = Path(__file__).parent.parent / "Makefile"


@pytest.fixture(scope="module")
def workflow() -> dict:
    import yaml

    return yaml.safe_load(WORKFLOW.read_text())


def test_workflow_watches_paths_that_exist(workflow: dict) -> None:
    """Фильтр путей не отстаёт от дерева.

    Переименовали файл — конвейер перестаёт запускаться. Не падает, не
    жалуется: просто больше не срабатывает, и правила снова едут в образ
    непроверенными. Это тот же почерк, что и весь M7.
    """
    root = WORKFLOW.parent.parent.parent
    # `on` в YAML — это булево True, а не строка: ключ приходится брать так.
    triggers = workflow.get("on") or workflow.get(True)
    watched = {
        pattern
        for trigger in triggers.values()
        if isinstance(trigger, dict)
        for pattern in trigger.get("paths", [])
    }

    missing = [pattern for pattern in watched if not list(root.glob(pattern.rstrip("*/")))]

    assert not missing, f"конвейер следит за тем, чего нет: {missing}"


def test_workflow_calls_targets_that_exist(workflow: dict) -> None:
    """Цели `make`, которые зовёт конвейер, объявлены в Makefile."""
    targets = {
        line.split(":")[0]
        for line in MAKEFILE.read_text().splitlines()
        if line and not line[0].isspace() and ":" in line
    }
    called = {
        word
        for job in workflow["jobs"].values()
        for step in job["steps"]
        for line in step.get("run", "").splitlines()
        for word in [line.strip().removeprefix("make ").split()[0]]
        if line.strip().startswith("make ")
    }

    assert called, "конвейер не зовёт ни одной цели — проверять нечего"
    assert not called - targets, f"нет таких целей: {sorted(called - targets)}"


def test_the_gate_refuses_to_pass_without_the_library() -> None:
    """Отсутствие `yara-python` — провал, а не пропуск.

    Пропущенный шаг в зелёном конвейере читается как «проверено». Именно так
    выглядела бы выкатка правил, которые никто не компилировал: ровно то
    состояние, в котором проект и жил до M7.1.
    """
    source = (Path(__file__).parent.parent / "rules/check.py").read_text()

    assert "SystemExit(2)" in source
    assert "проверка не выполнялась" in source
