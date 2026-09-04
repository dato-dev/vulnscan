"""Инструмент настройки `keys.json`, `weights.json`, `policies.json`.

Проверяется не диалог, а три его обещания.

**Оно вообще запускается.** Скрипт, который никто не зовёт из тестов, ломается
молча: `corpus/check.py` пролежал сломанным с переименования пакетов до M7.1, и
всё это время регрессия на ложные срабатывания не выполнялась. Здесь тот же
риск: инструмент импортирует `vscommon`, а его модули двигаются.

**Проверяет загрузчик сервиса, а не сам инструмент.** Своя копия правил
однажды одобрит то, что сервис отвергнет, и разбираться будут по симптому
«ключ есть в файле, но не работает». Поэтому проверяется, что отвергнутое
загрузчиком не остаётся на диске.

**Список вопросов не отстаёт от модели.** Поле, добавленное в `TenantPolicy`,
не спросят — и настроить его через инструмент будет нельзя, причём без единой
ошибки. Об этом отдельный тест.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from vscommon.keys import MIN_SECRET_LEN
from vscommon.models import CdrProfile, FailMode, Severity, TenantPolicy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/configure.py"


def _load_tool() -> Any:
    spec = importlib.util.spec_from_file_location("vs_configure", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["vs_configure"] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop("vs_configure", None)
    return module


@pytest.fixture(scope="module")
def tool() -> Any:
    return _load_tool()


@pytest.fixture()
def files(tool: Any, tmp_path: Path) -> Any:
    return tool.files_at(tmp_path / "config")


GOOD_SECRET = "s" * MIN_SECRET_LEN


# --- скрипт не должен протухать -------------------------------------------


def test_tool_is_importable(tool: Any) -> None:
    assert tool.COMMANDS, "ни одна команда не зарегистрирована"
    assert "check" in tool.COMMANDS


def test_every_command_is_described(tool: Any) -> None:
    """Команда без описания не находится в меню, а значит её нет."""
    for name, command in tool.COMMANDS.items():
        assert command.group, f"{name}: не указана группа"
        assert command.title, f"{name}: не сказано, что команда делает"
        assert callable(command.run)


# --- разбор ввода ---------------------------------------------------------


def test_int_range_is_enforced(tool: Any) -> None:
    parse = tool.p_int(1, 100)
    assert parse(" 80 ") == 80
    for bad in ("0", "101", "восемьдесят", ""):
        with pytest.raises(tool.BadValueError):
            parse(bad)


def test_size_accepts_human_units(tool: Any) -> None:
    """20971520 глазами не читается, а ошибка на порядок в нём — читается плохо."""
    assert tool.p_bytes("20MB") == 20 * 1024**2
    assert tool.p_bytes("20 МБ") == 20 * 1024**2
    assert tool.p_bytes("0") == 0
    with pytest.raises(tool.BadValueError):
        tool.p_bytes("20 попугаев")


def test_short_secret_is_refused_at_input(tool: Any) -> None:
    """Та же граница, что у загрузчика: иначе ключ молча не загрузится."""
    with pytest.raises(tool.BadValueError):
        tool.p_secret("s" * (MIN_SECRET_LEN - 1))
    assert tool.p_secret(GOOD_SECRET) == GOOD_SECRET


def test_origin_refuses_masks_and_open_http(tool: Any) -> None:
    """`*.example.com` превращает захват поддомена в кражу публичного ключа."""
    assert tool.p_origin("https://acme.tld/") == "https://acme.tld"
    assert tool.p_origin("http://localhost:3000") == "http://localhost:3000"
    for bad in ("https://*.acme.tld", "http://acme.tld", "acme.tld", "https://acme.tld/upload"):
        with pytest.raises(tool.BadValueError):
            tool.p_origin(bad)


def test_callback_host_refuses_url(tool: Any) -> None:
    assert tool.p_host("Bot") == "bot"
    with pytest.raises(tool.BadValueError):
        tool.p_host("https://bot/callback")


def test_weight_overrides_parse(tool: Any) -> None:
    assert tool.p_scores("PDF_LAUNCH=90, YARA:high=40") == {"PDF_LAUNCH": 90, "YARA:high": 40}
    for bad in ("PDF_LAUNCH", "pdf_launch=90", "PDF_LAUNCH=900"):
        with pytest.raises(tool.BadValueError):
            tool.p_scores(bad)


# --- запись файлов --------------------------------------------------------


def test_keys_file_is_written_for_owner_only(tool: Any, files: Any) -> None:
    """В keys.json секреты подписи, а не настройки."""
    tool.apply(files.keys, {"k1": {"tenant": "t", "secret": GOOD_SECRET}}, tool.verify_keys)
    assert files.keys.path.stat().st_mode & 0o777 == 0o600


def test_comments_survive_a_change(tool: Any, files: Any) -> None:
    """Ключи с подчёркивания — комментарии; инструмент не имеет права их съесть."""
    files.weights.save({"_": ["пояснение"], "PDF_LAUNCH": {"score": 90, "severity": "critical"}})
    data = files.weights.load()
    data["PDF_OBJSTM"] = {"score": 0, "severity": "info"}
    tool.apply(files.weights, data, tool.verify_weights)

    written = json.loads(files.weights.path.read_text())
    assert written["_"] == ["пояснение"]
    assert set(tool.entries(written)) == {"PDF_LAUNCH", "PDF_OBJSTM"}


def test_rejected_entry_does_not_stay_on_disk(tool: Any, files: Any) -> None:
    """Загрузчик отверг запись — файл возвращается в прежнее состояние.

    Ровно ради этого проверка идёт по записанному файлу, а не по значению в
    памяти: сервис прочтёт файл, а не то, что инструмент думал записать.
    """
    tool.apply(files.keys, {"k1": {"tenant": "t", "secret": GOOD_SECRET}}, tool.verify_keys)
    before = files.keys.path.read_bytes()

    with pytest.raises(tool.BadValueError):
        tool.apply(
            files.keys,
            {"k1": {"tenant": "t", "secret": GOOD_SECRET}, "k2": {"tenant": "t", "secret": "кор"}},
            tool.verify_keys,
        )

    assert files.keys.path.read_bytes() == before


def test_rollback_removes_a_file_that_did_not_exist(tool: Any, files: Any) -> None:
    with pytest.raises(tool.BadValueError):
        tool.apply(files.keys, {"k1": {"tenant": "t", "secret": "кор"}}, tool.verify_keys)
    assert not files.keys.path.exists()


# --- проверка теми же загрузчиками, что у сервиса --------------------------


def test_verify_policies_catches_impossible_threshold(tool: Any, files: Any) -> None:
    files.policies.save({"team": {"block_threshold": 200}})
    problems = tool.verify_policies(files.policies.path)
    assert problems and "team" in problems[0]


def test_verify_weights_catches_unknown_severity(tool: Any, files: Any) -> None:
    files.weights.save({"PDF_LAUNCH": {"score": 90, "severity": "апокалипсис"}})
    problems = tool.verify_weights(files.weights.path)
    assert problems and "severity" in problems[0]


def test_verify_keys_catches_public_admin_key(tool: Any, files: Any) -> None:
    """Публичный ключ администратора — это ключ администратора в HTML."""
    files.keys.save({"k": {"tenant": "t", "secret": GOOD_SECRET, "public": True, "admin": True}})
    assert tool.verify_keys(files.keys.path)


def test_check_reports_public_key_without_origins(tool: Any, files: Any) -> None:
    """Такой ключ не работает нигде, и молчать об этом нельзя."""
    files.keys.save({"site": {"tenant": "t", "secret": GOOD_SECRET, "public": True}})
    assert tool.cmd_check(files) == 1


def test_check_passes_on_a_sane_setup(tool: Any, files: Any) -> None:
    files.keys.save({"k": {"tenant": "team", "secret": GOOD_SECRET}})
    files.policies.save({"team": {"block_threshold": 70, "suspicious_threshold": 25}})
    os.chmod(files.keys.path, 0o600)
    assert tool.cmd_check(files) == 0


def test_check_notices_loose_permissions(tool: Any, files: Any) -> None:
    files.keys.save({"k": {"tenant": "team", "secret": GOOD_SECRET}})
    os.chmod(files.keys.path, 0o644)
    assert tool.cmd_check(files) == 1


def test_check_on_empty_directory_is_not_an_error(tool: Any, files: Any) -> None:
    """Файлов нет — это состояние, а не поломка. Но сказать о нём надо."""
    assert tool.cmd_check(files) == 0


# --- вопросы не должны отставать от модели --------------------------------


def test_policy_questions_cover_the_model(tool: Any) -> None:
    """Поле, добавленное в TenantPolicy, обязано появиться в вопросах.

    Иначе настроить его инструментом нельзя — и узнать об этом неоткуда: ни
    ошибки, ни предупреждения, просто в файле никогда не появится ключ.
    """
    asked = {param.name for param in tool.POLICY_PARAMS}
    model = set(TenantPolicy.model_fields) - {"tenant"}
    assert asked == model, f"вопросы разошлись с моделью: {asked ^ model}"


def test_policy_answers_are_accepted_by_the_model(tool: Any) -> None:
    """Умолчания вопросов складываются в политику, которую примет сервис."""
    payload = {param.name: param.default for param in tool.POLICY_PARAMS}
    policy = TenantPolicy.model_validate({**payload, "tenant": "t"})
    assert policy.fail_mode is FailMode(payload["fail_mode"])
    assert policy.default_profile is CdrProfile(payload["default_profile"])


def test_enum_choices_are_taken_from_the_enums(tool: Any) -> None:
    """Список допустимых значений собирается из перечислений, а не переписан руками."""
    for param in tool.POLICY_PARAMS:
        if param.name == "fail_mode":
            for mode in FailMode:
                assert param.parse(mode.value) == mode.value
        if param.name == "default_profile":
            for profile in CdrProfile:
                assert param.parse(profile.value) == profile.value
    for severity in Severity:
        assert tool.WEIGHT_SEVERITY.parse(severity.value) == severity.value


# --- сам диалог -----------------------------------------------------------


def _answers(tool: Any, monkeypatch: pytest.MonkeyPatch, *values: str) -> None:
    """Подменяет ввод оператора заранее заданными ответами."""
    queue = list(values)
    monkeypatch.setattr(tool, "read_line", lambda _prompt: queue.pop(0))


def test_ask_repeats_until_the_value_is_allowed(tool: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _answers(tool, monkeypatch, "500", "восемьдесят", "80")
    param = next(p for p in tool.POLICY_PARAMS if p.name == "block_threshold")
    assert tool.ask(param) == 80


def test_enter_keeps_the_current_value(tool: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """При правке ответом по умолчанию должно быть настроенное, а не заводское.

    Иначе Enter молча возвращает параметр к умолчанию — и настройка,
    сделанная год назад, исчезает при правке соседнего поля.
    """
    _answers(tool, monkeypatch, "")
    param = next(p for p in tool.POLICY_PARAMS if p.name == "block_threshold")
    assert param.default == 80
    assert tool.ask(param, 45) == 45


def test_dash_clears_a_list(tool: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _answers(tool, monkeypatch, "-")
    assert tool.ask(tool.KEY_CALLBACK_HOSTS, ["bot"]) == []


def test_choose_refuses_an_invalid_new_name(tool: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Тенант с опечаткой не ошибка ни для одного загрузчика: он просто никому
    не применится. Значит проверять имя должен тот, кто его спрашивает."""
    _answers(tool, monkeypatch, "Team Legal", "team-legal")
    assert tool.choose("тенант", [], allow_new=tool.KEY_TENANT.parse) == "team-legal"


def test_added_key_can_actually_sign_a_request(
    tool: Any, files: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сквозная проверка: заведённым ключом подписывается запрос.

    Инструмент, который пишет синтаксически верный файл с ключом, которым
    нельзя подписать, ничем не лучше правки руками.
    """
    from vscommon.keys import KeyRegistry
    from vscommon.signing import sign

    _answers(tool, monkeypatch, "bot-1", "telegram-bot", "нет", "нет", "bot", "нет", "да")
    tool.cmd_keys_add(files)

    entry = json.loads(files.keys.path.read_text())["bot-1"]
    registry = KeyRegistry.load(str(files.keys.path))
    timestamp, signature = sign(entry["secret"], b"body")
    key = registry.resolve("bot-1", b"body", timestamp, signature)

    assert key is not None and key.tenant == "telegram-bot"
    assert key.callback_hosts == ("bot",)


def test_disabled_key_stays_in_the_file(
    tool: Any, files: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Отзыв — не удаление: «отозван» и «не существовал» при разборе разные вещи."""
    files.keys.save({"bot-1": {"tenant": "t", "secret": GOOD_SECRET}})
    _answers(tool, monkeypatch, "bot-1")
    tool.cmd_keys_disable(files)

    written = json.loads(files.keys.path.read_text())
    assert written["bot-1"]["disabled"] is True
    assert _loaded_key(files.keys.path, "bot-1") is None


def _loaded_key(path: Path, key_id: str) -> Any:
    """Что увидит сервис: отозванный ключ загрузчик не отдаёт."""
    from vscommon.keys import KeyRegistry

    return KeyRegistry.load(str(path)).get(key_id)
