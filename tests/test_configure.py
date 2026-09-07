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


COMPUTED = {
    "tenant": "подставляется по имени записи в файле",
    "delivery_error": (
        "выставляет загрузчик, когда блок delivery описан негодно. Человеку "
        "этого поля задавать нечего: он задаёт сам delivery, а ошибку разбора "
        "сервис обнаруживает сам"
    ),
}
"""Поля политики, которые не спрашивают: их вычисляет сервис, а не оператор."""


def test_policy_questions_cover_the_model(tool: Any) -> None:
    """Поле, добавленное в TenantPolicy, обязано появиться в вопросах.

    Иначе настроить его инструментом нельзя — и узнать об этом неоткуда: ни
    ошибки, ни предупреждения, просто в файле никогда не появится ключ.
    """
    asked = {param.name for param in tool.POLICY_PARAMS}
    model = set(TenantPolicy.model_fields) - set(COMPUTED)

    assert asked == model, f"вопросы разошлись с моделью: {asked ^ model}"


def test_computed_fields_are_really_computed() -> None:
    """Список исключений не должен становиться местом, куда прячут забытое.

    Проверяется, что исключённое поле и правда существует в модели: иначе
    строка переживает своё поле и начинает молча покрывать чужое имя.
    """
    stale = set(COMPUTED) - set(TenantPolicy.model_fields)

    assert not stale, f"в исключениях поля, которого нет в модели: {sorted(stale)}"
    for name, reason in COMPUTED.items():
        assert len(reason) > 20, f"{name}: причина исключения не написана"


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


# --- разграничение приёмников (M14.4) --------------------------------------


def _policies(tmp_path: Any, payload: dict) -> Any:
    from pathlib import Path

    path = Path(tmp_path) / "policies.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def test_destination_without_a_prefix_is_flagged(tool: Any, tmp_path: Any) -> None:
    """Учётной записью без префикса можно писать в весь бакет.

    Формально это годная конфигурация, поэтому загрузчик её принимает.
    Практически префикс на тенанта — единственное, что ограничивает ущерб от
    утечки этой учётки.
    """
    path = _policies(
        tmp_path, {"team-a": {"delivery": {"bucket": "clean", "credentials_id": "drop"}}}
    )

    problems = tool.verify_policies(path)

    assert any("prefix" in problem for problem in problems), problems


def test_two_tenants_in_one_directory_are_flagged(tool: Any, tmp_path: Any) -> None:
    """Документы двух клиентов не должны смешиваться в одном каталоге."""
    same = {"bucket": "clean", "prefix": "vulnscan/", "credentials_id": "drop"}
    path = _policies(tmp_path, {"team-a": {"delivery": same}, "team-b": {"delivery": same}})

    problems = tool.verify_policies(path)

    assert any("смешаются" in problem for problem in problems), problems


def test_separate_prefixes_pass(tool: Any, tmp_path: Any) -> None:
    """Проверка проверки: правильная конфигурация не должна ругаться."""
    path = _policies(
        tmp_path,
        {
            "team-a": {"delivery": {"bucket": "clean", "prefix": "a/", "credentials_id": "d1"}},
            "team-b": {"delivery": {"bucket": "clean", "prefix": "b/", "credentials_id": "d2"}},
        },
    )

    assert tool.verify_policies(path) == []


def test_broken_destination_is_reported_by_the_checker(tool: Any, tmp_path: Any) -> None:
    """Опечатку видно до выката, а не по отсутствию файлов в ящике."""
    path = _policies(
        tmp_path,
        {"team-a": {"delivery": {"buckett": "clean", "credentials_id": "drop"}}},
    )

    problems = tool.verify_policies(path)

    assert any("приёмник" in problem for problem in problems), problems


def test_delivery_secrets_need_owner_only_rights(
    tool: Any, tmp_path: Path, capsys: Any
) -> None:
    """Ключи к чужим хранилищам — такие же секреты, как и ключи подписи.

    Проверка списком, а не строкой на `keys.json`: следующий файл с секретами
    иначе появился бы без неё, и заметить это можно было бы только по чужому
    доступу к бакету.
    """
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    delivery = secrets / "delivery.json"
    delivery.write_text("{}", encoding="utf-8")
    delivery.chmod(0o644)

    files = tool.files_at(tmp_path / "config")
    tool.cmd_check(files)

    assert "delivery.json доступен не только владельцу" in capsys.readouterr().out


def test_correct_rights_are_not_reported(tool: Any, tmp_path: Path, capsys: Any) -> None:
    """Проверка проверки: на правильных правах жалобы быть не должно."""
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    delivery = secrets / "delivery.json"
    delivery.write_text("{}", encoding="utf-8")
    delivery.chmod(0o600)

    tool.cmd_check(tool.files_at(tmp_path / "config"))

    assert "delivery.json" not in capsys.readouterr().out


# --- ссылка на учётные данные разрешается (M14.8) --------------------------


def _with_delivery(tmp_path: Path, credentials_id: str = "yandex-drop") -> Any:
    config = tmp_path / "config"
    config.mkdir(exist_ok=True)
    (config / "policies.json").write_text(
        json.dumps(
            {
                "team-a": {
                    "delivery": {
                        "bucket": "clean",
                        "prefix": "vulnscan/team-a/",
                        "credentials_id": credentials_id,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return config


def test_missing_credentials_file_is_reported(tool: Any, tmp_path: Path, capsys: Any) -> None:
    """Приёмник настроен, а учёток нет — доставки не будет ни одной.

    Узнать об этом иначе можно только по пустому ящику у клиента: сервис
    работает, вердикты выдаёт, файлы никуда не едут.
    """
    tool.cmd_check(tool.files_at(_with_delivery(tmp_path)))

    assert "учётных данных нет" in capsys.readouterr().out


def test_unknown_credentials_id_is_reported(tool: Any, tmp_path: Path, capsys: Any) -> None:
    """Опечатка в ссылке ловится до выката, а не по записям dead-letter."""
    config = _with_delivery(tmp_path, credentials_id="yandex-drp")
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    (secrets / "delivery.json").write_text(
        json.dumps({"yandex-drop": {"access_key": "a", "secret_key": "s" * 16}}),
        encoding="utf-8",
    )

    tool.cmd_check(tool.files_at(config))

    assert "нет записи «yandex-drp»" in capsys.readouterr().out


def test_resolvable_reference_is_quiet(tool: Any, tmp_path: Path, capsys: Any) -> None:
    """Проверка проверки: на верной ссылке жалобы быть не должно."""
    config = _with_delivery(tmp_path)
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    delivery = secrets / "delivery.json"
    delivery.write_text(
        json.dumps({"yandex-drop": {"access_key": "a", "secret_key": "s" * 16}}),
        encoding="utf-8",
    )
    delivery.chmod(0o600)

    tool.cmd_check(tool.files_at(config))

    assert "delivery" not in capsys.readouterr().out


# --- политика по тенанту, а не по key_id -----------------------------------


def test_policy_named_after_a_key_id_is_an_error(
    tool: Any, tmp_path: Path, capsys: Any
) -> None:
    """Имя политики совпало с идентификатором ключа — она не применится никогда.

    Путаница естественная: `KEY_ID` лежит в `.env`, встречается в логах и в
    заголовке запроса, а тенант виден только внутри `keys.json`. При этом
    ошибка молчит — сервис работает, вердикты выдаёт, настройка не действует.
    Именно так настроенная доставка не выгрузила ни одного файла.
    """
    config = tmp_path / "config"
    config.mkdir()
    keys = config / "keys.json"
    keys.write_text(
        json.dumps({"telegram-bot-1": {"tenant": "telegram-bot", "secret": GOOD_SECRET}}),
        encoding="utf-8",
    )
    # Права выставляем сразу: иначе ненулевой код возврата пришёл бы от
    # проверки прав, и тест проходил бы, даже если проверку тенанта убрать.
    keys.chmod(0o600)
    (config / "policies.json").write_text(
        json.dumps({"telegram-bot-1": {"block_threshold": 50}}), encoding="utf-8"
    )

    code = tool.cmd_check(tool.files_at(config))
    printed = capsys.readouterr().out

    assert code != 0, "это ошибка, а не замечание: запись не применится никогда"
    assert "названа по идентификатору ключа" in printed
    assert "«telegram-bot»" in printed, "надо назвать верное имя, а не только сказать «не так»"


def test_policy_for_a_tenant_without_keys_is_only_a_note(
    tool: Any, tmp_path: Path, capsys: Any
) -> None:
    """Тенант без ключей — не ошибка: ключ могли ещё не выпустить.

    Разделение существенное: если считать ошибкой и это, вывод перестанут
    читать, и настоящая находка утонет вместе с остальным.
    """
    config = tmp_path / "config"
    config.mkdir()
    keys = config / "keys.json"
    keys.write_text(
        json.dumps({"k1": {"tenant": "team-a", "secret": GOOD_SECRET}}), encoding="utf-8"
    )
    keys.chmod(0o600)
    (config / "policies.json").write_text(
        json.dumps({"team-b": {"block_threshold": 50}}), encoding="utf-8"
    )

    code = tool.cmd_check(tool.files_at(config))

    assert code == 0
    assert "ключей этого тенанта нет" in capsys.readouterr().out


def test_template_without_a_unique_part_is_noted(tool: Any, tmp_path: Path, capsys: Any) -> None:
    """Два документа с одним именем затрут друг друга.

    Замечание, а не ошибка: в бакете может быть включено версионирование, и
    тогда перезапись документ не теряет. Но по умолчанию теряет — молча, и
    обнаруживается это, когда файл ищут и не находят.
    """
    config = tmp_path / "config"
    config.mkdir()
    keys = config / "keys.json"
    keys.write_text(
        json.dumps({"k": {"tenant": "team-a", "secret": GOOD_SECRET}}), encoding="utf-8"
    )
    keys.chmod(0o600)
    (config / "policies.json").write_text(
        json.dumps(
            {
                "team-a": {
                    "delivery": {
                        "bucket": "b",
                        "prefix": "p/",
                        "credentials_id": "c",
                        "key_template": "{filename}-Проверено-{verdict}{ext}",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    code = tool.cmd_check(tool.files_at(config))
    printed = capsys.readouterr().out

    assert "затрут друг друга" in printed
    assert code != 0, "учёток нет — это отдельная ошибка, замечание её не заменяет"


def test_template_with_scan_id_is_quiet(tool: Any, tmp_path: Path, capsys: Any) -> None:
    """Проверка проверки: с уникальной частью замечания быть не должно."""
    config = tmp_path / "config"
    config.mkdir()
    (config / "policies.json").write_text(
        json.dumps(
            {
                "team-a": {
                    "delivery": {
                        "bucket": "b",
                        "prefix": "p/",
                        "credentials_id": "c",
                        "key_template": "{filename}-{scan_id}{ext}",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    tool.cmd_check(tool.files_at(config))

    assert "затрут друг друга" not in capsys.readouterr().out


# --- подписанный запрос к служебным ручкам ---------------------------------


@pytest.fixture()
def ask(tool: Any) -> Any:
    """Модуль `deploy/vsask.py` — как его запускает оператор."""
    import importlib.util
    from pathlib import Path as _Path

    path = _Path(__file__).parent.parent / "deploy/vsask.py"
    spec = importlib.util.spec_from_file_location("vsask", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_signature_matches_what_the_service_checks(ask: Any) -> None:
    """Подпись считается функциями сервиса, а не своей копией.

    Копия разошлась бы молча: запросы начали бы отвергаться, а причина в ответ
    не уходит — сервис намеренно не сообщает, ключа нет или подпись не сошлась.
    """
    from vscommon.keys import AccessKey, KeyRegistry
    from vscommon.signing import sign

    secret = "s" * 40
    registry = KeyRegistry(
        {"admin-1": AccessKey(key_id="admin-1", tenant="root", secret=secret, admin=True)}
    )
    timestamp, signature = sign(secret, b"")

    key, _check = registry.check("admin-1", b"", timestamp, signature)

    assert key is not None and key.admin
    assert "from vscommon.signing import" in (ask.__doc__ or "") or hasattr(ask, "sign")


def test_missing_admin_key_says_what_to_do(ask: Any) -> None:
    """Отказ должен вести к действию, а не просто сообщать о нём.

    Обычным ключом служебные ручки отвечают `404` — «не найдено», — и без
    подсказки оператор ищет несуществующую ручку вместо того, чтобы завести
    ключ.
    """
    with pytest.raises(SystemExit) as exc:
        ask.pick_key({"k1": {"tenant": "team-a", "secret": "s" * 40}}, None)

    assert "configure.py keys add" in str(exc.value)


def test_several_admin_keys_are_not_guessed(ask: Any) -> None:
    """Угадывать нельзя: запрос уйдёт от чужого имени.

    В аудите служебных ручек остаётся, кто спрашивал; выбранный за оператора
    ключ сделал бы эту запись ложной.
    """
    keys = {
        "a1": {"secret": "s" * 40, "admin": True},
        "a2": {"secret": "z" * 40, "admin": True},
    }

    with pytest.raises(SystemExit) as exc:
        ask.pick_key(keys, None)

    assert "--key" in str(exc.value)


def test_disabled_admin_key_is_not_picked(ask: Any) -> None:
    """Отозванный ключ сервис не примет — выбирать его незачем."""
    keys = {"a1": {"secret": "s" * 40, "admin": True, "disabled": True}}

    with pytest.raises(SystemExit) as exc:
        ask.pick_key(keys, None)

    assert "административного ключа нет" in str(exc.value)


def test_old_python_says_so_instead_of_blaming_the_package() -> None:
    """Сообщение об ошибке обязано называть настоящую причину.

    Системный `python3` часто старый. Импорт из vscommon падает изнутри, и
    прежний текст приписывал это отсутствию пакета — оператор шёл искать
    несуществующую проблему вместо того, чтобы взять другой интерпретатор.
    """
    from pathlib import Path as _Path

    for name in ("configure.py", "vsask.py"):
        source = (_Path(__file__).parent.parent / "deploy" / name).read_text()
        guard = source.index("sys.version_info < (3, 12)")
        imports = source.index("from vscommon")

        assert guard < imports, f"{name}: версия проверяется после импорта — сообщение соврёт"
        assert ".venv/bin/python" in source, f"{name}: не сказано, чем запускать"
