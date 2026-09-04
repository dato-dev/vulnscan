"""M7.2: канареечная выкатка правил и откат без выката.

Два механизма, и оба существуют ради одного свойства: **правило не должно
уметь навредить**.

Выключатель отвечает на «правило уже в бою и ошибается». До сих пор лечение
требовало правки смонтированных файлов и раскатки; теперь имя правила кладётся
в Redis, и воркеры перестают учитывать его совпадения на ближайшей
перезагрузке.

Канарейка отвечает на «правило ещё не в бою, и неизвестно, стоит ли».
Набор-кандидат прогоняется рядом с действующим и не влияет ни на вердикт, ни
на `engines`, ни на кэш. Набор, способный изменить вердикт, — это не
канарейка, а выкатка на долю трафика; здесь проверяется, что он таким не
стал.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fakeredis import aioredis
from fastapi import HTTPException

from vscommon import rules_control as control
from vscommon.canary import CanaryLedger
from vscommon.keys import AccessKey
from vscommon.models import ObjectRef, ScanJob
from vscommon.rules_control import DisabledRule, RulesControl
from vscommon.weights import WeightTable
from worker_app.stages.base import ScanContext
from worker_app.stages.yara_rules import YaraStage

SHA = "a" * 64


@pytest.fixture()
async def redis():
    client = aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


def _entry(rule: str = "pdf_launch_action") -> DisabledRule:
    return DisabledRule(rule=rule, reason="массовые ложные срабатывания", author="дежурный")


class _Match:
    """То немногое из `yara.Match`, чем пользуется стадия."""

    def __init__(self, rule: str, tags: list[str] | None = None) -> None:
        self.rule = rule
        self.tags = tags or ["high"]


class _Rules:
    """Заглушка скомпилированных правил: yara-python есть не везде."""

    def __init__(self, *rules: str) -> None:
        self._rules = rules

    def match(self, path: str, timeout: int = 0) -> list[_Match]:
        return [_Match(rule) for rule in self._rules]


def _context(tmp_path: Path) -> ScanContext:
    target = tmp_path / "doc.pdf"
    target.write_bytes(b"%PDF-1.4\n")
    job = ScanJob(
        scan_id="s1",
        sha256=SHA,
        source=ObjectRef(bucket="b", key="k"),
        size=target.stat().st_size,
        filename_ext=".pdf",
    )
    return ScanContext(job=job, path=target, weights=WeightTable())


def _stage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *rules: str) -> YaraStage:
    from worker_app.stages import yara_rules as module

    directory = tmp_path / "rules"
    directory.mkdir(exist_ok=True)
    (directory / "r.yar").write_text("rule x { condition: true }")
    monkeypatch.setattr(module.settings, "yara_rules_dir", str(directory))
    monkeypatch.setattr(module.settings, "yara_enabled", True)
    monkeypatch.setattr(module.settings, "yara_candidate_dir", "")
    return YaraStage(rules=_Rules(*rules))


# --- выключатель: запись ---------------------------------------------------


async def test_reason_and_author_are_required() -> None:
    """Механизм ослабления проверки без объяснения не применяют.

    Через полгода должно быть понятно, кто и зачем выключил детект, — иначе
    правило остаётся выключенным просто потому, что никто не решается
    включить.
    """
    with pytest.raises(ValueError):
        DisabledRule(rule="x", reason="ок", author="дежурный")
    with pytest.raises(ValueError):
        DisabledRule(rule="x", reason="массовые ложные срабатывания", author="")


async def test_disable_and_enable_round_trip(redis) -> None:
    rules = RulesControl(redis)
    await rules.disable(_entry())

    assert await rules.disabled() == frozenset({"pdf_launch_action"})

    assert await rules.enable("pdf_launch_action", "дежурный")
    assert await rules.disabled() == frozenset()


async def test_enabling_a_working_rule_reports_false(redis) -> None:
    assert not await RulesControl(redis).enable("нет такого", "дежурный")


async def test_entry_keeps_who_and_why(redis) -> None:
    rules = RulesControl(redis)
    await rules.disable(_entry())

    (stored,) = await rules.entries()

    assert stored.author == "дежурный"
    assert stored.reason == "массовые ложные срабатывания"
    assert stored.days == 0


def test_disabled_at_is_not_taken_from_the_request() -> None:
    """Давность выключения проставляет сервер: по ней записи и пересматривают."""
    entry = control.entry_from_request(
        {
            "rule": "x",
            "reason": "массовые ложные срабатывания",
            "author": "дежурный",
            "disabled_at": 0,
        }
    )

    assert entry.disabled_at > 0


# --- выключатель: действие на стадии --------------------------------------


def test_disabled_rule_gives_no_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Совпадение выключенного правила не становится признаком."""
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action", "pdf_js_with_autoexec")
    stage.apply_control(frozenset({"pdf_launch_action"}))
    ctx = _context(tmp_path)

    stage.run(ctx)

    assert [f.code for f in ctx.findings] == ["YARA_PDF_JS_WITH_AUTOEXEC"]


def test_suppression_is_visible_in_engines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Отсечённые совпадения видны в ответе и в истории.

    Иначе разбор старого скана не объяснить: правило было, признака нет, и
    непонятно, промолчало оно или его выключили.
    """
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    stage.apply_control(frozenset({"pdf_launch_action"}))
    ctx = _context(tmp_path)

    stage.run(ctx)

    assert ctx.engines["yara"]["suppressed"] == 1
    assert ctx.engines["yara"]["matches"] == 0


def test_disabling_changes_the_rules_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Отпечаток входит в ключ структурного кэша — и обязан меняться.

    Иначе выключение правила не обесценило бы кэш: файл, проверенный час
    назад, продолжал бы отдаваться с признаком от правила, которого больше
    нет в работе. Ровно тот способ, которым в этом проекте уже несколько раз
    протухали кэшированные факты.
    """
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    before = stage.rules_fingerprint

    stage.apply_control(frozenset({"pdf_launch_action"}))

    assert stage.rules_fingerprint != before


def test_fingerprint_returns_after_enabling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Включили обратно — отпечаток тот же, что был. Кэш снова годен."""
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    before = stage.rules_fingerprint

    stage.apply_control(frozenset({"pdf_launch_action"}))
    stage.apply_control(frozenset())

    assert stage.rules_fingerprint == before


def test_fingerprint_does_not_depend_on_the_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Множество, а не список: порядок не должен обесценивать кэш зря."""
    assert control.fingerprint(frozenset({"a", "b"})) == control.fingerprint(frozenset({"b", "a"}))


def test_applying_the_same_list_is_not_a_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Иначе каждая перезагрузка сообщала бы о смене конфигурации."""
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")

    assert stage.apply_control(frozenset({"pdf_launch_action"}))
    assert not stage.apply_control(frozenset({"pdf_launch_action"}))


# --- канарейка -------------------------------------------------------------


def _with_candidate(stage: YaraStage, *rules: str) -> None:
    """Подставляет скомпилированного кандидата, минуя yara-python."""
    stage._candidate = _Rules(*rules)


def test_candidate_never_becomes_a_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Главное свойство канарейки: она не может сделать хуже.

    Набор, способный изменить вердикт, — это не канарейка, а выкатка на долю
    трафика. Тогда сырое правило блокировало бы настоящие документы, то есть
    механизм, заведённый ради безопасной проверки, сам стал бы источником
    аварии.
    """
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    _with_candidate(stage, "pdf_launch_action", "новое_широкое_правило")
    ctx = _context(tmp_path)

    stage.run(ctx)

    assert [f.code for f in ctx.findings] == ["YARA_PDF_LAUNCH_ACTION"]


def test_candidate_does_not_touch_engines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`engines` попадает в кэш и в историю: кандидату там места нет."""
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    _with_candidate(stage, "новое_широкое_правило")
    ctx = _context(tmp_path)

    stage.run(ctx)

    assert ctx.engines["yara"] == {"status": "ok", "matches": 1}


def test_candidate_is_not_part_of_the_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Правка кандидата не должна обесценивать структурный кэш.

    Кандидата правят часто — ради этого он и заведён. Входи он в отпечаток,
    каждая правка выбрасывала бы все сохранённые признаки, и выкатка правил
    стоила бы полного перепрогона потока.
    """
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    before = stage.rules_fingerprint

    _with_candidate(stage, "новое_широкое_правило")

    assert stage.rules_fingerprint == before


def test_disagreement_reaches_the_observer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Расхождение уходит наблюдателю с обеими сторонами.

    Одной стороны мало: лишнее у кандидата — будущие ложные срабатывания,
    пропавшее — потерянный детект, и решения по ним разные.
    """
    stage = _stage(tmp_path, monkeypatch, "старое")
    _with_candidate(stage, "новое")
    seen: list[tuple[str, frozenset[str], frozenset[str]]] = []
    stage.observe_with(lambda sha, active, candidate: seen.append((sha, active, candidate)))

    stage.run(_context(tmp_path))

    assert seen == [(SHA, frozenset({"старое"}), frozenset({"новое"}))]


def test_agreement_is_not_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Совпадения считают метрики. Журнал хранит то, что надо разбирать."""
    stage = _stage(tmp_path, monkeypatch, "одно_и_то_же")
    _with_candidate(stage, "одно_и_то_же")
    seen = []
    stage.observe_with(lambda *args: seen.append(args))

    stage.run(_context(tmp_path))

    assert seen == []


def test_broken_candidate_does_not_break_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Что бы кандидат ни сделал, проверка файла уже состоялась.

    Кандидат по определению сырой. Уронить им стадию значило бы получить
    `STAGE_FAILED` и подозрительный вердикт на исправном документе — то есть
    ровно ту аварию, ради предотвращения которой канарейку и заводили.
    """

    class _Exploding:
        def match(self, path: str, timeout: int = 0) -> list[_Match]:
            raise RuntimeError("кандидат сломан")

    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    stage._candidate = _Exploding()
    ctx = _context(tmp_path)

    stage.run(ctx)

    assert [f.code for f in ctx.findings] == ["YARA_PDF_LAUNCH_ACTION"]


def test_disabled_rules_apply_to_the_active_set_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сравнение идёт с тем, что реально повлияло на вердикт.

    Действующая сторона берётся ПОСЛЕ отсева выключенных правил: расхождение
    должно означать «результат был бы другим», а не «наборы описаны разными
    словами».

    Кандидата выключатель при этом не касается, и это намеренно. Правило
    выключают, потому что оно ошибается, а чинят — в кандидате: отсеки мы его
    и там, исправленная версия не показалась бы в отчёте вовсе, то есть
    проверить починку было бы нечем.
    """
    stage = _stage(tmp_path, monkeypatch, "выключенное", "рабочее")
    stage.apply_control(frozenset({"выключенное"}))
    _with_candidate(stage, "рабочее")
    seen = []
    stage.observe_with(lambda *args: seen.append(args))

    stage.run(_context(tmp_path))

    assert seen == [], "кандидат и действующий набор согласны: расхождения нет"


# --- журнал расхождений ----------------------------------------------------


async def test_ledger_separates_the_two_sides(redis) -> None:
    ledger = CanaryLedger(redis)
    await ledger.record(SHA, frozenset({"старое"}), frozenset({"старое", "новое"}))
    await ledger.record("b" * 64, frozenset({"старое"}), frozenset())

    report = await ledger.report()

    assert report.disagreements == 2
    assert dict(report.candidate_only) == {"новое": 1}
    assert dict(report.active_only) == {"старое": 1}


async def test_ledger_keeps_no_file_content(redis) -> None:
    """В журнале только усечённый хэш: исходник ищется в карантине."""
    await CanaryLedger(redis).record(SHA, frozenset(), frozenset({"новое"}))

    (sample,) = (await CanaryLedger(redis).report()).samples

    assert sample.startswith("a" * 12 + " ")
    assert len(sample.split()[0]) == 12


async def test_reset_clears_the_observation(redis) -> None:
    """Смена кандидата обнуляет наблюдение.

    Иначе отчёт складывал бы расхождения двух разных наборов и отвечал бы на
    вопрос, которого никто не задавал.
    """
    ledger = CanaryLedger(redis)
    await ledger.record(SHA, frozenset(), frozenset({"новое"}))

    await ledger.reset()

    assert (await ledger.report()).disagreements == 0


# --- права: выключать правила может только администратор -------------------


def _request(state) -> SimpleNamespace:
    request = SimpleNamespace()
    request.app = SimpleNamespace(state=SimpleNamespace(vs=state))
    request.state = SimpleNamespace(access_key=AccessKey(key_id="k", tenant="t", secret="s" * 32))
    request.url = SimpleNamespace(path="/v1/ops/rules/disabled")
    return request


async def test_tenant_cannot_disable_a_rule(redis) -> None:
    """Тенант выключил бы детект себе, а платит за это не он.

    Если правило ошибается на потоке одного клиента, лечится это весами или
    записью в списке доверенных — тем, что действует на него одного.
    """
    from gateway_app.routes.ops import disable_rule

    state = SimpleNamespace(rule_control=RulesControl(redis))
    body = json.dumps(
        {"rule": "pdf_launch_action", "reason": "мешает нам", "author": "клиент"}
    ).encode()

    with pytest.raises(HTTPException) as exc:
        await disable_rule(_request(state), body=body, scope="team-a")

    assert exc.value.status_code == 404
    assert await RulesControl(redis).disabled() == frozenset()


async def test_admin_can_disable_a_rule(redis) -> None:
    from gateway_app.routes.ops import disable_rule

    state = SimpleNamespace(rule_control=RulesControl(redis))
    body = json.dumps(
        {"rule": "pdf_launch_action", "reason": "массовые ложные срабатывания", "author": "админ"}
    ).encode()

    stored = await disable_rule(_request(state), body=body, scope=None)

    assert stored.rule == "pdf_launch_action"
    assert await RulesControl(redis).disabled() == frozenset({"pdf_launch_action"})


async def test_tenant_cannot_read_the_canary_report(redis) -> None:
    """В отчёте усечённые хэши со всего потока установки."""
    from gateway_app.routes.ops import canary_report

    state = SimpleNamespace(canary=CanaryLedger(redis))

    with pytest.raises(HTTPException) as exc:
        await canary_report(_request(state), scope="team-a")

    assert exc.value.status_code == 404


def test_configured_but_empty_candidate_is_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Каталог кандидата задан, а правил в нём нет — это WARNING.

    Снаружи молчание здесь неотличимо от работающей канарейки, которая не
    нашла расхождений, то есть от «кандидат хорош, выкатывай». А причина
    бывает скучной: воркер собран `read_only`, наружу смонтирован только
    `./config`, и путь, указанный мимо него, внутри контейнера просто не
    существует.
    """
    from worker_app.stages import yara_rules as module

    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")
    monkeypatch.setattr(module.settings, "yara_candidate_dir", str(tmp_path / "нет-такого"))

    with caplog.at_level("WARNING"):
        assert stage._compile_candidate() is None

    assert "канарейка настроена" in caplog.text


def test_no_candidate_dir_says_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Канарейки нет — обычное состояние, и жаловаться не на что.

    Иначе предупреждение шло бы у каждой установки постоянно и перестало бы
    что-либо значить ровно к тому моменту, когда понадобится.
    """
    stage = _stage(tmp_path, monkeypatch, "pdf_launch_action")

    with caplog.at_level("WARNING"):
        assert stage._compile_candidate() is None

    assert caplog.text == ""
