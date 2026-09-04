"""M12.7: фрейм и загрузчик.

Виджет держится на одном разделении: наш код выполняется в НАШЕМ документе, а
на странице сайта живёт только обвязка, создающая фрейм. Здесь проверяются обе
половины — серверная (кому отдаётся фрейм и с какими заголовками) и то, что
код на чужой странице действительно почти ничего не делает.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway_app.routes import widget
from vscommon.keys import AccessKey, KeyRegistry

SITE = "https://acme.tld"
ASSETS = Path(widget.__file__).parent.parent / "widget"


def _registry(
    origins: tuple[str, ...] = (SITE,), public: bool = True, disabled: bool = False
) -> KeyRegistry:
    key = AccessKey(
        key_id="acme-public",
        tenant="acme",
        secret="p" * 32,
        public=public,
        origins=origins,
        disabled=disabled,
    )
    return KeyRegistry({key.key_id: key})


def _client(keys: KeyRegistry | None = None, on_unavailable: str = "block") -> TestClient:
    from vscommon.models import TenantPolicy
    from vscommon.policy import PolicyRegistry

    policy = TenantPolicy(widget_on_unavailable=on_unavailable)
    app = FastAPI()
    from fakeredis import aioredis

    from vscommon.ownership import Ownership
    from vscommon.queue import ResultChannel
    from vscommon.tickets import StatusTicketStore

    redis = aioredis.FakeRedis(decode_responses=True)
    app.state.vs = SimpleNamespace(
        keys=keys or _registry(),
        policies=PolicyRegistry(default=policy, overrides={}),
        status_tickets=StatusTicketStore(redis),
        ownership=Ownership(redis, ttl_s=3600),
        results=ResultChannel(redis),
    )
    app.include_router(widget.router)
    return TestClient(app)


# --- кому отдаётся фрейм -------------------------------------------------


def test_frame_is_served_for_a_valid_site_key() -> None:
    response = _client().get("/widget/v1/frame", params={"key": "acme-public", "origin": SITE})

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_frame_ancestors_limit_embedding_to_the_site() -> None:
    """`frame-ancestors` перечисляет ровно origin ключа.

    Это главная защита от встраивания на чужую страницу, и важно, что
    исполняет её браузер: параметры запроса ставит тот, кто нас встраивает, а
    заголовок — мы.
    """
    response = _client().get("/widget/v1/frame", params={"key": "acme-public"})
    policy = response.headers["Content-Security-Policy"]

    assert f"frame-ancestors {SITE}" in policy
    assert "*" not in policy.split("frame-ancestors")[1].split(";")[0]


def test_frame_is_not_served_for_unknown_key() -> None:
    """Негодный ключ — `404`, а не подсказка.

    Отвечать «такого ключа нет» и «ключ не публичный» по-разному значит
    помогать перебирать.
    """
    response = _client().get("/widget/v1/frame", params={"key": "нет-такого"})

    assert response.status_code == 404


def test_frame_is_not_served_for_secret_key() -> None:
    """Секретным ключом фрейм не получить.

    Иначе идентификатор секретного ключа оказался бы в разметке страницы —
    ровно то, ради предотвращения чего затевалось разделение ключей.
    """
    response = _client(_registry(public=False)).get(
        "/widget/v1/frame", params={"key": "acme-public"}
    )

    assert response.status_code == 404


def test_frame_is_not_served_for_disabled_key() -> None:
    """Отзыв ключа выключает виджет сразу."""
    response = _client(_registry(disabled=True)).get(
        "/widget/v1/frame", params={"key": "acme-public"}
    )

    assert response.status_code == 404


def test_frame_is_not_served_for_key_without_origins() -> None:
    """Ключ без списка origin не даёт фрейма.

    `frame-ancestors` с пустым списком означал бы «встраивать нельзя никому»,
    и виджет молча не работал бы. Лучше честный отказ на выдаче.
    """
    response = _client(_registry(origins=())).get(
        "/widget/v1/frame", params={"key": "acme-public"}
    )

    assert response.status_code == 404


def test_frame_is_not_cached_publicly() -> None:
    """Кэш только приватный: документ зависит от ключа.

    Общий кэш отдал бы фрейм одного сайта другому вместе с его списком origin.
    """
    response = _client().get("/widget/v1/frame", params={"key": "acme-public"})

    assert "private" in response.headers["Cache-Control"]


def test_loader_is_public_and_cacheable() -> None:
    """Загрузчик отдаётся всем: секретного в нём нет.

    И знать, кому его отдавать, на этом этапе нельзя — ключ появляется только
    в разметке страницы, которую мы не видим.
    """
    response = _client().get("/widget/v1/loader.js")

    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "public" in response.headers["Cache-Control"]


# --- что делает код на чужой странице ------------------------------------


def _loader() -> str:
    return (ASSETS / "loader.js").read_text()


def _frame() -> str:
    return (ASSETS / "frame.html").read_text()


def test_loader_checks_both_origin_and_source() -> None:
    """Обе проверки входящего сообщения на месте.

    Origin — потому что сообщение может прислать любой фрейм на странице,
    включая рекламный. Источник — потому что origin совпадёт и у второго
    нашего фрейма, если на странице две формы.
    """
    source = _loader()

    assert "event.origin !== WIDGET_ORIGIN" in source
    assert "event.source !== frame.contentWindow" in source


def test_frame_never_posts_to_wildcard() -> None:
    """Сообщения уходят конкретному origin, не `*`.

    Со звёздочкой их прочитал бы любой фрейм, оказавшийся в цепочке.
    """
    assert 'postMessage(Object.assign({ source: "vulnscan" }, message), parentOrigin)' in _frame()
    assert '"*"' not in _frame().split("function tell")[1].split("}")[0]


def test_ticket_never_leaves_the_frame() -> None:
    """Талон не уходит в родительское окно.

    Талон — предмет для загрузки файла. Отдать его на страницу значит отдать
    возможность грузить файлы от имени сайта, и вся аккуратность с ключами
    обесценилась бы одной строкой.
    """
    frame = _frame()
    posted = re.findall(r"tell\(\{([^}]*)\}", frame)

    assert posted, "не нашлось ни одного сообщения наружу — проверка бессмысленна"
    for message in posted:
        assert "ticket" not in message, f"талон уходит наружу: {message}"
        assert "token" not in message, f"талон уходит наружу: {message}"


def test_loader_clears_the_field_when_not_checked() -> None:
    """Заблокировано или не проверено — скрытое поле пустое.

    Пустое значение на сервере сайта означает «вложения нет». Это безопасное
    состояние: непроверенный файл не должен выглядеть как проверенный.
    """
    source = _loader()

    assert 'data.type === "checked" || data.type === "pending"' in source
    assert 'field.value = ""' in source


def test_loader_does_not_read_the_file() -> None:
    """Загрузчик не прикасается к файлу.

    Весь смысл фрейма в том, что байты идут от посетителя прямо к нам, минуя
    страницу сайта. Появление здесь чтения файла означало бы, что мы вернулись
    к варианту «наш скрипт в чужой странице» и потеряли главное.
    """
    source = _loader()

    for forbidden in ("FileReader", "files[0]", "FormData", "fetch("):
        assert forbidden not in source, f"загрузчик работает с файлом: {forbidden}"


# --- контракт и версия (M12.8) -------------------------------------------


def test_message_types_are_pinned() -> None:
    """Набор сообщений зафиксирован явно.

    Список продублирован здесь намеренно, и это не дублирование ради
    дублирования: правка контракта должна требовать правки теста, то есть
    остановки и ответа на вопрос «а это точно совместимо?».

    Добавить тип — совместимо: страница, которая его не знает, не среагирует.
    Убрать или переименовать — ломающее, и тогда нужен `/widget/v2/`.
    """
    from gateway_app.widget.contract import MESSAGE_TYPES

    assert {
        "ready",
        "busy",
        "checked",
        "pending",
        "blocked",
        "unchecked",
    } == MESSAGE_TYPES


def test_frame_sends_only_declared_types() -> None:
    """Фрейм не шлёт ничего сверх контракта.

    Незаявленный тип не сломает страницу, но и не сработает: обработчик на
    стороне сайта написан по документации, а не по нашему коду.
    """
    from gateway_app.widget.contract import MESSAGE_TYPES

    sent = set(re.findall(r'type:\s*"([a-z]+)"', _frame()))

    assert sent, "во фрейме не нашлось ни одного сообщения — проверка бессмысленна"
    assert sent <= MESSAGE_TYPES, f"фрейм шлёт незаявленное: {sorted(sent - MESSAGE_TYPES)}"


def test_declared_types_are_actually_sent() -> None:
    """И наоборот: заявленный тип действительно отправляется.

    Тип в контракте, которого нет в коде, — обещание, которого никто не
    выполняет. Интегратор напишет под него обработчик и будет ждать вечно.
    """
    from gateway_app.widget.contract import MESSAGE_TYPES

    sent = set(re.findall(r'type:\s*"([a-z]+)"', _frame()))

    assert sent >= MESSAGE_TYPES, f"объявлено, но не шлётся: {sorted(MESSAGE_TYPES - sent)}"


def test_loader_fills_the_field_for_exactly_the_declared_types() -> None:
    """Загрузчик заполняет поле ровно при тех типах, что названы в контракте.

    Расхождение здесь самое неприятное из возможных: фрейм сообщил «проверено»,
    загрузчик тип не узнал, поле осталось пустым — и форма уходит без вложения,
    хотя посетитель его приложил. Ошибки нигде нет, жалоба приходит от людей.
    """
    from gateway_app.widget.contract import TYPES_WITH_SCAN_ID

    condition = _loader().split("if (data.type ===")[1].split(") {")[0]
    handled = set(re.findall(r'"([a-z]+)"', condition))

    assert handled == set(TYPES_WITH_SCAN_ID)


def test_default_field_name_matches_the_loader() -> None:
    """Имя скрытого поля в контракте и в коде одно.

    Его читает бэкенд сайта. Разошлось — поле приходит под другим именем, и
    сервер видит отправку без вложения.
    """
    from gateway_app.widget.contract import DEFAULT_FIELD, HOST_ATTRIBUTE

    assert f'"{DEFAULT_FIELD}"' in _loader()
    assert f'"{HOST_ATTRIBUTE}"' in _loader()


def test_version_is_in_the_path_not_a_parameter() -> None:
    """Версия стоит в пути.

    Адрес — то единственное, что сайт у себя записал. Версия параметром
    означала бы, что за одним адресом со временем меняется поведение, то есть
    ровно то, от чего версионирование должно защищать.
    """
    from gateway_app.widget.contract import VERSION

    assert widget.router.prefix == f"/widget/{VERSION}"


def test_version_is_reported_in_headers() -> None:
    """Версия видна в ответе.

    Нужна при разборе «у нас всё сломалось»: иначе неизвестно, что именно
    лежит у сайта в кэше.
    """
    from gateway_app.widget.contract import VERSION

    client = _client()

    assert client.get("/widget/v1/loader.js").headers["X-Vulnscan-Widget"] == VERSION
    frame_response = client.get("/widget/v1/frame", params={"key": "acme-public"})
    assert frame_response.headers["X-Vulnscan-Widget"] == VERSION


def test_frame_params_are_the_declared_ones() -> None:
    """Загрузчик передаёт фрейму ровно объявленные параметры."""
    from gateway_app.widget.contract import FRAME_PARAMS

    built = _loader().split("frame.src =")[1].split(";")[0]

    for name in FRAME_PARAMS:
        assert f"{name}=" in built, (
            f"параметр {name} объявлен в контракте, но загрузчик его не шлёт"
        )


def test_loader_points_at_the_current_version() -> None:
    """Адрес фрейма внутри загрузчика совпадает с версией контракта.

    Версия здесь продублирована: в `contract.py` и строкой в JavaScript.
    Разойдясь, они дадут загрузчик новой версии, который просит фрейм старой,
    — и виджет перестанет работать у тех, у кого свежий скрипт, то есть у всех
    сразу после выката.
    """
    from gateway_app.widget.contract import VERSION

    assert f"/widget/{VERSION}/frame" in _loader()


# --- поведение при недоступности задаёт политика (M12.9) ------------------


def test_policy_is_baked_into_the_frame() -> None:
    """Режим приходит с сервера, а не выбирается страницей.

    JavaScript на странице правит кто угодно: посетитель через консоль, сам
    сайт «чтобы форма не мешала», расширение браузера. Оставь мы выбор там —
    «не смогли проверить» тихо превратилось бы в «отправляем как есть».
    """
    blocking = _client(on_unavailable="block").get(
        "/widget/v1/frame", params={"key": "acme-public"}
    )
    marking = _client(on_unavailable="mark").get(
        "/widget/v1/frame", params={"key": "acme-public"}
    )

    assert 'var ON_UNAVAILABLE = "block"' in blocking.text
    assert 'var ON_UNAVAILABLE = "mark"' in marking.text


def test_placeholder_never_reaches_the_browser() -> None:
    """Подстановка действительно происходит.

    Незаменённый placeholder не сломал бы фрейм заметно: строка не равна
    «mark», значит поведение было бы блокирующим. Тихо правильный ответ по
    неверной причине — худший вид ошибки, поэтому проверяется явно.
    """
    response = _client().get("/widget/v1/frame", params={"key": "acme-public"})

    assert "__ON_UNAVAILABLE__" not in response.text


def test_default_is_blocking() -> None:
    """Умолчание — не пропускать.

    Непроверенный файл не должен выглядеть как проверенный, и умолчание в
    таком выборе всегда должно быть строгим.
    """
    from vscommon.models import TenantPolicy

    assert TenantPolicy().widget_on_unavailable == "block"


def test_frame_reports_whether_submission_is_allowed() -> None:
    """Сообщение `unchecked` несёт флаг, а не оставляет сайт гадать."""
    frame = _frame()

    assert "allow_submit: !block" in frame
    assert 'ON_UNAVAILABLE !== "mark"' in frame


def test_loader_records_the_state() -> None:
    """Второе скрытое поле объясняет, почему `scan_id` пуст.

    Пустое значение означает «вложения нет», но не говорит, не приложили ли
    файл, заблокирован ли он или проверка не состоялась. Для бэкенда сайта
    это три разных случая.
    """
    from gateway_app.widget.contract import STATE_FIELD

    loader = _loader()

    assert f'stateField.name = "{STATE_FIELD}"' in loader
    assert "stateField.value = data.type" in loader


def test_unchecked_never_fills_the_scan_id() -> None:
    """Даже в режиме `mark` идентификатора нет.

    Его и не существует: проверка не состоялась. Сайт узнаёт о вложении из
    поля состояния и принимает решение сам — но «непроверенный» никогда не
    выглядит как «проверенный».
    """
    from gateway_app.widget.contract import TYPES_WITH_SCAN_ID

    assert "unchecked" not in TYPES_WITH_SCAN_ID


# --- CSP (M12.10) --------------------------------------------------------


def test_documented_csp_matches_what_the_widget_needs() -> None:
    """Документация просит ровно те директивы, которые нужны.

    Лишняя просьба ослабить политику — то, из-за чего интеграцию отклоняет
    служба безопасности сайта, и справедливо. Недостающая — неделя переписки:
    виджет молча не появляется на странице, а причина видна только в консоли.

    Проверяется по коду: загрузчик грузит скрипт (`script-src`) и создаёт
    фрейм (`frame-src`), и больше со страницы ничего не запрашивает.
    """
    from pathlib import Path

    doc = (Path(__file__).parent.parent / "docs/protocol.md").read_text()
    csp = doc.split("### CSP на стороне сайта")[1].split("###")[0]

    assert "script-src" in csp
    assert "frame-src" in csp

    loader = _loader()
    # Со страницы мы ничего не запрашиваем — значит connect-src просить не за
    # что. Если это изменится, документацию придётся править вместе с кодом.
    assert "fetch(" not in loader
    assert "XMLHttpRequest" not in loader
    assert "eval(" not in loader


def test_frame_policy_forbids_everything_by_default() -> None:
    """Политика самого фрейма — запрещающая, с точечными разрешениями.

    Список запрещённого пропустил бы то, о чём мы не подумали; список
    разрешённого — нет.
    """
    response = _client().get("/widget/v1/frame", params={"key": "acme-public"})
    policy = response.headers["Content-Security-Policy"]

    assert "default-src 'none'" in policy
    assert "connect-src 'self'" in policy
    assert "form-action 'none'" in policy


# --- оформление (тема) ---------------------------------------------------


def test_known_variables_are_applied() -> None:
    """Переданное оформление попадает в документ."""
    response = _client().get(
        "/widget/v1/frame",
        params={"key": "acme-public", "accent": "#123abc", "radius": "12px"},
    )

    assert "--vs-accent: #123abc;" in response.text
    assert "--vs-radius: 12px;" in response.text


def test_unknown_variables_are_dropped() -> None:
    """Неизвестное имя отбрасывается молча.

    Список закрытый: переменная, о которой мы не думали, — это возможность,
    которую мы не проверяли. Молча, а не с объяснением: подсказка «такая не
    поддерживается» помогает подбирать.
    """
    response = _client().get(
        "/widget/v1/frame", params={"key": "acme-public", "position": "absolute"}
    )

    assert "position" not in response.text.split("id=\"theme\"")[1].split("</style>")[0]


@pytest.mark.parametrize(
    "value",
    [
        "url(https://evil.example/beacon.png)",
        "#123; } body { display: none",
        "red; background-image: url(//evil.example)",
        'red" onload="alert(1)',
        "expression(alert(1))",
        "var(--vs-accent); } * { color: red",
    ],
)
def test_dangerous_values_are_rejected(value: str) -> None:
    """Значение, не похожее на цвет, не попадает в документ.

    Проверка идёт списком разрешённого, а не экранированием. Разница
    принципиальная: экранирование защищает от выхода из строки, а нам нужно
    защититься от любого значения, которого мы не ожидали. `url()` внутри
    цвета уносит наружу факт открытия формы, а закрывающая скобка добавляет
    свои правила к нашим — включая `content`, дописывающий текст к нашим
    сообщениям.
    """
    response = _client().get(
        "/widget/v1/frame", params={"key": "acme-public", "accent": value}
    )
    theme = response.text.split('id="theme"')[1].split("</style>")[0]

    assert "url(" not in theme
    assert "evil.example" not in theme
    assert "}" not in theme
    assert "onload" not in theme


def test_theme_is_empty_when_nothing_passed() -> None:
    """Без параметров блок пуст, а не заполнен мусором."""
    response = _client().get("/widget/v1/frame", params={"key": "acme-public"})
    theme = response.text.split('id="theme"')[1].split("</style>")[0]

    assert theme.strip() == ">"


def test_loader_forwards_theme_attributes() -> None:
    """Загрузчик пробрасывает `data-vulnscan-*`, кроме служебных.

    Список известных переменных живёт на сервере в одном экземпляре: второй
    список в JavaScript разошёлся бы с ним, и разошёлся бы молча — параметр
    просто перестал бы действовать.
    """
    loader = _loader()

    assert 'attribute.name.indexOf("data-vulnscan-") !== 0' in loader
    assert 'name === "key" || name === "field"' in loader


def test_theme_variables_exist_in_the_stylesheet() -> None:
    """Каждая объявленная переменная действительно используется.

    Переменная, которую можно передать, но которая ни на что не влияет, —
    обещание без исполнения: интегратор подберёт цвет и не поймёт, почему
    ничего не изменилось.
    """
    from gateway_app.widget.theme import VARIABLES

    frame = _frame()
    unused = [name for name in VARIABLES.values() if f"var({name}" not in frame]

    assert not unused, f"объявлены, но не применяются: {unused}"


# --- пример интеграции проверяет вердикт сам -----------------------------


def test_example_verifies_on_the_backend() -> None:
    """Пример с виджетом запрашивает вердикт своим ключом.

    Пример — то, что копируют. Пропущенный здесь шаг проверки разойдётся по
    чужим сайтам вместе с ним, причём в виде, который выглядит работающим:
    форма принимает файлы, вердикт «есть», проверки нет.
    """
    from pathlib import Path

    source = (
        Path(__file__).parent.parent / "examples/feedback-site/feedback_site.py"
    ).read_text()
    handler = source.split("async def widget_submit")[1].split("@app.")[0]

    assert "client.result(vulnscan_scan_id)" in handler, "вердикт не запрашивается у сканера"


def test_example_does_not_trust_the_form_state() -> None:
    """Поле состояния из формы не решает, принимать ли вложение.

    Его написал браузер посетителя. Годится оно ровно на одно — объяснить
    человеку, что случилось, когда вложения нет.
    """
    from pathlib import Path

    source = (
        Path(__file__).parent.parent / "examples/feedback-site/feedback_site.py"
    ).read_text()
    handler = source.split("async def widget_submit")[1].split("@app.")[0]

    # Решение принимается по ответу сканера, а не по состоянию из формы.
    decisions = handler.split("client.result(vulnscan_scan_id)")[1]
    assert "vulnscan_state" not in decisions, "состояние из формы влияет на решение"
    assert "outcome.blocked" in decisions
    assert "outcome.safe" in decisions


def test_example_distinguishes_blocked_from_unverifiable() -> None:
    """`not blocked` и `safe` в примере разведены.

    Самая частая ошибка интеграции, и пример обязан показывать правильный
    вариант: три ветки, а не две.
    """
    from pathlib import Path

    source = (
        Path(__file__).parent.parent / "examples/feedback-site/feedback_site.py"
    ).read_text()
    handler = source.split("async def widget_submit")[1].split("@app.")[0]

    assert "if outcome.blocked" in handler
    assert "if not outcome.safe" in handler


# --- отложенный результат доводится до конца ------------------------------


def test_frame_polls_for_a_deferred_verdict() -> None:
    """Фрейм дожидается результата, а не бросает посетителя.

    Регрессия, найденная на живом стенде: крупный файл отвечал `202`, фрейм
    писал «ещё проверяется» и на этом останавливался. Прочитать вердикт он не
    мог — для этого нужна подпись, которой у него нет и быть не должно, — и
    посетитель не узнавал, принят его файл или нет. Никогда.
    """
    frame = _frame()

    assert "/widget/v1/status?ticket=" in frame
    assert "POLL_LIMIT" in frame
    # Именно вызов, а не наличие функции: объявленная и не вызванная она
    # оставляет поведение ровно тем, каким оно было до правки, а тест при
    # этом остаётся зелёным. На это я уже наступил, проверяя ломкой.
    assert "await await_result(sent.statusTicket)" in frame

    # И ветка отложенного ответа действительно к ней ведёт.
    deferred = frame.split("var pending =")[1]
    assert "await_result" in deferred


def test_status_ticket_is_issued_only_for_deferred_uploads() -> None:
    """Талон наблюдения выдаётся, когда он нужен, и не выдаётся зря.

    При синхронном ответе вердикт уже в теле: лишний предмет с доступом к
    скану — лишняя поверхность без выгоды.
    """
    from pathlib import Path

    source = (
        Path(__file__).parent.parent / "services/gateway/gateway_app/routes/scan.py"
    ).read_text()

    assert "if ticket is not None and not synchronous:" in source
    assert "X-Vulnscan-Status-Ticket" in source


def test_status_endpoint_needs_a_ticket() -> None:
    """Без талона ручка состояния не отвечает.

    Иначе она стала бы способом читать чужие вердикты по идентификатору —
    ровно то, от чего защищает проверка владения на остальных ручках.
    """
    response = _client().get("/widget/v1/status")

    assert response.status_code == 404


def test_status_endpoint_reveals_only_the_outcome() -> None:
    """Наружу уходит три состояния, а не вердикт с признаками.

    Браузеру нужно ровно одно: что показать посетителю. Балл, коды признаков
    и имя файла ему не нужны, а всё лишнее пришлось бы объяснять — и защищать.
    """
    from pathlib import Path

    source = (
        Path(__file__).parent.parent / "services/gateway/gateway_app/routes/widget.py"
    ).read_text()
    handler = source.split("async def status_by_ticket")[1]

    assert '"outcome"' in handler
    for leaked in ("findings", "score", "filename", "sha256"):
        assert leaked not in handler, f"ручка состояния отдаёт лишнее: {leaked}"


def test_status_endpoint_rechecks_ownership() -> None:
    """Владение перепроверяется, хотя талон выдавали мы.

    Между выдачей и опросом скан может истечь, а «не знаем чей» не может
    означать «отдать спросившему».
    """
    from pathlib import Path

    source = (
        Path(__file__).parent.parent / "services/gateway/gateway_app/routes/widget.py"
    ).read_text()
    handler = source.split("async def status_by_ticket")[1]

    assert "ownership.allows(" in handler
