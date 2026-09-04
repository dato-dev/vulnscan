"""M12.2: загрузка по талону — отдельный путь аутентификации.

Талон уезжает в браузер, то есть попадает в руки посетителя. Всё, что здесь
проверяется, — про границы этого предмета: он пускает на загрузку и никуда
больше, гасится один раз и не переживает отзыв ключа, которым выдан.

Проверяется зависимость, а не HTTP: стенда для маршрутов gateway в проекте нет,
а решение «пускать или нет» целиком принимается здесь. Подделывать вокруг неё
FastAPI ради того же ответа — работа без выигрыша.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fakeredis import aioredis
from fastapi import HTTPException

from vscommon.keys import AccessKey, KeyRegistry
from vscommon.tickets import TicketStore


class _Headers(dict):
    """Заголовки, как их отдаёт Starlette: без учёта регистра.

    Обычный словарь здесь врёт. `Host` и `host` — один заголовок, и двойник,
    который их различает, проверяет не то поведение, которое поедет: код,
    читающий `host`, в тесте получал пустоту, а в бою — значение.
    """

    def get(self, name: str, default: str = "") -> str:  # type: ignore[override]
        lowered = name.lower()
        for key, value in self.items():
            if key.lower() == lowered:
                return str(value)
        return default

    def __contains__(self, name: object) -> bool:
        return any(key.lower() == str(name).lower() for key in self)


class _Request:
    """То немногое из `Request`, чем пользуется зависимость."""

    def __init__(self, headers: dict[str, str], state: Any) -> None:
        self.headers = _Headers(headers)
        self.method = "POST"
        # `scheme` нужен для вычисления собственного origin сервиса.
        self.url = SimpleNamespace(path="/v1/scan", scheme="https")
        self.app = SimpleNamespace(state=SimpleNamespace(vs=state))
        self.state = SimpleNamespace()


def _registry(disabled: bool = False) -> KeyRegistry:
    key = AccessKey(
        key_id="acme-site",
        tenant="acme",
        secret="s" * 32,
        disabled=disabled,
    )
    return KeyRegistry({key.key_id: key})


@pytest.fixture()
def store() -> TicketStore:
    return TicketStore(aioredis.FakeRedis())


@pytest.mark.asyncio
async def test_valid_ticket_authenticates_upload(store: TicketStore) -> None:
    """Годный талон пускает на загрузку и приносит ключ своего тенанта."""
    from gateway_app.auth import require_key_or_ticket

    ticket, _ = await store.issue("acme", "acme-site", max_bytes=4096)
    state = SimpleNamespace(tickets=store, keys=_registry())
    request = _Request({"X-Vulnscan-Ticket": ticket.token}, state)

    key = await require_key_or_ticket(request)  # type: ignore[arg-type]

    assert key.tenant == "acme"
    assert request.state.ticket.max_bytes == 4096


@pytest.mark.asyncio
async def test_ticket_works_once(store: TicketStore) -> None:
    """Повторное предъявление того же талона — отказ.

    Без этого талон, подсмотренный в браузере, становится ключом на время
    своей жизни.
    """
    from gateway_app.auth import require_key_or_ticket

    ticket, _ = await store.issue("acme", "acme-site", max_bytes=4096)
    state = SimpleNamespace(tickets=store, keys=_registry())

    await require_key_or_ticket(_Request({"X-Vulnscan-Ticket": ticket.token}, state))  # type: ignore[arg-type]

    with pytest.raises(HTTPException) as exc:
        await require_key_or_ticket(_Request({"X-Vulnscan-Ticket": ticket.token}, state))  # type: ignore[arg-type]

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_unknown_ticket_is_rejected(store: TicketStore) -> None:
    """Выдуманный талон не проходит, и причина в ответ не уходит."""
    from gateway_app.auth import require_key_or_ticket

    state = SimpleNamespace(tickets=store, keys=_registry())

    with pytest.raises(HTTPException) as exc:
        await require_key_or_ticket(_Request({"X-Vulnscan-Ticket": "выдуманный"}, state))  # type: ignore[arg-type]

    assert exc.value.status_code == 401
    # «не существовал», «истёк» и «уже погашен» для предъявителя одно и то же:
    # различать их — значит подсказывать подбирающему.
    assert exc.value.detail == "талон недействителен"


@pytest.mark.asyncio
async def test_ticket_dies_with_its_key(store: TicketStore) -> None:
    """Отзыв ключа гасит и выданные им талоны.

    Гарантию даёт `KeyRegistry.get`: отключённый ключ он не возвращает. Второй
    проверки в `auth` нет намеренно — два места, решающих одно, расходятся.
    Тест закрепляет наблюдаемое поведение, а не конкретную строку: важно, что
    отзыв срабатывает сразу, а не «примерно скоро», когда истечёт последний
    выданный талон.
    """
    from gateway_app.auth import require_key_or_ticket

    ticket, _ = await store.issue("acme", "acme-site", max_bytes=4096)
    state = SimpleNamespace(tickets=store, keys=_registry(disabled=True))

    with pytest.raises(HTTPException) as exc:
        await require_key_or_ticket(_Request({"X-Vulnscan-Ticket": ticket.token}, state))  # type: ignore[arg-type]

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_signature_wins_over_ticket(store: TicketStore) -> None:
    """При наличии идентификатора ключа идём по подписи, а не по талону.

    Порядок важен: клиент с валидной подписью, приславший заодно протухший
    талон, должен загрузить файл, а не получить отказ.
    """
    from gateway_app.auth import require_key_or_ticket

    state = SimpleNamespace(tickets=store, keys=_registry())
    request = _Request(
        {"X-Vulnscan-Key": "acme-site", "X-Vulnscan-Ticket": "протухший"},
        state,
    )

    with pytest.raises(HTTPException) as exc:
        await require_key_or_ticket(request)  # type: ignore[arg-type]

    # Отказ именно по подписи — талон даже не смотрели.
    assert exc.value.detail == "запрос не подписан"


@pytest.mark.asyncio
async def test_ticket_is_not_accepted_elsewhere() -> None:
    """Талон принимает только загрузка.

    Проверка структурная и потому надёжнее: единственная зависимость, знающая
    про заголовок талона, — `require_key_or_ticket`, и подключена она к одному
    маршруту. Появится второй — тест упадёт и заставит объяснить зачем.
    """
    routes = (Path(__file__).parent.parent / "services/gateway/gateway_app/routes").rglob("*.py")
    users = {
        path.name: path.read_text().count("require_key_or_ticket")
        for path in routes
        if "require_key_or_ticket" in path.read_text()
    }

    assert users == {"scan.py": 2}, (
        f"талон принимает не только загрузка: {users}. "
        "Ожидается один импорт и одно использование в scan.py"
    )


# --- публичный ключ сайта (M12.3) ----------------------------------------


def _site_key(origins: tuple[str, ...] = ("https://acme.tld",)) -> KeyRegistry:
    key = AccessKey(
        key_id="acme-public",
        tenant="acme",
        # Секрет у публичного ключа формально есть, но он публичен: лежит в
        # HTML вместе с идентификатором. Подписывать им нельзя.
        secret="p" * 32,
        public=True,
        origins=origins,
    )
    return KeyRegistry({key.key_id: key})


@pytest.mark.asyncio
async def test_site_key_accepts_allowed_origin(store: TicketStore) -> None:
    """Публичный ключ с разрешённого адреса пропускается."""
    from gateway_app.auth import require_site_key

    state = SimpleNamespace(tickets=store, keys=_site_key())
    request = _Request(
        {"X-Vulnscan-Key": "acme-public", "Origin": "https://acme.tld"}, state
    )

    key = await require_site_key(request)  # type: ignore[arg-type]

    assert key.tenant == "acme"


@pytest.mark.asyncio
async def test_site_key_rejects_foreign_origin(store: TicketStore) -> None:
    """Тот же ключ с чужой страницы не работает.

    Ради этого привязка и существует: ключ виден всем, кто открыл исходный код
    страницы, и без списка origin его можно вставить на любой сайт и
    расходовать чужую квоту.
    """
    from gateway_app.auth import require_site_key

    state = SimpleNamespace(tickets=store, keys=_site_key())
    request = _Request(
        {"X-Vulnscan-Key": "acme-public", "Origin": "https://зло.tld"}, state
    )

    with pytest.raises(HTTPException) as exc:
        await require_site_key(request)  # type: ignore[arg-type]

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_site_key_without_origins_works_nowhere(store: TicketStore) -> None:
    """Пустой список origin означает «ещё не настроено», а не «разрешено всё».

    Умолчание в аутентификации — дыра, и здесь оно особенно дорогое: публичный
    ключ без списка годится для любого сайта в интернете.
    """
    from gateway_app.auth import require_site_key

    state = SimpleNamespace(tickets=store, keys=_site_key(origins=()))
    request = _Request(
        {"X-Vulnscan-Key": "acme-public", "Origin": "https://acme.tld"}, state
    )

    with pytest.raises(HTTPException):
        await require_site_key(request)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_public_key_can_never_sign(store: TicketStore) -> None:
    """Публичным ключом нельзя подписать запрос — ни с какой подписью.

    Это главное свойство разделения. Секрет публичного ключа знает каждый
    посетитель сайта; если бы им проходила проверка подписи, подписать мог бы
    кто угодно, и весь смысл двух типов ключей исчез бы.

    Проверяется на подписи, посчитанной ПРАВИЛЬНО: отказ должен наступать
    из-за типа ключа, а не из-за неверных байтов.
    """
    from vscommon.signing import sign

    registry = _site_key()
    body = b'{"wait_ms":400}'
    timestamp, signature = sign("p" * 32, body)

    key, check = registry.check("acme-public", body, timestamp, signature)

    assert key is None, "публичный ключ прошёл проверку подписи"
    assert not check.ok


@pytest.mark.asyncio
async def test_normal_key_is_not_a_site_key(store: TicketStore) -> None:
    """Обычный ключ тенанта не годится как ключ сайта.

    Иначе секретный ключ можно было бы вставить в HTML и он бы работал — то
    есть разделение существовало бы только на бумаге.
    """
    from gateway_app.auth import require_site_key

    state = SimpleNamespace(tickets=store, keys=_registry())
    request = _Request({"X-Vulnscan-Key": "acme-site", "Origin": "https://acme.tld"}, state)

    with pytest.raises(HTTPException):
        await require_site_key(request)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("configured", "sent", "expected"),
    [
        (("https://acme.tld",), "https://acme.tld", True),
        (("https://acme.tld",), "https://acme.tld/", True),
        (("https://acme.tld/",), "https://acme.tld", True),
        (("https://ACME.tld",), "https://acme.tld", True),
        (("https://acme.tld",), "http://acme.tld", False),
        (("https://acme.tld",), "https://acme.tld:8443", False),
        (("https://acme.tld",), "https://sub.acme.tld", False),
        (("https://acme.tld",), "null", False),
        (("https://acme.tld",), "", False),
    ],
)
def test_origin_matching_rules(configured: tuple[str, ...], sent: str, expected: bool) -> None:
    """Сравнение точное; регистр и косая черта не значат ничего.

    Схема и порт значат: `http` вместо `https` — это другой канал, другой порт
    — другой сервис. Поддомен тоже не подходит, и это главное: маска
    `*.acme.tld` превращала бы захват любого заброшенного поддомена в кражу
    ключа.

    `Origin: null` шлют документы из песочницы и файлы с диска. Значение
    выглядит валидным, поэтому отвергается явно, а не «не совпало».
    """
    from vscommon.keys import origin_allowed

    key = AccessKey(
        key_id="k", tenant="acme", secret="p" * 32, public=True, origins=configured
    )

    assert origin_allowed(key, sent) is expected


def test_public_admin_key_is_refused(tmp_path: Path) -> None:
    """Ключ не может быть одновременно публичным и административным.

    Такой ключ — это ключ администратора, лежащий в HTML страницы. Запись не
    загружается вовсе: предупреждения мало, потому что предупреждения читают
    после инцидента.
    """
    from vscommon.keys import KeyRegistry

    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {"bad": {"tenant": "t", "secret": "s" * 32, "public": True, "admin": True}}
        )
    )

    assert KeyRegistry.load(str(path)).get("bad") is None


def test_example_file_shows_both_key_types() -> None:
    """Пример ключей описывает и обычный, и публичный.

    Файл-пример — то, что копируют. Отсутствующий в нём тип ключа существует
    только в документации, а копируют не документацию.
    """
    from vscommon.keys import KeyRegistry

    registry = KeyRegistry.load("deploy/config/keys.example.json")
    kinds = {key_id: registry.get(key_id) for key_id in ("telegram-bot-1", "acme-site-public")}

    assert all(key is not None for key in kinds.values()), f"в примере не хватает ключа: {kinds}"
    assert kinds["acme-site-public"].public is True
    assert kinds["acme-site-public"].origins, "у публичного ключа в примере нет origins"
    assert kinds["telegram-bot-1"].public is False


# --- запрос из нашего фрейма ---------------------------------------------


@pytest.mark.asyncio
async def test_request_from_our_own_frame_is_accepted(store: TicketStore) -> None:
    """Талон выдаётся по запросу из документа фрейма.

    Регрессия, найденная на первом же запуске виджета: фрейм живёт на НАШЕМ
    origin, и обращение к `/v1/tickets` для него same-origin — браузер ставит
    наш адрес, а не адрес сайта. Проверка искала адрес сайта и отвечала «ключ
    сайта недействителен», хотя ключ был в полном порядке.

    Доверие здесь опирается не на заголовок, а на `frame-ancestors`:
    загрузиться этот документ мог только на странице из списка ключа.
    """
    from gateway_app.auth import require_site_key

    state = SimpleNamespace(tickets=store, keys=_site_key())
    request = _Request(
        {
            "X-Vulnscan-Key": "acme-public",
            # Наш собственный адрес, не адрес сайта.
            "Origin": "https://scanner.example",
            "Host": "scanner.example",
        },
        state,
    )

    key = await require_site_key(request)  # type: ignore[arg-type]

    assert key.tenant == "acme"


@pytest.mark.asyncio
async def test_foreign_origin_is_still_refused(store: TicketStore) -> None:
    """Послабление не открыло дверь чужим адресам.

    Без этой проверки предыдущая означала бы «принимаем любой origin»: наш
    собственный адрес совпадает не со всем подряд, и это надо показать.
    """
    from gateway_app.auth import require_site_key

    state = SimpleNamespace(tickets=store, keys=_site_key())
    request = _Request(
        {
            "X-Vulnscan-Key": "acme-public",
            "Origin": "https://evil.example",
            "Host": "scanner.example",
        },
        state,
    )

    with pytest.raises(HTTPException) as exc:
        await require_site_key(request)  # type: ignore[arg-type]

    assert exc.value.status_code == 401
