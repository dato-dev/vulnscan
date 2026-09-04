"""M12.4: CORS для загрузки из браузера.

Проверяется через настоящее ASGI-приложение, а не вызовом функции: CORS — это
поведение на границе, и половина ошибок в нём это забытый заголовок в ответе,
которого при прямом вызове просто не видно.

Приложение здесь минимальное: middleware плюс заглушка маршрута. Поднимать
целый gateway ради заголовков незачем — ему нужны Redis, хранилище и ключи, а
проверяем мы не их.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway_app.cors import cors_middleware
from vscommon.keys import AccessKey, KeyRegistry

SITE = "https://acme.tld"
FOREIGN = "https://evil.example"
"""Адреса здесь только из ASCII, и это не упрощение.

Заголовки HTTP кодируются latin-1: интернационализированное имя приезжает в
`Origin` уже как punycode (`xn--...`). Кириллица в этом заголовке невозможна —
первая версия теста на ней и упала, притом в клиенте, а не в проверяемом коде.
"""


def _app(keys: KeyRegistry) -> FastAPI:
    app = FastAPI()
    app.state.vs = SimpleNamespace(keys=keys)
    app.middleware("http")(cors_middleware)

    @app.post("/v1/tickets")
    async def tickets() -> dict[str, str]:
        return {"ticket": "тест"}

    @app.post("/v1/scan")
    async def scan() -> dict[str, str]:
        return {"scan_id": "тест"}

    @app.get("/v1/scan/{scan_id}")
    async def result(scan_id: str) -> dict[str, str]:
        return {"scan_id": scan_id}

    return app


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


@pytest.fixture()
def client() -> TestClient:
    return TestClient(_app(_registry()))


def test_preflight_is_answered_for_known_origin(client: TestClient) -> None:
    """Браузер получает разрешение на загрузку с зарегистрированного адреса."""
    response = client.options(
        "/v1/scan",
        headers={
            "Origin": SITE,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-vulnscan-ticket, content-type",
        },
    )

    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == SITE
    assert "POST" in response.headers["Access-Control-Allow-Methods"]
    assert "x-vulnscan-ticket" in response.headers["Access-Control-Allow-Headers"].lower()


def test_allow_origin_is_never_a_wildcard(client: TestClient) -> None:
    """Отдаётся конкретный адрес, а не `*`.

    Со звёздочкой ответ прочитала бы любая страница, а в ответе на `/v1/tickets`
    лежит талон — то есть предмет, которым грузят файл.
    """
    preflight = client.options(
        "/v1/tickets",
        headers={"Origin": SITE, "Access-Control-Request-Method": "POST"},
    )
    actual = client.post("/v1/tickets", headers={"Origin": SITE})

    assert preflight.headers["Access-Control-Allow-Origin"] == SITE
    assert actual.headers["Access-Control-Allow-Origin"] == SITE


def test_preflight_from_unknown_origin_is_refused(client: TestClient) -> None:
    """Чужой сайт не получает разрешения.

    Не потому, что это защита — настоящая проверка на самом запросе, — а
    потому, что сообщать первому встречному о том, что мы принимаем
    браузерные загрузки, незачем.
    """
    response = client.options(
        "/v1/scan",
        headers={"Origin": FOREIGN, "Access-Control-Request-Method": "POST"},
    )

    assert response.status_code == 403
    assert "Access-Control-Allow-Origin" not in response.headers


def test_response_to_unknown_origin_has_no_cors_headers(client: TestClient) -> None:
    """Ответ на обычный запрос с чужого адреса браузер прочитать не сможет."""
    response = client.post("/v1/scan", headers={"Origin": FOREIGN})

    assert "Access-Control-Allow-Origin" not in response.headers


def test_reading_results_is_not_exposed_to_browsers(client: TestClient) -> None:
    """Чтение результата из браузера не разрешается даже своему сайту.

    Оно требует секретного ключа, а секретному ключу в браузере не место.
    Разрешив CORS «на всякий случай», мы бы приглашали держать секрет в
    странице — то есть ровно то, ради предотвращения чего затевались талоны.
    """
    response = client.get("/v1/scan/abc", headers={"Origin": SITE})

    assert "Access-Control-Allow-Origin" not in response.headers


def test_unknown_request_headers_are_not_granted(client: TestClient) -> None:
    """Разрешаются только известные заголовки, список положительный.

    Незнакомый заголовок не пропускается «раз уж попросили»: браузер спрашивает
    ровно то, что собирается прислать, и согласие на неизвестное — это согласие
    на то, чего мы не проверяли.
    """
    response = client.options(
        "/v1/scan",
        headers={
            "Origin": SITE,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-vulnscan-ticket, x-forged",
        },
    )

    granted = response.headers["Access-Control-Allow-Headers"].lower()
    assert "x-vulnscan-ticket" in granted
    assert "forged" not in granted


def test_vary_origin_is_always_set(client: TestClient) -> None:
    """`Vary: Origin` обязателен.

    Без него промежуточный кэш отдаст одному сайту разрешение, выданное
    другому, — и разрешение окажется у того, кому его не давали.
    """
    preflight = client.options(
        "/v1/scan", headers={"Origin": SITE, "Access-Control-Request-Method": "POST"}
    )
    actual = client.post("/v1/scan", headers={"Origin": SITE})

    assert preflight.headers["Vary"] == "Origin"
    assert "Origin" in actual.headers["Vary"]


def test_disabled_key_stops_being_allowed() -> None:
    """Отзыв ключа убирает его origin из разрешённых сразу.

    Реестр читается на каждый запрос, а не кэшируется: кэш означал бы, что
    отозванный ключ ещё какое-то время принимается.
    """
    client = TestClient(_app(_registry(disabled=True)))

    response = client.options(
        "/v1/scan", headers={"Origin": SITE, "Access-Control-Request-Method": "POST"}
    )

    assert response.status_code == 403


def test_secret_key_origins_do_not_open_cors() -> None:
    """Origin, прописанный непубличному ключу, ничего не открывает.

    Иначе поле `origins` у обычного ключа тихо включало бы браузерный доступ
    там, где его не задумывали.
    """
    client = TestClient(_app(_registry(public=False)))

    response = client.options(
        "/v1/scan", headers={"Origin": SITE, "Access-Control-Request-Method": "POST"}
    )

    assert response.status_code == 403


def test_degraded_registry_allows_nothing() -> None:
    """Реестр не прочитан — не разрешаем никого.

    Умолчание в аутентификации это дыра, и в CORS ровно так же: «не знаем» не
    может означать «можно».
    """
    client = TestClient(_app(KeyRegistry({}, degraded=True)))

    response = client.options(
        "/v1/scan", headers={"Origin": SITE, "Access-Control-Request-Method": "POST"}
    )

    assert response.status_code == 403
