"""Пример подключения — форма обратной связи: оба способа и все исходы.

Сайт гоняется целиком через HTTP, сканер подменён. Проверяется то, что
копируют подключающиеся команды: какие исходы принимаются, что видит
посетитель и что делается с копией.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from vulnscan_client import CleanCopy, VulnscanError
from vulnscan_client.client import _to_outcome

SITE = Path(__file__).resolve().parents[1] / "examples/feedback-site/feedback_site.py"


@pytest.fixture(scope="module")
def site() -> Any:
    spec = importlib.util.spec_from_file_location("feedback_site", SITE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["feedback_site"] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop("feedback_site", None)


def _outcome(verdict: str = "clean", status: str = "done", sanitized: bool = True, **extra: Any):
    return _to_outcome(
        {
            "scan_id": "scan-7",
            "verdict": verdict,
            "status": status,
            "score": 0,
            "sanitized": {"ref": {}} if sanitized else None,
            **extra,
        }
    )


class FakeScanner:
    def __init__(self, *outcomes: Any, copy: CleanCopy | None = None) -> None:
        self._outcomes = list(outcomes)
        self.copy = copy or CleanCopy(b"PK\x03\x04docx", "application/vnd.x-docx", "scan-7.docx")
        self.uploads: list[tuple[str, str]] = []
        self.results: list[str] = []

    def _next(self) -> Any:
        item = self._outcomes.pop(0) if len(self._outcomes) > 1 else self._outcomes[0]
        if isinstance(item, Exception):
            raise item
        return item

    async def scan(self, content: bytes, filename: str, content_type: str = "", profile=None):
        self.uploads.append((filename, content_type))
        return self._next()

    async def result(self, scan_id: str):
        self.results.append(scan_id)
        return self._next()

    async def download_clean_copy(self, scan_id: str) -> CleanCopy:
        return self.copy


@pytest.fixture()
def client(site: Any, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(site, "POLL_DELAY_S", 0.0)
    monkeypatch.setattr(site, "SITE_KEY", "demo-site-public")
    site._clean_files.clear()

    def use(fake: FakeScanner) -> TestClient:
        site.app.dependency_overrides[site.scanner] = lambda: fake
        # Без `with`: lifespan не запускается — настоящий клиент и порт метрик
        # тесту не нужны.
        return TestClient(site.app)

    yield use
    site.app.dependency_overrides.clear()


def _send(http: TestClient, data: bytes = b"%PDF-1.7", name: str = "Жалоба.docx") -> str:
    response = http.post(
        "/feedback",
        data={"name": "Мария", "message": "текст"},
        files={"attachment": (name, data, "application/octet-stream")},
    )
    assert response.status_code == 200
    return response.text


# --- способ первый: через библиотеку ----------------------------------------


def test_clean_file_accepted_as_rebuilt_copy_of_its_own_type(client) -> None:
    fake = FakeScanner(_outcome())
    http = client(fake)

    page = _send(http)
    copy = http.get("/clean/scan-7")

    assert 'class="box ok"' in page and "/clean/scan-7" in page
    # Тип и имя копии — от сканера, а не «всё это PDF».
    assert copy.headers["content-type"].startswith("application/vnd.x-docx")
    assert 'filename="scan-7.docx"' in copy.headers["content-disposition"]
    assert copy.headers["x-content-type-options"] == "nosniff"


def test_browser_type_is_passed_as_hint(client) -> None:
    fake = FakeScanner(_outcome())
    _send(client(fake))

    assert fake.uploads == [("Жалоба.docx", "application/octet-stream")]


@pytest.mark.parametrize(
    ("outcome", "css", "phrase"),
    [
        (
            _outcome("malicious", sanitized=False, findings=[{"code": "DOCX_DDE"}]),
            "bad",
            "DOCX_DDE",
        ),
        (_outcome("encrypted", sanitized=False), "warn", "паролем"),
        (_outcome("unsupported", sanitized=False), "warn", "неподдерживаемом"),
        (_outcome("suspicious"), "warn", "вызвало вопросы"),
        # Незнакомый вердикт без копии: принять нечего — оригинал мы не берём.
        (_outcome("нечто-новое", sanitized=False), "warn", "безопасную копию"),
        (_outcome("clean", sanitized=False), "warn", "безопасную копию"),
    ],
)
def test_every_verdict_has_its_answer(client, outcome, css, phrase) -> None:
    page = _send(client(FakeScanner(outcome)))

    assert f'class="box {css}"' in page and phrase in page


def test_blocked_file_offers_no_copy(client) -> None:
    http = client(FakeScanner(_outcome("malicious", sanitized=False)))
    page = _send(http)

    assert "/clean/" not in page
    assert http.get("/clean/scan-7").status_code == 404


def test_scanner_down_is_not_accepted(client) -> None:
    page = _send(client(FakeScanner(VulnscanError("сервис недоступен"))))

    assert "Не смогли проверить" in page and "/clean/" not in page


def test_pending_is_polled_to_verdict(client) -> None:
    fake = FakeScanner(_outcome("", status="queued"), _outcome("", status="scanning"), _outcome())
    page = _send(client(fake))

    assert 'class="box ok"' in page
    assert fake.results  # дожидались опросом, а не сдались на `202`


def test_pending_forever_is_neither_clean_nor_suspicious(client) -> None:
    page = _send(client(FakeScanner(_outcome("", status="queued"))))

    assert "ещё проверяется" in page and "вызвало вопросы" not in page


def test_no_attachment_is_just_a_message(client) -> None:
    fake = FakeScanner(_outcome())
    response = client(fake).post("/feedback", data={"name": "Мария", "message": "текст"})

    assert "Сообщение принято" in response.text and fake.uploads == []


def test_oversized_upload_refused_before_parsing(client, site, monkeypatch) -> None:
    monkeypatch.setattr(site, "MAX_BYTES", 1024)
    fake = FakeScanner(_outcome())

    response = client(fake).post(
        "/feedback",
        data={"name": "Мария", "message": "текст"},
        files={"attachment": ("big.pdf", b"x" * (200 * 1024), "application/pdf")},
    )

    assert response.status_code == 413
    assert fake.uploads == []
    assert "больше" in response.text


def test_copies_do_not_grow_without_bound(client, site, monkeypatch) -> None:
    monkeypatch.setattr(site, "KEEP_COPIES", 3)
    http = client(FakeScanner(_outcome()))

    for n in range(6):
        fake = FakeScanner(_outcome(scan_id=f"scan-{n}"))
        site.app.dependency_overrides[site.scanner] = lambda fake=fake: fake
        _send(http)

    assert len(site._clean_files) == 3


# --- способ второй: наш виджет ------------------------------------------------


def _widget(http: TestClient, **fields: str) -> str:
    response = http.post("/widget-feedback", data={"name": "Мария", "message": "т", **fields})
    assert response.status_code == 200
    return response.text


def test_widget_page_points_to_scanner(client, site, monkeypatch) -> None:
    monkeypatch.setattr(site, "SCANNER_PUBLIC_URL", "https://scan.example")
    page = client(FakeScanner(_outcome())).get("/widget").text

    assert 'src="https://scan.example/widget/v1/loader.js"' in page
    assert 'data-vulnscan-key="demo-site-public"' in page


def test_widget_verdict_is_asked_with_own_key(client) -> None:
    """Состояние из формы написал браузер. Вердикт — только от сканера."""
    fake = FakeScanner(_outcome("malicious", sanitized=False))

    page = _widget(client(fake), vulnscan_scan_id="scan-7", vulnscan_state="clean")

    assert fake.results == ["scan-7"]
    assert 'class="box bad"' in page


def test_widget_accepts_the_same_way_as_library(client) -> None:
    http = client(FakeScanner(_outcome()))

    page = _widget(http, vulnscan_scan_id="scan-7")

    assert 'class="box ok"' in page and http.get("/clean/scan-7").status_code == 200


def test_widget_unknown_scan_id_is_refused(client) -> None:
    """Подобранный или чужой идентификатор: сканер отвечает «нет такого»."""
    page = _widget(client(FakeScanner(None)), vulnscan_scan_id="чужой")

    assert "не найдено" in page


def test_widget_without_attachment_trusts_state_only_for_wording(client) -> None:
    fake = FakeScanner(_outcome())

    page = _widget(client(fake), vulnscan_state="blocked")

    assert "заблокировано" in page and fake.results == []


def test_widget_scanner_down(client) -> None:
    page = _widget(client(FakeScanner(VulnscanError("x"))), vulnscan_scan_id="scan-7")

    assert "Не смогли подтвердить" in page


def test_healthz_does_not_touch_scanner(client) -> None:
    assert client(FakeScanner(VulnscanError("лежит"))).get("/healthz").json() == {"status": "ok"}
