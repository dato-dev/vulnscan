"""M9.3: фиксированные векторы протокола, общие для всех реализаций.

Смысл файла — не в том, чтобы поймать ошибку в Python-клиенте: он и так покрыт.
Смысл в том, чтобы **вторая реализация** проверялась не на живом стенде и не
перепиской, а прогоном по тем же числам.

До сих пор расхождение схем подписи обнаруживалось так: клиент получает `401`,
и дальше часы уходят на выяснение, что именно не сошлось — секрет, порядок
полей, разделитель или кодировка. Ответ «подпись не сошлась» одинаков во всех
четырёх случаях, и это не оплошность, а необходимость: подробный ответ подсказал
бы подбирающему, насколько он близок.

Здесь же проверяются обе стороны сразу: `vscommon.signing` (сервис) и
`vulnscan_client` (опорная библиотека). Разойдясь между собой, они разойдутся и
с документом.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

VECTORS = Path(__file__).parent / "vectors/protocol.json"
DOC = Path(__file__).parent.parent / "docs/protocol.md"


def _data() -> dict[str, Any]:
    return dict(json.loads(VECTORS.read_text()))


def _payload(vector: dict[str, Any]) -> bytes:
    """Байты нагрузки из вектора.

    В файле они лежат дважды: как текст и как hex. Берём hex — он однозначен, а
    текстовое представление есть для человека, который читает файл глазами.
    """
    return bytes.fromhex(vector["payload_hex"])


def _cases() -> list[dict[str, Any]]:
    return list(_data()["signatures"])


@pytest.mark.parametrize("vector", _cases(), ids=lambda v: v["name"])
def test_service_matches_vector(vector: dict[str, Any]) -> None:
    """Подпись сервиса совпадает с зафиксированной."""
    from vscommon.signing import sign

    _, signature = sign(vector["secret"], _payload(vector), vector["timestamp"])

    assert signature == vector["signature"], f"{vector['name']}: {vector['description']}"


@pytest.mark.parametrize("vector", _cases(), ids=lambda v: v["name"])
def test_client_matches_vector(vector: dict[str, Any]) -> None:
    """И подпись опорной библиотеки — тоже.

    Библиотека считает подпись своим кодом, без импорта серверного: она едет к
    чужой команде и не должна тянуть за собой `vscommon`. Ровно поэтому её надо
    сверять отдельно — две копии одного алгоритма расходятся молча.
    """
    from vulnscan_client.client import _sign

    _, signature = _sign(vector["secret"], _payload(vector), vector["timestamp"])

    assert signature == vector["signature"], f"{vector['name']}: {vector['description']}"


@pytest.mark.parametrize("case", _data()["canonical_request"], ids=lambda c: c["path"])
def test_canonical_request_bytes(case: dict[str, Any]) -> None:
    """Канонический запрос собирается байт в байт.

    Здесь ошибаются чаще, чем в самом HMAC: регистр метода, лишняя косая черта,
    `\\r\\n` вместо `\\n`. Каждая даёт `401` без подсказки.
    """
    from vscommon.signing import canonical_request

    produced = canonical_request(case["method"], case["path"], case["key_id"])

    assert produced.hex() == case["bytes_hex"]
    assert produced.decode() == case["bytes_utf8"]


def test_client_and_service_agree_on_canonical_request() -> None:
    """Две реализации канонического запроса дают одно и то же.

    У библиотеки своя копия (`_canonical`), потому что зависимости от
    `vscommon` у неё нет. Расхождение проявилось бы как `401` у интегратора и
    только на загрузке файла — на остальных ручках схема другая.
    """
    from vscommon.signing import canonical_request
    from vulnscan_client.client import _canonical

    for method, path, key_id in (
        ("POST", "/v1/scan", "acme-prod"),
        ("get", "/v1/scan/abc", "tenant-2"),
        ("GET", "/v1/scan/abc/clean", "ключ-в-юникоде"),
    ):
        assert _canonical(method, path, key_id) == canonical_request(method, path, key_id)


# --- документ и векторы не расходятся ------------------------------------


def test_document_states_the_same_numbers() -> None:
    """Числа в спецификации совпадают с векторами.

    Документ пишут руками, векторы считает код. Разойдясь, они дадут ровно то,
    против чего сам документ и написан: реализацию, сделанную по описанию и не
    проходящую проверку.
    """
    text = DOC.read_text()
    data = _data()

    assert str(data["algorithm"]["max_skew_s"]) in text, "окно расхождения часов не описано"

    for status in data["retryable_status"]["callback_response"]:
        assert str(status) in text, f"код {status} есть в векторах, но не в документе"


def test_document_matches_the_service() -> None:
    """И совпадают с кодом, а не только друг с другом."""
    from vscommon.signing import MAX_SKEW_S
    from vulnscan_client.client import MAX_SKEW_S as CLIENT_SKEW

    declared = _data()["algorithm"]["max_skew_s"]

    assert declared == MAX_SKEW_S == CLIENT_SKEW, (
        f"окно расхождения разъехалось: векторы {declared}, "
        f"сервис {MAX_SKEW_S}, библиотека {CLIENT_SKEW}"
    )


def test_safe_verdicts_agree() -> None:
    """Список безопасного один и тот же в векторах и в библиотеке.

    Он положительный намеренно: незнакомый вердикт обязан считаться
    небезопасным. Разойдясь, версии дадут разный ответ на один и тот же файл —
    и в опасную сторону.
    """
    from vulnscan_client.client import SAFE_VERDICTS

    assert set(_data()["verdicts"]["safe"]) == set(SAFE_VERDICTS)


def test_all_verdicts_are_classified() -> None:
    """Каждый вердикт сервиса разложен по одной из корзин.

    Новый вердикт, не попавший ни в одну, — это значение, о котором клиент не
    знает, что с ним делать. Тест заставляет решить это здесь, а не оставить
    на интегратора.
    """
    from vscommon.models import Verdict

    buckets = _data()["verdicts"]
    classified = {
        verdict
        for name, values in buckets.items()
        if name != "note"
        for verdict in values
    }
    known = {v.value for v in Verdict}

    assert known == classified, (
        f"не разложены по корзинам: {sorted(known - classified)}; "
        f"лишние в векторах: {sorted(classified - known)}"
    )


# --- справочник библиотеки не отстаёт от неё -----------------------------

SDK_DOC = Path(__file__).parent.parent / "docs/sdk.md"


def test_every_public_name_is_documented() -> None:
    """Всё, что библиотека экспортирует, описано в справочнике.

    Критерий M9.1 — «подключиться можно, не открывая исходники». Публичное имя,
    которого нет в документе, отправляет читателя ровно туда, откуда его хотели
    увести.
    """
    import vulnscan_client

    text = SDK_DOC.read_text()
    missing = [name for name in vulnscan_client.__all__ if name not in text]

    assert not missing, f"экспортируется, но не описано: {missing}"


def test_documented_defaults_match_the_code() -> None:
    """Значения по умолчанию в тексте совпадают с сигнатурой.

    Числа в документации устаревают тише всего: читатель верит написанному и
    узнаёт правду по поведению.
    """
    import inspect

    from vulnscan_client import VulnscanClient

    text = SDK_DOC.read_text()
    signature = inspect.signature(VulnscanClient.__init__)

    for name in ("timeout_s", "wait_ms", "retries"):
        default = signature.parameters[name].default
        assert f"{name}={default}" in text, (
            f"в документе не описано умолчание {name}={default}"
        )
