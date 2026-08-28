"""HMAC-подпись запросов к API и исходящих коллбэков."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from enum import StrEnum

SIGNATURE_HEADER = "X-Vulnscan-Signature"
TIMESTAMP_HEADER = "X-Vulnscan-Timestamp"
MAX_SKEW_S = 300


def canonical_request(method: str, path: str, key_id: str) -> bytes:
    """Что подписывается, когда тело подписать нельзя.

    Загрузка файла приходит как multipart: подписать её тело можно только
    прочитав его, а читать тело до аутентификации нельзя — тогда нагрузка уже
    принята и проверка частоты теряет смысл. Целостность обеспечивает TLS,
    подпись доказывает отправителя.

    Путь входит намеренно: без него подпись, снятая с одной ручки, годилась бы
    для любой другой в пределах окна времени.

    Живёт здесь, а не в gateway: это деталь протокола, и обе стороны обязаны
    строить строку одинаково. Копия на стороне клиента разошлась бы молча, а
    выглядело бы это как неверный ключ.
    """
    return f"{method.upper()}\n{path}\n{key_id}".encode()


def sign(secret: str, body: bytes, timestamp: int | None = None) -> tuple[str, str]:
    """Возвращает (timestamp, signature). Подписывается `ts.body`."""
    ts = str(timestamp if timestamp is not None else int(time.time()))
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256)
    return ts, f"sha256={mac.hexdigest()}"


class Rejection(StrEnum):
    """Почему подпись не принята.

    Наружу причина не уходит — клиенту незачем знать, ключа нет или подпись не
    сошлась. Но в лог она обязана попадать: без неё расхождение часов между
    площадками выглядит как неверный ключ, и разбираться можно часами.
    """

    OK = "ok"
    MALFORMED = "malformed"
    SKEW = "skew"
    MISMATCH = "mismatch"


@dataclass(frozen=True, slots=True)
class SignatureCheck:
    reason: Rejection
    skew_s: int | None = None

    @property
    def ok(self) -> bool:
        return self.reason is Rejection.OK


def check_signature(secret: str, body: bytes, timestamp: str, signature: str) -> SignatureCheck:
    """Проверка подписи с объяснением отказа."""
    try:
        skew = abs(int(time.time()) - int(timestamp))
    except ValueError:
        return SignatureCheck(Rejection.MALFORMED)
    if skew > MAX_SKEW_S:
        return SignatureCheck(Rejection.SKEW, skew_s=skew)

    _, expected = sign(secret, body, int(timestamp))
    try:
        candidate = signature.encode("ascii")
    except UnicodeEncodeError:
        return SignatureCheck(Rejection.MALFORMED)
    if not hmac.compare_digest(expected.encode("ascii"), candidate):
        return SignatureCheck(Rejection.MISMATCH, skew_s=skew)
    return SignatureCheck(Rejection.OK, skew_s=skew)


def verify(secret: str, body: bytes, timestamp: str, signature: str) -> bool:
    """Проверка подписи с защитой от replay по окну MAX_SKEW_S."""
    try:
        skew = abs(int(time.time()) - int(timestamp))
    except ValueError:
        return False
    if skew > MAX_SKEW_S:
        return False
    _, expected = sign(secret, body, int(timestamp))
    # Сравниваем байтами: `compare_digest` на строках с не-ASCII символами
    # бросает TypeError, и подпись с кириллицей в заголовке давала бы 500
    # вместо честного 401 — необработанное исключение прямо в аутентификации.
    try:
        candidate = signature.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(expected.encode("ascii"), candidate)
