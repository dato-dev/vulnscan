"""Почему зеркало не смогло скачать базы — одной строкой в лог.

Вызывается из `entrypoint.sh`, когда `cvd update` провалился. Сам `cvdupdate`
пишет «Failed to download daily.cvd» и не говорит причины, а причины бывают
очень разные, и чинятся они разными людьми: закрытый для сети CDN, отсутствие
выхода наружу, сломанный DNS, лимит частоты. Без различия каждая из них
выглядит одинаково — пустой каталог и 404 для clamd.

Так и вышло при выкате в Kubernetes: версии баз зеркало узнавало (TXT-запрос
идёт к своему резолверу), скачивание проваливалось мгновенно, и причину
искали по сетевым политикам, которые к тому моменту были сняты.

Только стандартная библиотека: образ собран на alpine вокруг чужой утилиты.
Адрес прокси в лог не попадает — в нём бывают логин и пароль; пишется лишь
факт, что прокси задан.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

URL = "https://database.clamav.net/daily.cvd"
TIMEOUT_S = 15.0


def classify(error: BaseException | None, status: int | None = None) -> str:
    """Причина по исключению или коду ответа. Чистая функция — ради тестов."""
    if error is None and status is not None and status < 400:
        return (
            f"CDN доступен (HTTP {status}): сеть в порядке, причину надо искать "
            "в выводе cvdupdate выше"
        )
    if isinstance(error, urllib.error.HTTPError):
        status = error.code
    if status == 403:
        return (
            "CDN ClamAV отказал в доступе (HTTP 403). Так он отвечает на запросы "
            "из закрытых для него стран и сетей: с этого адреса базы не получить "
            "ни при каких настройках кластера. Нужен выход через другую сеть "
            "(прокси) либо другой источник баз"
        )
    if status == 429:
        return (
            "CDN ограничил частоту (HTTP 429). Бан обычно суточный; частые "
            "перезапуски зеркала его продлевают"
        )
    if status is not None:
        return f"CDN ответил HTTP {status}"

    reason = getattr(error, "reason", error)
    if isinstance(reason, socket.gaierror):
        return (
            "имя database.clamav.net не разрешается: DNS недоступен или не "
            "отвечает на внешние имена"
        )
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return (
            f"нет ответа за {TIMEOUT_S:.0f} с: выход наружу закрыт — сетевой "
            "политикой, файрволом или отсутствием маршрута"
        )
    if isinstance(reason, ConnectionRefusedError):
        return "соединение отвергнуто: что-то на пути закрывает порт 443"
    return f"сетевая ошибка: {type(reason).__name__}"


def main() -> int:
    # Как экспортёр рядом: образ не тянет общий код, настройка своя.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    proxy = bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"))
    request = urllib.request.Request(URL, method="HEAD")
    try:
        # S310: адрес — константа выше, со схемой https; ничего извне сюда
        # не подставляется.
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:  # noqa: S310
            verdict = classify(None, response.status)
    except Exception as exc:
        # Любое исключение — задача ровно в том, чтобы назвать причину.
        verdict = classify(exc)

    route = "через прокси" if proxy else "напрямую, прокси не задан"
    logger.warning("проверка доступа к CDN (%s): %s", route, verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
