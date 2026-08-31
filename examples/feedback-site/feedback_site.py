"""Демонстрационный сайт с формой обратной связи.

Имя файла НЕ `site.py`: так называется модуль стандартной библиотеки, и
`import site` доставал бы то один, то другой в зависимости от путей.

Показывает, как чужая команда подключается к сканеру. Здесь нет ничего, чего
не было бы в руководстве (docs/integration.md) — это оно же, но работающее.

Устройство намеренно простое: браузер шлёт файл нам, мы подписываем запрос
своим ключом и передаём сканеру. Иначе никак — ключ в JavaScript не положишь,
а без подписи сканер не примет.

Плата за простоту: враждебный файл на секунду оказывается в памяти этого
процесса. Для демонстрации приемлемо; в бою стоит смотреть в сторону
одноразовых талонов на загрузку, чтобы файл шёл сразу в сканер.
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import sys
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

try:
    from vulnscan_client import VulnscanClient, VulnscanError
except ImportError:
    # Запуск из репозитория, а не из образа: там пакет лежит рядом в packages/
    # и его надо показать интерпретатору. В образе он скопирован в /app и
    # находится сам — вычислять путь «на два уровня вверх» там нельзя, каталога
    # такой глубины просто нет, и получался IndexError на старте.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages"))
    from vulnscan_client import VulnscanClient, VulnscanError

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("feedback-site")

SCANNER_URL = os.environ.get("SCANNER_URL", "http://gateway:8080")
KEY_ID = os.environ.get("SCANNER_KEY_ID", "")
SECRET = os.environ.get("SCANNER_SECRET", "")

MAX_BYTES = 16 * 1024 * 1024

POLL_ATTEMPTS = 6
POLL_DELAY_S = 1.0
"""Дожидание результата опросом.

Коллбэк здесь не принимается: у сайта нет публичного адреса, а заводить его
ради демонстрации незачем. Поэтому ключу выданы пустые `callback_hosts`, и
результат забирается опросом — так же, как описано в руководстве.
"""

app = FastAPI(title="Обратная связь", docs_url=None, redoc_url=None)

# M10.10. Метрики стороны, которая подключается, а не сервиса. Префикс свой,
# не `vs_`: `vs_` принадлежит коду сканера, здесь же измеряется поведение
# клиента — то, что увидела бы у себя подключающаяся команда.
#
# Вопрос, на который они отвечают, ровно один: что происходит с посетителем,
# приложившим файл. Сколько ждал, чем кончилось, и как часто вместо ответа он
# получает «попробуйте позже», потому что проверка не состоялась. Последнее
# особенно важно: отказ проверки — это не ошибка сайта и в его собственных
# метриках ошибок HTTP не виден вовсе.
uploads = Counter("feedback_uploads_total", "Вложения по исходу проверки", ("outcome",))
wait_seconds = Histogram(
    "feedback_scan_wait_seconds",
    "Сколько посетитель ждал вердикта",
    buckets=(0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0),
)
scanner_errors = Counter(
    "feedback_scanner_errors_total", "Проверка не состоялась", ("kind",)
)

# Обезвреженные копии живут в памяти процесса до перезапуска: это витрина,
# а не хранилище. Оригиналы не сохраняются вообще.
_clean_files: dict[str, tuple[bytes, str]] = {}


def _client() -> VulnscanClient:
    # `trace_context` здесь не передаётся: пример намеренно не тянет
    # OpenTelemetry — библиотека обязана работать с одним httpx. Команда,
    # которая трассировку ведёт, передаёт сюда функцию, возвращающую свой
    # текущий `traceparent`, и её трейс продолжится на стороне сервиса.
    return VulnscanClient(base_url=SCANNER_URL, key_id=KEY_ID, secret=SECRET, wait_ms=5000)


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>Обратная связь</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto;
         padding: 0 1.5rem; line-height: 1.6; }}
  h1 {{ font-size: 1.6rem; margin-bottom: .3rem; }}
  .sub {{ color: #666; margin-top: 0; }}
  label {{ display: block; margin-top: 1.1rem; font-weight: 600; font-size: .9rem; }}
  input, textarea {{ width: 100%; padding: .55rem; font: inherit;
                     border: 1px solid #bbb; border-radius: 6px; background: transparent;
                     color: inherit; }}
  textarea {{ min-height: 6rem; }}
  button {{ margin-top: 1.4rem; padding: .6rem 1.4rem; font: inherit; font-weight: 600;
            border: 0; border-radius: 6px; background: #2f4f82; color: #fff;
            cursor: pointer; }}
  .box {{ margin-top: 1.6rem; padding: 1rem 1.2rem; border-radius: 8px;
          border-left: 4px solid; }}
  .ok {{ border-color: #2c7256; background: #2c725618; }}
  .warn {{ border-color: #9a6b12; background: #9a6b1218; }}
  .bad {{ border-color: #a03a30; background: #a03a3018; }}
  code {{ font-size: .85em; }}
  .meta {{ color: #666; font-size: .85rem; margin-top: .6rem; }}
</style>

<h1>Напишите нам</h1>
<p class="sub">Можно приложить PDF — например, скан документа.</p>

<form method="post" action="/feedback" enctype="multipart/form-data" id="f">
  <label>Ваше имя<input name="name" required maxlength="80"></label>
  <label>Сообщение<textarea name="message" required maxlength="2000"></textarea></label>
  <label>Вложение (PDF)<input type="file" name="attachment" accept="application/pdf"></label>
  <button type="submit" id="go">Отправить</button>
</form>

<script>
  // Проверка занимает секунды, а форма всё это время выглядит так, будто
  // ничего не произошло. Без обратной связи посетитель жмёт кнопку второй раз
  // и отправляет файл дважды.
  document.getElementById('f').addEventListener('submit', function () {{
    var b = document.getElementById('go');
    b.disabled = true;
    b.textContent = 'Проверяем вложение…';
  }});
</script>

{result}
"""


@app.get("/", response_class=HTMLResponse)
async def form() -> str:
    return PAGE.format(result="")


@app.post("/feedback", response_class=HTMLResponse)
async def submit(
    name: str = Form(...),
    message: str = Form(...),
    attachment: UploadFile | None = File(default=None),
) -> str:
    who = html.escape(name[:80])

    if attachment is None or not attachment.filename:
        return PAGE.format(result=_box("ok", f"Спасибо, {who}! Сообщение принято."))

    content = await attachment.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        uploads.labels(outcome="too_large").inc()
        return PAGE.format(result=_box("warn", "Файл больше 16 МБ — пришлите поменьше."))

    started = time.monotonic()
    try:
        async with _client() as client:
            outcome = await client.scan(
                content, filename=attachment.filename, content_type="application/pdf"
            )
    except VulnscanError as exc:
        # Проверка не состоялась. Принимать непроверенный файл нельзя: это
        # оставляет без защиты ровно тогда, когда что-то уже пошло не так.
        logger.warning("сканер недоступен: %s", type(exc).__name__)
        # Тип исключения, а не текст: текст может содержать адрес и параметры,
        # а метка обязана быть из закрытого списка.
        scanner_errors.labels(kind=type(exc).__name__).inc()
        uploads.labels(outcome="unchecked").inc()
        return PAGE.format(
            result=_box("warn", "Не смогли проверить вложение. Попробуйте чуть позже.")
        )

    # Проверка могла не уложиться в отведённое время. Это НЕ повод показывать
    # посетителю «файл вызвал вопросы»: «не закончили» и «подозрительный» —
    # разные вещи, и путать их так же скверно, как считать непроверенное чистым.
    if outcome.pending:
        outcome = await _await_result(outcome.scan_id) or outcome

    wait_seconds.observe(time.monotonic() - started)

    if outcome.pending:
        uploads.labels(outcome="pending").inc()
        return PAGE.format(
            result=_box(
                "warn",
                "Вложение ещё проверяется — большие файлы занимают время. "
                "Отправьте форму повторно через минуту.",
            )
        )

    # Вердикт как метка допустим: список закрыт и задан сервисом. Ни имя файла,
    # ни идентификатор скана в метки не попадают — это был бы ряд на посетителя.
    uploads.labels(outcome=outcome.verdict).inc()
    return PAGE.format(result=await _decide(outcome, who))


async def _await_result(scan_id: str):
    """Опрос до готовности. Возвращает `None`, если так и не дождались."""
    async with _client() as client:
        for _attempt in range(POLL_ATTEMPTS):
            await asyncio.sleep(POLL_DELAY_S)
            try:
                outcome = await client.result(scan_id)
            except VulnscanError:
                return None
            if outcome is not None and not outcome.pending:
                return outcome
    logger.info("проверка не завершилась за отведённое время")
    return None


async def _decide(outcome: object, who: str) -> str:
    """Три состояния, и среднее — самое важное.

    `not blocked` НЕ означает «безопасно»: файл, который не удалось проверить,
    не заблокирован, но и чистым не является. Проверка `if not blocked`
    молча приняла бы зашифрованный архив как безобидный.
    """
    scan_id = outcome.scan_id  # type: ignore[attr-defined]
    meta = f'<p class="meta">Идентификатор проверки: <code>{html.escape(scan_id)}</code></p>'

    if outcome.blocked:  # type: ignore[attr-defined]
        reasons = ", ".join(
            html.escape(f["code"])
            for f in outcome.findings[:4]  # type: ignore[attr-defined]
        )
        return _box(
            "bad",
            "Вложение отклонено: в нём нашлось активное содержимое."
            + (f"<br><small>Признаки: {reasons}</small>" if reasons else "")
            + meta,
        )

    if outcome.unscannable:  # type: ignore[attr-defined]
        return _box(
            "warn",
            "Вложение не удалось проверить — возможно, оно зашифровано или "
            "в неподдерживаемом формате. Пришлите обычный PDF." + meta,
        )

    link = await _fetch_clean(outcome)

    if not outcome.safe:  # type: ignore[attr-defined]
        # Серая зона и незнакомые вердикты. Копию отдаём и здесь: она собрана
        # заново, без активных элементов, и это ровно тот случай, ради которого
        # пересборка и нужна. Не отдавать её значило бы наказывать посетителя
        # за то, что файл показался подозрительным.
        return _box(
            "warn",
            f"Спасибо, {who}! Вложение вызвало вопросы — мы приняли его "
            "пересобранную копию и посмотрим внимательнее." + link + meta,
        )

    return _box(
        "ok",
        f"Спасибо, {who}! Вложение проверено и обезврежено — "
        "мы работаем с пересобранной копией, а не с вашим файлом." + link + meta,
    )


async def _fetch_clean(outcome: object) -> str:
    """Забирает пересобранную копию, если она есть.

    Копия — то, ради чего всё и затевалось, поэтому она отдаётся и для чистых,
    и для подозрительных. Не отдаётся только для заблокированных: там
    пересобирать нечего, сервис их и не пересобирает.
    """
    if not outcome.sanitized:  # type: ignore[attr-defined]
        return ""
    scan_id = outcome.scan_id  # type: ignore[attr-defined]
    try:
        async with _client() as client:
            clean = await client.download_clean(scan_id)
    except VulnscanError:
        logger.warning("не удалось забрать обезвреженную копию")
        return ""
    _clean_files[scan_id] = (clean, "application/pdf")
    return f'<br><a href="/clean/{html.escape(scan_id)}">Скачать безопасную копию</a>'


@app.get("/metrics")
async def metrics_endpoint() -> Response:
    """Отдельного порта нет: у сайта уже есть свой HTTP, и заводить второй
    ради четырёх метрик незачем. У сервисов сканера порт отдельный по другой
    причине — у воркера и бота своего HTTP нет вовсе.
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/clean/{scan_id}")
async def clean(scan_id: str) -> Response:
    """Пересобранная копия. Именно она и есть смысл всей затеи.

    Даже для чистого файла отдаётся копия, а не оригинал: она собрана заново,
    без активных элементов, и это работает против того, чего мы ещё не умеем
    детектить.
    """
    item = _clean_files.get(scan_id)
    if item is None:
        return Response("не найдено", status_code=404)
    body, content_type = item
    return Response(
        body,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="clean-{scan_id[:8]}.pdf"'},
    )


def _box(kind: str, text: str) -> str:
    return f'<div class="box {kind}">{text}</div>'
