"""Демонстрационный сайт с формой обратной связи.

Имя файла НЕ `site.py`: так называется модуль стандартной библиотеки, и
`import site` доставал бы то один, то другой в зависимости от путей.

Показывает, как чужая команда подключается к сканеру. Здесь нет ничего, чего
не было бы в руководстве (docs/integration.md) — это оно же, но работающее.

Два способа, и сайт показывает оба:

* **через библиотеку** (`/`): браузер шлёт файл нам, мы подписываем запрос
  своим ключом и передаём сканеру. Ключ в JavaScript не положишь, а без
  подписи сканер не примет. Плата — враждебный файл на секунду оказывается
  в памяти этого процесса;
* **через наш виджет** (`/widget`): файл уходит из браузера прямо в сканер по
  одноразовому талону, этот сервер его не видит. К нам приходит только
  идентификатор проверки — и вердикт по нему мы всё равно спрашиваем у
  сканера сами, своим ключом.

Решение по вердикту у обоих способов одно (`_decide`): как файл попал в
сканер, на то, что с ним делать, не влияет.
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import sys
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from prometheus_client import Counter, Histogram, start_http_server

try:
    from vulnscan_client import (
        CleanCopy,
        ScanOutcome,
        VulnscanClient,
        VulnscanError,
        resolve_ca_file,
    )
except ImportError:
    # Запуск из репозитория, а не из образа: там пакет лежит рядом в packages/
    # и его надо показать интерпретатору. В образе он скопирован в /app и
    # находится сам — вычислять путь «на два уровня вверх» там нельзя, каталога
    # такой глубины просто нет, и получался IndexError на старте.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages"))
    from vulnscan_client import (
        CleanCopy,
        ScanOutcome,
        VulnscanClient,
        VulnscanError,
        resolve_ca_file,
    )

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("feedback-site")

# --- настройки --------------------------------------------------------------

SCANNER_URL = os.environ.get("SCANNER_URL", "")
"""Адрес сканера для вызовов сервер-серверу. Сканер в Kubernetes, сайт — на
другом сервере, так что это внешний адрес за Gateway API, по HTTPS."""

SCANNER_PUBLIC_URL = os.environ.get("SCANNER_PUBLIC_URL", "") or SCANNER_URL
"""Адрес сканера, видимый БРАУЗЕРУ посетителя, — для виджета. Обычно тот же,
что `SCANNER_URL`; отличается, если сайт ходит к сканеру по внутреннему имени."""

SCANNER_CA_FILE = os.environ.get("SCANNER_CA_FILE", "")
"""Сертификат своего центра, если TLS на входе в кластер выпущен не публичным.
Касается только вызовов сервер-серверу: браузеру посетителя этот файл не
передать, и виджет с таким сертификатом у посетителя не заработает."""

KEY_ID = os.environ.get("SCANNER_KEY_ID", "")
SECRET = os.environ.get("SCANNER_SECRET", "")
SITE_KEY = os.environ.get("SCANNER_SITE_KEY", "")
"""Публичный ключ сайта для виджета. Лежит в HTML открыто — так и задумано."""

MAX_BYTES = int(os.environ.get("MAX_UPLOAD_MB", "16")) * 1024 * 1024
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9108"))
"""Метрики — на отдельном порту, а не на порту сайта: сайт смотрит в интернет,
и `/metrics` на нём был бы открыт каждому. `0` — не отдавать вовсе."""

POLL_ATTEMPTS = 6
POLL_DELAY_S = 1.0
"""Дожидание результата опросом.

Коллбэк здесь не принимается: сайт не заводит адрес ради вебхука. Поэтому
ключу выданы пустые `callback_hosts`, и результат забирается опросом — так же,
как описано в руководстве.
"""

ACCEPT = ".pdf,.docx,.docm,.zip,.jpg,.jpeg,.png"
"""Что предлагать в диалоге выбора файла. Это подсказка браузеру, а не
проверка: прислать можно что угодно, и решает сканер."""

KEEP_COPIES = 64
KEEP_COPIES_S = 3600.0

# --- метрики ----------------------------------------------------------------

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
scanner_errors = Counter("feedback_scanner_errors_total", "Проверка не состоялась", ("kind",))

# --- клиент сканера ---------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Один клиент на процесс, а не на запрос: он держит пул соединений, и
    # новый клиент на каждый файл — новое TLS-рукопожатие с кластером.
    #
    # `trace_context` здесь не передаётся: пример намеренно не тянет
    # OpenTelemetry — библиотека обязана работать с одним httpx. Команда,
    # которая трассировку ведёт, передаёт сюда функцию, возвращающую свой
    # текущий `traceparent`, и её трейс продолжится на стороне сервиса.
    try:
        verify = resolve_ca_file(SCANNER_CA_FILE)
    except ValueError as exc:
        # Отказ на старте, а не «работаем без своего центра»: иначе каждая
        # проверка падала бы на TLS, и посетители видели бы «попробуйте позже»
        # по причине, которая в логе выглядит как недоступный сканер.
        logger.error("сертификат своего центра не годится: %s", exc)
        raise
    logger.info(
        "TLS к сканеру: %s", "свой центр" if verify is not True else "системные центры"
    )
    client = VulnscanClient(
        base_url=SCANNER_URL,
        key_id=KEY_ID,
        secret=SECRET,
        wait_ms=5000,
        verify=verify,
    )
    app.state.scanner = client
    if METRICS_PORT:
        start_http_server(METRICS_PORT)
    missing = [n for n, v in (("SCANNER_URL", SCANNER_URL), ("SCANNER_KEY_ID", KEY_ID),
                              ("SCANNER_SECRET", SECRET)) if not v]  # fmt: skip
    if missing:
        logger.error("не заданы переменные: %s — проверка вложений работать не будет", missing)
    try:
        yield
    finally:
        await client.close()


app = FastAPI(title="Обратная связь", docs_url=None, redoc_url=None, lifespan=lifespan)


def scanner(request: Request) -> VulnscanClient:
    """Зависимость, а не глобальная переменная: в тестах её подменяют."""
    client: VulnscanClient = request.app.state.scanner
    return client


@app.middleware("http")
async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Предел размера — до разбора формы, и заголовки безопасности.

    FastAPI разбирает multipart целиком до вызова обработчика, и проверка
    размера внутри него случается, когда файл уже лежит у нас на диске.
    `Content-Length` честные браузеры присылают всегда; кто пришлёт огромный
    поток без него, упрётся в предел внутри обработчика.
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BYTES + 64 * 1024:
        uploads.labels(outcome="too_large").inc()
        response: Response = HTMLResponse(
            PAGE.format(accept=ACCEPT, limit=_limit(), result=_box("warn", _too_big())),
            status_code=413,
        )
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# --- страницы ---------------------------------------------------------------

STYLE = """<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; max-width: 40rem; margin: 3rem auto;
         padding: 0 1.5rem; line-height: 1.6; }}
  h1 {{ font-size: 1.6rem; margin-bottom: .3rem; }}
  .sub {{ color: #666; margin-top: 0; }}
  nav {{ font-size: .9rem; margin-bottom: 1.5rem; }}
  label {{ display: block; margin-top: 1.1rem; font-weight: 600; font-size: .9rem; }}
  input, textarea {{ width: 100%; padding: .55rem; font: inherit;
                     border: 1px solid #bbb; border-radius: 6px; background: transparent;
                     color: inherit; box-sizing: border-box; }}
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
</style>"""

PAGE = (
    """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Обратная связь</title>
"""
    + STYLE
    + """
<nav>Через библиотеку · <a href="/widget">через виджет</a></nav>
<h1>Напишите нам</h1>
<p class="sub">Можно приложить PDF, документ Word, фото или ZIP-архив с ними — до {limit} МБ.</p>

<form method="post" action="/feedback" enctype="multipart/form-data" id="f">
  <label>Ваше имя<input name="name" required maxlength="80"></label>
  <label>Сообщение<textarea name="message" required maxlength="2000"></textarea></label>
  <label>Вложение<input type="file" name="attachment" accept="{accept}"></label>
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
)


@app.get("/", response_class=HTMLResponse)
async def form() -> str:
    return PAGE.format(accept=ACCEPT, limit=_limit(), result="")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Жив ли сам сайт. Сканер здесь не спрашивается: его недоступность —
    не повод перезапускать сайт, форма честно скажет «попробуйте позже»."""
    return {"status": "ok"}


@app.post("/feedback", response_class=HTMLResponse)
async def submit(
    name: str = Form(...),
    message: str = Form(...),
    attachment: UploadFile | None = File(default=None),
    client: VulnscanClient = Depends(scanner),
) -> str:
    """Способ первый: файл проходит через наш сервер, проверяем библиотекой."""
    who = html.escape(name[:80])
    page = lambda box: PAGE.format(accept=ACCEPT, limit=_limit(), result=box)  # noqa: E731

    if attachment is None or not attachment.filename:
        return page(_box("ok", f"Спасибо, {who}! Сообщение принято."))

    content = await attachment.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        uploads.labels(outcome="too_large").inc()
        return page(_box("warn", _too_big()))

    started = time.monotonic()
    try:
        outcome = await client.scan(
            content,
            filename=attachment.filename,
            # Заявленный браузером тип — только подсказка: сканер определяет
            # тип по содержимому и расхождение считает признаком.
            content_type=attachment.content_type or "application/octet-stream",
        )
    except VulnscanError as exc:
        # Проверка не состоялась. Принимать непроверенный файл нельзя: это
        # оставляет без защиты ровно тогда, когда что-то уже пошло не так.
        logger.warning("сканер недоступен: %s", type(exc).__name__)
        # Тип исключения, а не текст: текст может содержать адрес и параметры,
        # а метка обязана быть из закрытого списка.
        scanner_errors.labels(kind=type(exc).__name__).inc()
        uploads.labels(outcome="unchecked").inc()
        return page(_box("warn", "Не смогли проверить вложение. Попробуйте чуть позже."))
    finally:
        del content  # оригинал нам не нужен и не хранится

    # Проверка могла не уложиться в отведённое время. Это НЕ повод показывать
    # посетителю «файл вызвал вопросы»: «не закончили» и «подозрительный» —
    # разные вещи, и путать их так же скверно, как считать непроверенное чистым.
    if outcome.pending:
        outcome = await _await_result(client, outcome.scan_id) or outcome
    wait_seconds.observe(time.monotonic() - started)

    return page(await _decide(client, outcome, who))


async def _await_result(client: VulnscanClient, scan_id: str) -> ScanOutcome | None:
    """Опрос до готовности. Возвращает `None`, если так и не дождались."""
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


async def _decide(client: VulnscanClient, outcome: ScanOutcome, who: str) -> str:
    """Что сказать посетителю. Одно решение на оба способа загрузки.

    Три состояния, и среднее — самое важное. `not blocked` НЕ означает
    «безопасно»: файл, который не удалось проверить, не заблокирован, но и
    чистым не является. Проверка `if not blocked` молча приняла бы
    зашифрованный архив как безобидный.

    Принимается всегда пересобранная копия, а не присланный файл, — даже
    чистый: копия собрана заново, без активных элементов, и это работает
    против того, чего мы ещё не умеем детектить.
    """
    meta = (
        f'<p class="meta">Идентификатор проверки: <code>{html.escape(outcome.scan_id)}</code></p>'
    )

    if outcome.pending:
        uploads.labels(outcome="pending").inc()
        return _box(
            "warn",
            "Вложение ещё проверяется — большие файлы занимают время. "
            "Отправьте форму повторно через минуту." + meta,
        )

    # Вердикт как метка допустим: список закрыт и задан сервисом. Ни имя файла,
    # ни идентификатор скана в метки не попадают — это был бы ряд на посетителя.
    uploads.labels(outcome=outcome.verdict or "unknown").inc()

    if outcome.blocked:
        reasons = ", ".join(html.escape(str(f.get("code", ""))) for f in outcome.findings[:4])
        return _box(
            "bad",
            "Вложение отклонено: в нём нашлось активное содержимое."
            + (f"<br><small>Признаки: {reasons}</small>" if reasons else "")
            + meta,
        )

    if outcome.unscannable:
        return _box(
            "warn",
            "Вложение не удалось проверить — возможно, оно защищено паролем или "
            "в неподдерживаемом формате. Пришлите PDF, документ Word, фото или "
            "ZIP-архив с ними." + meta,
        )

    copy = await _fetch_clean(client, outcome) if outcome.sanitized else None
    if copy is None:
        # Незнакомый вердикт, сбой пересборки или копия не скачалась. Принять
        # нечего: оригинал мы не берём, а копии нет.
        return _box(
            "warn",
            "Не получилось подготовить безопасную копию вложения. Попробуйте "
            "отправить форму ещё раз чуть позже." + meta,
        )
    link = f'<br><a href="/clean/{html.escape(outcome.scan_id)}">Скачать безопасную копию</a>'

    if not outcome.safe:
        # Серая зона. Копию принимаем и здесь: она собрана заново, без
        # активных элементов, и это ровно тот случай, ради которого пересборка
        # и нужна. Не принимать её значило бы наказывать посетителя за то, что
        # файл показался подозрительным.
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


# --- пересобранные копии ----------------------------------------------------

_clean_files: OrderedDict[str, tuple[float, CleanCopy]] = OrderedDict()
"""Витрина, а не хранилище: последние копии в памяти процесса, с пределом по
числу и по времени. Без предела поток вложений съел бы память сайта. В
настоящей интеграции копия уезжает в ваше хранилище — например, доставкой
сканера прямо в S3 (M14), и тогда скачивать её не нужно вовсе."""


async def _fetch_clean(client: VulnscanClient, outcome: ScanOutcome) -> CleanCopy | None:
    try:
        copy = await client.download_clean_copy(outcome.scan_id)
    except VulnscanError:
        logger.warning("не удалось забрать обезвреженную копию")
        return None
    now = time.monotonic()
    _clean_files[outcome.scan_id] = (now, copy)
    _clean_files.move_to_end(outcome.scan_id)
    while len(_clean_files) > KEEP_COPIES:
        _clean_files.popitem(last=False)
    for scan_id in [s for s, (at, _) in _clean_files.items() if now - at > KEEP_COPIES_S]:
        del _clean_files[scan_id]
    return copy


@app.get("/clean/{scan_id}")
async def clean(scan_id: str) -> Response:
    """Пересобранная копия. Именно она и есть смысл всей затеи.

    Тип и имя — те, что назвал сканер: копия GIF — это PNG, а документ,
    пересобранный профилем `strict`, может быть другого вида, чем исходник.
    """
    item = _clean_files.get(scan_id)
    if item is None or time.monotonic() - item[0] > KEEP_COPIES_S:
        return Response("не найдено", status_code=404)
    copy = item[1]
    return Response(
        copy.content,
        media_type=copy.content_type,
        headers={"Content-Disposition": f'attachment; filename="{copy.filename}"'},
    )


# --- способ второй: наш виджет ----------------------------------------------

WIDGET_PAGE = (
    """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Обратная связь через виджет</title>
"""
    + STYLE
    + """
<nav><a href="/">Через библиотеку</a> · через виджет</nav>
<h1>Напишите нам</h1>
<p class="sub">Вложение проверяется виджетом: файл идёт прямо в сканер, наш сервер
его не видит.</p>

<form method="post" action="/widget-feedback">
  <label>Ваше имя<input name="name" required maxlength="80"></label>
  <label>Сообщение<textarea name="message" required maxlength="2000"></textarea></label>

  <label>Вложение</label>
  <!-- Вся интеграция — этот блок и один скрипт. Оформление задаётся
       атрибутами: сервис принимает только известные переменные и только
       проверенные значения, поэтому чужой CSS сюда не попадает. -->
  <div data-vulnscan-key="{site_key}"
       data-vulnscan-accent="#2f4f82"
       data-vulnscan-radius="6px"
       data-vulnscan-size="15px"></div>
  <script src="{scanner}/widget/v1/loader.js" async></script>

  <button type="submit">Отправить</button>
</form>
{result}
"""
)


def _widget_page(box: str) -> str:
    return WIDGET_PAGE.format(
        site_key=html.escape(SITE_KEY), scanner=html.escape(SCANNER_PUBLIC_URL), result=box
    )


@app.get("/widget", response_class=HTMLResponse)
async def widget_form() -> str:
    """Вторая форма — через виджет, для сравнения с первой.

    Разница видна по коду: здесь нет ни чтения файла, ни отправки его в
    сканер. Файл уходит из браузера прямо в сканер, минуя этот сервер.
    """
    if not SITE_KEY:
        return "<p>Задайте SCANNER_SITE_KEY — публичный ключ сайта.</p>"
    return _widget_page("")


@app.post("/widget-feedback", response_class=HTMLResponse)
async def widget_submit(
    name: str = Form(...),
    message: str = Form(...),
    vulnscan_scan_id: str = Form(""),
    vulnscan_state: str = Form(""),
    client: VulnscanClient = Depends(scanner),
) -> str:
    """Приём формы от виджета.

    ГЛАВНОЕ ЗДЕСЬ — вердикт запрашивается у сканера **своим ключом**. Всё, что
    пришло в полях формы, включая `vulnscan_state` и сам идентификатор,
    написал браузер посетителя: он отправит что угодно.

    Поля из формы годятся ровно на одно — объяснить посетителю, что случилось,
    когда вложения нет. Решение принимается по ответу сканера, тем же
    `_decide`, что и у первой формы.
    """
    who = html.escape(name[:80])

    if not vulnscan_scan_id:
        # Вложения нет. Почему — подскажет состояние, но верить ему можно
        # только для текста сообщения.
        excuse = {
            "blocked": "Вложение заблокировано проверкой.",
            "unchecked": "Вложение не удалось проверить.",
            "busy": "Проверка ещё не закончилась.",
        }.get(vulnscan_state, "Сообщение принято без вложения.")
        return _widget_page(
            _box("ok" if not vulnscan_state else "warn", f"Спасибо, {who}! {excuse}")
        )

    try:
        outcome = await client.result(vulnscan_scan_id)
    except VulnscanError:
        logger.warning("сканер недоступен на проверке результата")
        uploads.labels(outcome="unchecked").inc()
        return _widget_page(
            _box("warn", "Не смогли подтвердить проверку вложения. Попробуйте позже.")
        )

    if outcome is None:
        # Идентификатор не наш или устарел. Ровно то, что придёт, если его
        # подобрали или подставили руками: чужой тенант получает `None`, а не
        # чужой вердикт.
        logger.warning("предъявлен неизвестный scan_id")
        return _widget_page(_box("bad", "Вложение не найдено. Приложите файл заново."))

    if outcome.pending:
        outcome = await _await_result(client, outcome.scan_id) or outcome
    return _widget_page(await _decide(client, outcome, who))


def _box(kind: str, text: str) -> str:
    return f'<div class="box {kind}">{text}</div>'


def _limit() -> int:
    return MAX_BYTES // (1024 * 1024)


def _too_big() -> str:
    return f"Файл больше {_limit()} МБ — пришлите поменьше."
