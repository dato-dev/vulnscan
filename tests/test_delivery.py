"""M14.1 и M14.3: копия уезжает в хранилище клиента, решение видно в ящике.

Два свойства проверяются здесь, и второе важнее первого.

**Выгрузка идёт из notifier.** У воркера нет сетевого выхода наружу; выгрузка
оттуда разобрала бы периметр, ради которого он и заперт. Воркер только ставит
задание.

**Приёмник отвечает на вопрос «что стало с документом».** Пустой ящик означает
одновременно «файл заблокирован», «ещё в работе» и «сервис сломался».
Различить это по содержимому невозможно, поэтому рядом с каждым файлом уезжает
манифест — и он же уезжает вместо файла, когда выгружать нечего.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from notifierapp.dropoff import MANIFEST_SUFFIX, DropoffError, manifest_for
from notifierapp.main import Notifier
from vscommon.delivery import Delivery, DeliveryCredentials
from vscommon.models import (
    CdrProfile,
    DeadLetterReason,
    DeliveryTask,
    Finding,
    ObjectRef,
    SanitizedArtifact,
    ScanResult,
    ScanStatus,
    Severity,
    TenantPolicy,
    Verdict,
)

SHA = "a" * 64
DESTINATION = Delivery(bucket="incoming-clean", prefix="vulnscan/", credentials_id="drop")
CREDENTIALS = DeliveryCredentials(access_key="AKIA", secret_key="s" * 32)


def _result(verdict: Verdict = Verdict.CLEAN, sanitized: bool = True) -> ScanResult:
    return ScanResult(
        scan_id="01J-скан",
        sha256=SHA,
        status=ScanStatus.DONE,
        verdict=verdict,
        score=0 if verdict is Verdict.CLEAN else 95,
        findings=[Finding(stage="yara", code="YARA_PDF_LAUNCH", severity=Severity.CRITICAL)]
        if verdict is not Verdict.CLEAN
        else [],
        sanitized=SanitizedArtifact(
            ref=ObjectRef(bucket="vulnscan-clean", key="ab/clean.pdf"),
            profile=CdrProfile.STANDARD,
            original_sha256=SHA,
            sanitized_sha256="b" * 64,
        )
        if sanitized
        else None,
    )


def _task(result: ScanResult, name: str = "01J-скан.pdf") -> DeliveryTask:
    return DeliveryTask(
        scan_id=result.scan_id,
        tenant="team-a",
        destination=DESTINATION,
        artifact=result.sanitized.ref if result.sanitized else None,
        name=name,
        payload=result.model_dump_json(),
    )


# --- манифест --------------------------------------------------------------


def test_manifest_says_whether_the_file_is_there() -> None:
    """Главный вопрос ящика: файл рядом есть или его не будет.

    Выводить это из наличия соседнего объекта нельзя — «объекта нет» означает
    и «не прошёл проверку», и «выгрузка ещё идёт».
    """
    delivered = manifest_for(_result().model_dump_json(), "doc.pdf", delivered=True)
    refused = manifest_for(
        _result(Verdict.MALICIOUS, sanitized=False).model_dump_json(), "doc.pdf", delivered=False
    )

    assert delivered["delivered"] is True
    assert delivered["object"] == "doc.pdf"
    assert refused["delivered"] is False
    assert refused["object"] is None, "файла не будет — ссылаться не на что"


def test_manifest_explains_the_refusal() -> None:
    """Отказ без причины оставляет владельца документа гадать.

    Коды признаков — часть публичного контракта, и по ним видно, что именно
    нашли: `YARA_PDF_LAUNCH` объясняет отказ, «не прошёл» — нет.
    """
    manifest = manifest_for(
        _result(Verdict.MALICIOUS, sanitized=False).model_dump_json(), "doc.pdf", delivered=False
    )

    assert manifest["verdict"] == "malicious"
    assert [item["code"] for item in manifest["findings"]] == ["YARA_PDF_LAUNCH"]


def test_manifest_distinguishes_clean_from_suspicious() -> None:
    """Подозрительный файл тоже отдаётся — решение принимает клиент.

    Без манифеста чистый и подозрительный документы в ящике неразличимы, и
    разделение «сервис детектит, клиент решает» превращается в фикцию.
    """
    manifest = manifest_for(_result(Verdict.SUSPICIOUS).model_dump_json(), "doc.pdf", True)

    assert manifest["verdict"] == "suspicious"
    assert manifest["delivered"] is True


def test_manifest_carries_no_file_content() -> None:
    """В ящик клиента уезжает решение о документе, а не документ повторно."""
    manifest = manifest_for(_result().model_dump_json(), "doc.pdf", True)
    flat = json.dumps(manifest, ensure_ascii=False)

    assert "content" not in manifest
    assert "%PDF" not in flat


def test_manifest_survives_a_broken_payload() -> None:
    """Битый результат не должен оставлять ящик совсем пустым.

    Манифест с `verdict: unknown` хуже полного, но несравнимо лучше молчания:
    по нему видно, что решение принималось и что-то пошло не так.
    """
    manifest = manifest_for("не json", "doc.pdf", delivered=False)

    assert manifest["verdict"] == "unknown"
    assert manifest["delivered"] is False


def test_manifest_is_versioned() -> None:
    """Формат читают чужие скрипты. Молчаливая смена структуры их сломает."""
    assert manifest_for(_result().model_dump_json(), "doc.pdf", True)["manifest_version"] == 1


# --- выгрузка --------------------------------------------------------------


class _FakeS3:
    """boto3 нам в тестах не нужен: важен порядок и содержание вызовов."""

    def __init__(self, fail_on: str = "") -> None:
        self.uploaded: list[tuple[str, str]] = []
        self.objects: dict[str, bytes] = {}
        self.calls: list[str] = []
        self._fail_on = fail_on

    def upload_fileobj(self, stream: Any, bucket: str, key: str, ExtraArgs: dict) -> None:  # noqa: N803
        self.calls.append("file")
        if self._fail_on == "file":
            raise RuntimeError("приёмник недоступен")
        self.uploaded.append((bucket, key))
        self.objects[key] = stream.read()

    def put_object(self, Bucket: str, Key: str, Body: bytes, ContentType: str) -> None:  # noqa: N803
        self.calls.append("manifest")
        if self._fail_on == "manifest":
            raise RuntimeError("приёмник недоступен")
        self.objects[Key] = Body


@pytest.fixture()
def dropoff(monkeypatch: pytest.MonkeyPatch):
    """`Dropoff` с подменённым клиентом S3."""
    from notifierapp import dropoff as module

    def _make(fail_on: str = ""):
        fake = _FakeS3(fail_on)
        instance = object.__new__(module.Dropoff)
        instance._destination = DESTINATION
        instance._client = fake
        return instance, fake

    return _make


def test_file_lands_under_the_prefix(dropoff, tmp_path: Path) -> None:
    """Префикс на тенанта ограничивает, куда можно писать (M14.4)."""
    instance, fake = dropoff()
    source = tmp_path / "clean.pdf"
    source.write_bytes(b"%PDF-1.4\n")

    key = instance.put_file(ObjectRef(bucket="b", key="k"), source, "01J.pdf")

    assert key == "vulnscan/01J.pdf"
    assert fake.uploaded == [("incoming-clean", "vulnscan/01J.pdf")]


def test_manifest_lands_beside_the_file(dropoff) -> None:
    """Рядом, а не в отдельном каталоге: иначе файл и решение о нём разведены."""
    instance, fake = dropoff()

    key = instance.put_manifest("01J.pdf", {"verdict": "clean"})

    assert key == "vulnscan/01J.pdf" + MANIFEST_SUFFIX
    assert json.loads(fake.objects[key])["verdict"] == "clean"


def test_upload_failure_is_raised_not_swallowed(dropoff, tmp_path: Path) -> None:
    """Проглоченный отказ выглядел бы как успешная выгрузка.

    Тогда файл не появился бы в ящике, а мы считали бы задание выполненным —
    то есть потеряли бы документ молча и навсегда.
    """
    instance, _fake = dropoff(fail_on="file")
    source = tmp_path / "clean.pdf"
    source.write_bytes(b"%PDF")

    with pytest.raises(DropoffError):
        instance.put_file(ObjectRef(bucket="b", key="k"), source, "01J.pdf")


# --- воркер ставит задание -------------------------------------------------


def test_worker_enqueues_only_when_configured() -> None:
    """Приёмника нет — задания нет. Это штатная работа, а не пропуск."""
    import inspect

    from worker_app.main import Worker

    source = inspect.getsource(Worker._enqueue_delivery)

    assert "policy.delivery is None" in source
    assert "return" in source


def test_worker_complains_about_a_broken_destination() -> None:
    """Негодный приёмник обязан быть слышен.

    Тенанту его настроили, значит файлов ждут — а они не придут. Молчание
    здесь неотличимо от «доставка не настраивалась».
    """
    import inspect

    from worker_app.main import Worker

    source = inspect.getsource(Worker._enqueue_delivery)

    assert "delivery_error" in source
    assert "logger.error" in source


def test_worker_does_not_upload_anything_itself() -> None:
    """У воркера нет сетевого выхода наружу — и не должно появиться.

    Выгрузка из процесса, разбирающего враждебные файлы, превратила бы дыру в
    парсере из «упал контейнер» в «есть канал наружу».
    """
    from pathlib import Path as _Path

    worker = _Path("services/worker/worker_app").rglob("*.py")
    offenders = [
        path.name
        for path in worker
        if "boto3.client" in path.read_text() or "Dropoff(" in path.read_text()
    ]

    assert not offenders, f"воркер сам ходит в чужое хранилище: {offenders}"


def test_original_filename_never_reaches_the_destination() -> None:
    """Имя объекта строится из `scan_id`, а не из имени файла.

    Имена файлов часто содержат персональные данные, и мы их не храним —
    только расширение. Сопоставить объект с обращением клиент может по
    `scan_id` из манифеста.
    """
    import inspect

    from worker_app.main import Worker

    source = inspect.getsource(Worker._enqueue_delivery)

    assert "result.scan_id}{job.filename_ext" in source


# --- отказ доставки виден --------------------------------------------------


def test_delivery_has_its_own_dead_letter_reason() -> None:
    """Невыгруженное попадает в разбор человеком, а не в пустоту.

    Отдельная причина, а не общая с коллбэком: разбирают их по-разному —
    коллбэк переотправляют, а недоступный приёмник чинит клиент.
    """
    assert DeadLetterReason.DELIVERY_FAILED.value == "delivery_failed"


def test_notifier_dead_letters_a_failed_delivery() -> None:
    import inspect

    from notifierapp.main import Notifier

    source = inspect.getsource(Notifier._delivery_failed)

    assert "DeadLetterReason.DELIVERY_FAILED" in source
    assert "logger.error" in source


def test_missing_credentials_are_not_retried() -> None:
    """Отсутствующая учётка — конфигурация, а не сетевая помеха.

    Повторять её десять раз с растущей паузой значит откладывать момент, когда
    о поломке узнают, на полчаса.
    """
    import inspect

    from notifierapp.main import Notifier

    source = inspect.getsource(Notifier._deliver)

    assert "_delivery_failed" in source
    assert "нет учётных данных" in source


def test_file_goes_before_the_manifest() -> None:
    """Манифест утверждает, что файл рядом есть.

    Появившись первым, он утверждал бы это до того, как это стало правдой, и
    читатель ящика, доверяющий манифесту, забрал бы пустоту.
    """
    import inspect

    from notifierapp.main import Notifier

    source = inspect.getsource(Notifier._put)

    assert source.index("put_file") < source.index("put_manifest")


# --- политика и приёмник ---------------------------------------------------


def test_destination_travels_in_the_task() -> None:
    """Приёмник не перечитывается при доставке.

    Решение принято политикой, действовавшей на момент проверки. Правка
    политики не должна переносить файл, который уже в пути.
    """
    task = _task(_result())

    assert task.destination.bucket == "incoming-clean"
    assert isinstance(TenantPolicy().delivery, type(None))


def test_task_without_artifact_is_still_a_task() -> None:
    """Файл не прошёл — задание всё равно ставится, ради манифеста."""
    task = _task(_result(Verdict.MALICIOUS, sanitized=False))

    assert task.artifact is None
    assert task.payload


# --- права в чужом хранилище (M14.4) ---------------------------------------

DROPOFF = Path("services/notifier/notifierapp/dropoff.py")

FORBIDDEN_CALLS = (
    "list_objects",
    "list_objects_v2",
    "delete_object",
    "delete_objects",
    "get_object",
    "download_file",
    "download_fileobj",
    "head_object",
    "head_bucket",
    "create_bucket",
    "generate_presigned_url",
)
"""Чего наш код в чужом хранилище делать не должен.

Не гигиена, а условие: учётная запись выдаётся **только на запись**. Любой из
этих вызовов означал бы, что она требует больше прав, — и при компрометации
сервиса злоумышленник получил бы чтение и подмену чужих документов вместо
мусора в чужом префиксе.

Соблазн понятный: `head_object` «чтобы не перезаписать», `list_objects` «чтобы
показать, что доехало». Каждый такой вызов тихо расширяет требуемые права, а
заметно это становится не в коде, а в чужой политике доступа.
"""


def test_dropoff_only_writes() -> None:
    used = [call for call in FORBIDDEN_CALLS if f".{call}(" in DROPOFF.read_text()]

    assert not used, (
        f"выгрузка требует больше прав, чем запись: {used}. "
        "Учётка клиента выдаётся write-only — см. M14.4."
    )


def test_the_check_looks_at_the_right_file() -> None:
    """Проверка проверки: файл на месте и что-то в чужое хранилище пишет.

    Без этого предыдущий тест проходил бы и после переименования модуля —
    осматривая пустоту.
    """
    source = DROPOFF.read_text()

    assert "upload_fileobj" in source
    assert "put_object" in source


def test_destination_client_is_not_our_store() -> None:
    """Клиент чужого хранилища строится отдельно от нашего.

    Переиспользовать `S3Store` было бы короче, но он создан на наших учётных
    данных и нашем адресе: выгрузка молча уехала бы в наш собственный бакет,
    а клиент ждал бы файлов у себя.
    """
    source = DROPOFF.read_text()

    assert "credentials.access_key" in source
    assert "destination.endpoint" in source
    assert "settings" not in source, "адрес приёмника берётся из задания, а не из настроек"


# --- отказ доставки виден в метриках (M14.5) -------------------------------

NOTIFIER = Path("services/notifier/notifierapp/main.py")


def test_every_outcome_is_counted() -> None:
    """Каждый исход выгрузки размечен.

    Пропущенный исход не ломает ничего заметно: график просто не растёт, а
    «не растёт» здесь означает и «всё доставлено», и «ничего не доставляется».

    Смотрим внутрь нужных методов, а не по всему файлу: рядом живёт счётчик
    коллбэков с теми же словами `delivered`, `retry` и `lost`, и проверка по
    файлу целиком проходила бы, даже если выгрузку не размечали вовсе.
    """
    import inspect

    from notifierapp.dropoff import OUTCOMES
    from notifierapp.main import Notifier

    source = "".join(
        inspect.getsource(method)
        for method in (Notifier._deliver, Notifier._retry_delivery, Notifier._delivery_failed)
    )
    missing = [outcome for outcome in OUTCOMES if f'"{outcome}"' not in source]

    assert not missing, f"исход не считается: {missing}"
    assert "copies_delivered" in source, "счётчик выгрузок не трогают вовсе"


def test_documented_outcomes_match_the_code() -> None:
    """Список в docs/metrics.md не отстаёт от кода.

    Дежурный читает описание метки, чтобы понять график во время инцидента.
    Значение, которого нет в описании, он истолкует как угодно.
    """
    doc = Path("docs/metrics.md").read_text()
    row = next(line for line in doc.splitlines() if "vs_deliveries_total" in line)

    from notifierapp.dropoff import OUTCOMES

    for outcome in OUTCOMES:
        assert f"`{outcome}`" in row, f"исход {outcome} не описан в инвентаре метрик"


def test_unreadable_credentials_are_marked_degraded() -> None:
    """Файл учёток задан и не прочитан — доставки не будет ни одной.

    Ящик клиента при этом выглядит так же, как при отсутствии файлов на
    проверку: пустым. Признак деградации — единственное, что эти два состояния
    различает.
    """
    source = NOTIFIER.read_text()

    assert 'report_degraded("delivery"' in source


def test_delayed_deliveries_are_visible() -> None:
    """Растущая очередь повторов означает недоступный приёмник.

    Заметить это надо раньше, чем клиент спросит, где его файлы.
    """
    source = NOTIFIER.read_text()

    assert 'stream="delivery:retry"' in source


# --- сама выгрузка, а не её исходный текст ---------------------------------


class _StubNotifier:
    """Ровно те поля `Notifier`, которых касается `_deliver`.

    Метод вызывается несвязанным: поднимать настоящий `Notifier` значит поднять
    Redis, реестр ключей и хранилище — ничего из этого к проверке отношения не
    имеет, а без вызова проверки нет вовсе.
    """

    def __init__(self, credentials: DeliveryCredentials | None = CREDENTIALS) -> None:
        self._credentials = _StubRegistry(credentials)
        self.put: list[DeliveryTask] = []
        self.failed: list[str] = []
        self.retried: list[str] = []
        self.raises: Exception | None = None

    def _put(self, task: DeliveryTask, credentials: DeliveryCredentials) -> None:
        if self.raises is not None:
            raise self.raises
        self.put.append(task)

    async def _delivery_failed(self, task: DeliveryTask, detail: str) -> None:
        self.failed.append(detail)

    async def _retry_delivery(self, task: DeliveryTask, detail: str) -> None:
        self.retried.append(detail)


class _StubRegistry:
    def __init__(self, credentials: DeliveryCredentials | None) -> None:
        self._credentials = credentials

    def get(self, credentials_id: str) -> DeliveryCredentials | None:
        return self._credentials


async def test_delivery_actually_runs() -> None:
    """Вызов `_deliver`, а не чтение его исходника.

    Проверки выше читают текст функции через `inspect.getsource` — так они
    видят намерение, но не то, выполняется ли оно. Опечатка в аргументах
    (спан трассировки принимал словарь позиционным аргументом) роняла `_deliver`
    на `TypeError` при каждом вызове, а вместе с ним и весь цикл выгрузки: он
    ловит исключение общим `except` и останавливается навсегда. Все проверки по
    исходному тексту при этом проходили.
    """
    notifier = _StubNotifier()
    task = _task(_result())

    await Notifier._deliver(notifier, task)

    assert notifier.put == [task]
    assert not notifier.failed
    assert not notifier.retried


async def test_missing_credentials_do_not_reach_the_storage() -> None:
    """Учётки нет — это конфигурация, и повторять её бессмысленно."""
    notifier = _StubNotifier(credentials=None)

    await Notifier._deliver(notifier, _task(_result()))

    assert not notifier.put
    assert not notifier.retried
    assert len(notifier.failed) == 1
    assert "drop" in notifier.failed[0]


@pytest.mark.parametrize(
    "error",
    [DropoffError("приёмник не ответил"), RuntimeError("боты в проводах")],
    ids=["dropoff", "unexpected"],
)
async def test_failed_upload_is_retried_not_swallowed(error: Exception) -> None:
    """Любой сбой выгрузки уводит задачу в повтор, а не наружу из `_deliver`.

    Исключение, вылетевшее наружу, останавливает цикл выгрузки целиком —
    поэтому непредвиденный сбой обрабатывается наравне с ожидаемым.
    """
    notifier = _StubNotifier()
    notifier.raises = error

    await Notifier._deliver(notifier, _task(_result()))

    assert not notifier.put
    assert len(notifier.retried) == 1
