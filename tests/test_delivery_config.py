"""M14.8: где живёт описание приёмника и чем оно отличается от учётных данных.

Здесь проверяются два решения, и оба про то, кто что видит.

**Адрес — в политике, ключи — по ссылке.** `POLICY_FILE` объявлен не только
gateway, но и воркеру с deepscan, а воркер — единственный процесс, разбирающий
враждебные файлы. Знание «мы пишем в такой-то бакет» ему безвредно; ключ
доступа к чужому хранилищу означал бы, что дыра в парсере даёт запись в
инфраструктуру клиента.

**Негодный блок — это состояние, а не отсутствие.** `TenantPolicy` неизвестные
поля игнорирует, и это правильно: так клиент не подсунет себе `on_timeout:
fail-open`. Но для приёмника мягкость означала бы, что опечатка в имени поля
превращается в «доставка не настроена» — и файлы просто перестают появляться в
ящике при исправном с виду сервисе.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from vscommon.delivery import (
    MIN_SECRET_LEN,
    CredentialsRegistry,
    Delivery,
    DeliveryCredentials,
    DeliveryError,
    parse_delivery,
)
from vscommon.models import TenantPolicy
from vscommon.policy import PolicyRegistry

GOOD = {"bucket": "incoming-clean", "credentials_id": "team-drop", "prefix": "vulnscan/"}


def _settings(policy_file: str = "") -> SimpleNamespace:
    """То немногое из настроек, чем пользуется загрузчик политик."""
    return SimpleNamespace(
        policy_file=policy_file,
        default_fail_mode="suspicious",
        default_block_threshold=80,
        default_suspicious_threshold=30,
        default_cdr_profile="standard",
        default_shadow_mode=False,
    )


def _written(tmp_path: Path, payload: dict) -> str:
    path = tmp_path / "policies.json"
    path.write_text(json.dumps(payload, ensure_ascii=False))
    return str(path)


# --- строгий разбор --------------------------------------------------------


def test_good_block_parses() -> None:
    delivery = parse_delivery(GOOD)

    assert delivery.bucket == "incoming-clean"
    assert delivery.credentials_id == "team-drop"


def test_unknown_field_is_refused() -> None:
    """Опечатка в имени поля — ошибка, а не молчаливый пропуск.

    Мягкий разбор здесь означал бы: `bucketname` вместо `bucket` → блок
    прочитан наполовину или не прочитан вовсе → приёмник «не настроен» → файлы
    не появляются в ящике, и сервис при этом выглядит исправным.
    """
    with pytest.raises(DeliveryError):
        parse_delivery({**GOOD, "buckett": "typo"})


def test_bucket_and_credentials_are_required() -> None:
    with pytest.raises(DeliveryError):
        parse_delivery({"credentials_id": "team-drop"})
    with pytest.raises(DeliveryError):
        parse_delivery({"bucket": "incoming-clean"})


def test_only_known_backends() -> None:
    """SMB решается отдельно (M14.6), NFS не в нашем периметре (M14.7)."""
    with pytest.raises(DeliveryError):
        parse_delivery({**GOOD, "backend": "nfs"})


def test_prefix_gets_a_separator() -> None:
    """Префикс без косой черты — обычная опечатка с тихим последствием.

    `vulnscan` + `doc.pdf` дало бы `vulnscandoc.pdf`: доставка работает, файлы
    ложатся не туда, и заметно это только глазами в чужом бакете.
    """
    assert parse_delivery({**GOOD, "prefix": "vulnscan"}).key_for("doc.pdf") == "vulnscan/doc.pdf"
    assert parse_delivery({**GOOD, "prefix": "a/b/"}).key_for("doc.pdf") == "a/b/doc.pdf"
    assert parse_delivery({**GOOD, "prefix": ""}).key_for("doc.pdf") == "doc.pdf"


# --- секретов в политике нет ----------------------------------------------


def test_policy_block_cannot_carry_a_secret() -> None:
    """Ключи в `policies.json` не примут — и это главное свойство M14.8.

    Файл читает воркер. Приняв здесь `secret_key`, мы отдали бы процессу,
    разбирающему враждебные файлы, доступ на запись в хранилище клиента.
    """
    with pytest.raises(DeliveryError):
        parse_delivery({**GOOD, "access_key": "AKIA", "secret_key": "s" * 32})


def test_credentials_never_render_the_secret() -> None:
    """Секрет не должен утечь в лог через случайный `repr` объекта."""
    creds = DeliveryCredentials(access_key="AKIA", secret_key="s" * MIN_SECRET_LEN)

    assert "s" * MIN_SECRET_LEN not in repr(creds)
    assert "s" * MIN_SECRET_LEN not in str(creds)
    assert "AKIA" in repr(creds), "идентификатор видеть надо: по нему разбирают отказ"


def test_short_secret_is_refused() -> None:
    with pytest.raises(ValueError):
        DeliveryCredentials(access_key="AKIA", secret_key="коротко")


# --- реестр учётных данных -------------------------------------------------


def test_missing_file_is_degraded_not_empty(tmp_path: Path) -> None:
    """Файл задан и не прочитан — это отказ доставки, а не работа без неё.

    Пустой реестр без пометки означал бы «приёмников нет», и промах
    bind-mount выглядел бы как штатная установка.
    """
    registry = CredentialsRegistry.load(str(tmp_path / "нет-такого.json"))

    assert registry.degraded
    assert len(registry) == 0


def test_no_file_configured_is_not_degraded() -> None:
    """Приёмников нет вовсе — обычное состояние, жаловаться не на что."""
    registry = CredentialsRegistry.load(None)

    assert not registry.degraded


def test_one_bad_entry_does_not_close_the_rest(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    path.write_text(
        json.dumps(
            {
                "_комментарий": "записи с подчёркиванием пропускаются",
                "битая": {"access_key": "AKIA"},
                "годная": {"access_key": "AKIA", "secret_key": "s" * MIN_SECRET_LEN},
            }
        )
    )

    registry = CredentialsRegistry.load(str(path))

    assert registry.get("годная") is not None
    assert registry.get("битая") is None


# --- загрузка политики -----------------------------------------------------


def test_policy_carries_the_destination(tmp_path: Path) -> None:
    path = _written(tmp_path, {"team-a": {"delivery": GOOD}})

    policy = PolicyRegistry.load(_settings(path)).for_tenant("team-a")

    assert isinstance(policy.delivery, Delivery)
    assert policy.delivery.bucket == "incoming-clean"
    assert policy.delivery_error == ""


def test_absent_destination_is_not_an_error(tmp_path: Path) -> None:
    """Копию забирают у нас — штатная работа, а не поломка."""
    path = _written(tmp_path, {"team-a": {"block_threshold": 50}})

    policy = PolicyRegistry.load(_settings(path)).for_tenant("team-a")

    assert policy.delivery is None
    assert policy.delivery_error == ""


def test_broken_destination_is_remembered_not_dropped(tmp_path: Path) -> None:
    """«Настроена и сломана» отличается от «не настроена».

    Свести их в одно значило бы: опечатка → доставки нет → файлы не приходят,
    и никто не знает, что их вообще должны были доставлять.
    """
    path = _written(tmp_path, {"team-a": {"delivery": {**GOOD, "buckett": "typo"}}})

    policy = PolicyRegistry.load(_settings(path)).for_tenant("team-a")

    assert policy.delivery is None
    assert policy.delivery_error, "негодный блок обязан оставить след"


def test_broken_destination_keeps_the_rest_of_the_policy(tmp_path: Path) -> None:
    """Пороги тенанта остаются в силе.

    Заменить их умолчаниями из-за опечатки в адресе означало бы ослабить
    проверку там, где сломана всего лишь выдача: у тенанта со строгим порогом
    50 он молча стал бы 80.
    """
    path = _written(
        tmp_path,
        {"team-a": {"block_threshold": 50, "delivery": {"bucket": "b"}}},
    )

    policy = PolicyRegistry.load(_settings(path)).for_tenant("team-a")

    assert policy.block_threshold == 50
    assert policy.delivery_error


def test_broken_destination_does_not_affect_neighbours(tmp_path: Path) -> None:
    """Одна негодная запись не закрывает доставку остальным."""
    path = _written(
        tmp_path,
        {
            "team-a": {"delivery": {"bucket": "b"}},
            "team-b": {"delivery": GOOD},
        },
    )

    registry = PolicyRegistry.load(_settings(path))

    assert registry.for_tenant("team-a").delivery is None
    assert registry.for_tenant("team-b").delivery is not None


# --- приёмник задаёт политика, а не запрос (M14.2) -------------------------


def test_request_cannot_name_a_destination() -> None:
    """«Просканируй и положи вот сюда» — примитив записи куда угодно.

    Тот же довод, по которому адреса коллбэков проверяются по списку ключа:
    поле в запросе превратило бы сервис в посредника для записи в любое
    доступное ему хранилище и в канал вывода данных наружу.
    """
    from vscommon.models import ScanRequest

    request = ScanRequest.model_validate({"delivery": GOOD, "wait_ms": 100})

    assert not hasattr(request, "delivery")
    assert "delivery" not in request.model_dump()


def test_destination_is_not_a_client_field() -> None:
    """Проверка проверки: поле живёт в политике, а не в запросе.

    Без этого предыдущий тест проходил бы и в мире, где `delivery` вообще
    нигде нет, — то есть не проверял бы ничего.
    """
    from vscommon.models import ScanRequest

    assert "delivery" in TenantPolicy.model_fields
    assert "delivery" not in ScanRequest.model_fields


# --- каталог секретов виден не всем ----------------------------------------

COMPOSE = Path(__file__).parent.parent / "deploy/docker-compose.yml"

SECRET_MOUNTS = ("./secrets",)
"""Каталоги, которые нельзя монтировать куда попало."""

ALLOWED_TO_SEE_SECRETS = {"notifier"}
"""Кому секреты приёмников нужны для работы.

Только доставляющий сервис. Он недоверенный контент не разбирает — об этом
сказано в его Dockerfile, — поэтому ключи здесь допустимы.
"""


def _services() -> dict[str, dict]:
    import yaml

    return yaml.safe_load(COMPOSE.read_text())["services"]


def test_secrets_are_mounted_only_where_needed() -> None:
    """Каталог с ключами от чужих хранилищ виден одному сервису.

    Отдельный каталог, а не файл в `config`, именно поэтому: `./config`
    монтируется в gateway, воркер и deepscan целиком. Положив учётные данные
    туда, мы отдали бы их процессу, который разбирает враждебные файлы, —
    причём молча, потому что для работы он их не читает.
    """
    leaked = [
        name
        for name, service in _services().items()
        if name not in ALLOWED_TO_SEE_SECRETS
        and any(
            str(volume).startswith(mount)
            for volume in (service.get("volumes") or [])
            for mount in SECRET_MOUNTS
        )
    ]

    assert not leaked, f"каталог секретов виден лишним сервисам: {leaked}"


def test_the_service_that_needs_them_gets_them() -> None:
    """Проверка проверки: без этого тест выше проходил бы и с пустым compose."""
    notifier = _services()["notifier"]
    mounts = [str(volume) for volume in notifier.get("volumes") or []]

    assert any(mount.startswith("./secrets") for mount in mounts), (
        "notifier доставляет копии, но каталог с учётными данными ему не смонтирован"
    )
    assert "DELIVERY_CREDENTIALS_FILE" in notifier["environment"]


# --- приёмник приходит только из политики (M14.2) --------------------------

INGEST = Path(__file__).parent.parent / "services/gateway/gateway_app"


def test_job_takes_the_destination_only_from_the_policy() -> None:
    """`ScanJob` не получает приёмник отдельным полем.

    Приёмник живёт внутри `policy`, которую собирает сервер по ключу тенанта.
    Отдельное поле в задании означало бы второй путь его задать — и рано или
    поздно на этот путь нашёлся бы способ повлиять снаружи.
    """
    from vscommon.models import ScanJob

    assert "delivery" not in ScanJob.model_fields
    assert "policy" in ScanJob.model_fields


def test_gateway_never_reads_a_destination_from_the_request() -> None:
    """Ни одна ручка приёма не смотрит в запрос за приёмником.

    «Просканируй и положи вот сюда» — примитив записи куда угодно и канал
    вывода данных наружу. Проверка структурная: поведенческий тест написали бы
    для той ручки, о которой помнят, а опасна как раз забытая.
    """
    offenders = {
        path.name: [
            line.strip()
            for line in path.read_text().splitlines()
            if "delivery" in line and ("request." in line or "payload" in line or "body" in line)
        ]
        for path in INGEST.rglob("*.py")
    }
    found = {name: lines for name, lines in offenders.items() if lines}

    assert not found, f"приёмник берётся из запроса: {found}"


def test_only_an_admin_key_can_change_a_destination() -> None:
    """Через административный API приёмник задать можно — и только им.

    Иначе тенант выписал бы себе выгрузку в любое хранилище, куда дотянется
    notifier, то есть получил бы тот же примитив окольным путём.
    """
    import inspect

    from gateway_app.routes import admin

    source = inspect.getsource(admin.set_policy)

    assert "require_admin" in source or "Depends(require_admin)" in source


# --- шаблон имени объекта --------------------------------------------------


def test_default_template_groups_by_day() -> None:
    """Без даты в ящике плоская груда случайных имён.

    Её нельзя ни отсортировать, ни посмотреть за период, ни разделить при
    выгрузке. Именно на это и пожаловались, когда доставка заработала.
    """
    name = parse_delivery(GOOD).object_name(
        scan_id="04cb0ab5", sha256="a" * 64, verdict="clean", ext=".pdf", when=1_757_232_000.0
    )

    assert name == "2025/09/07/04cb0ab5.pdf"


def test_unknown_placeholder_is_refused() -> None:
    """Неизвестная подстановка ловится при разборе, а не на живом файле.

    Иначе `str.format` бросил бы `KeyError` при первой выгрузке, доставка ушла
    бы в повторы и через десять попыток в dead-letter — всё это на
    конфигурации, негодной с самого начала.
    """
    with pytest.raises(DeliveryError):
        parse_delivery({**GOOD, "key_template": "{whatever}/{scan_id}"})


def test_filename_placeholder_switches_on_storage() -> None:
    """`{filename}` — не просто подстановка, а включение хранения имён.

    Чтобы подставить имя, его надо донести до воркера через очередь, то есть
    сохранить в Redis. По умолчанию gateway оставляет от имени только
    расширение; шаблон это умолчание отменяет, и делать это должен тенант
    осознанно, а не мы за него.
    """
    plain = parse_delivery(GOOD)
    asking = parse_delivery({**GOOD, "key_template": "{filename}-Проверено-{verdict}{ext}"})

    assert not plain.needs_filename
    assert asking.needs_filename


@pytest.mark.parametrize(
    "template",
    ["/{scan_id}", "../{scan_id}", "{date}//{scan_id}", "{scan_id}/../{sha}"],
)
def test_keys_that_escape_a_directory_are_refused(template: str) -> None:
    """Ключ в S3 — не путь, но клиент забирает ящик через `aws s3 sync`.

    Там ключ становится именем файла на его диске, и сегмент `..` превращается
    в выход за каталог. Чем читают ящик, мы не знаем, поэтому не отдаём того,
    что может так прочитаться.
    """
    with pytest.raises(DeliveryError):
        parse_delivery({**GOOD, "key_template": template})


def test_unbalanced_braces_are_refused() -> None:
    """`{scan_id{ext}` разберётся во что угодно, только не в задуманное."""
    with pytest.raises(DeliveryError):
        parse_delivery({**GOOD, "key_template": "{scan_id{ext}"})


def test_template_is_checked_on_a_sample_at_parse_time() -> None:
    """Разбор прогоняет шаблон на образце, а не только смотрит на подстановки.

    Проверка проверки: годный шаблон обязан пройти, иначе предыдущие тесты
    проходили бы и в мире, где отвергается всё подряд.
    """
    delivery = parse_delivery({**GOOD, "key_template": "{verdict}/{year}/{sha}{ext}"})

    assert delivery.object_name("s", "abcdef123456" + "0" * 52, "malicious", ".pdf", 0.0) == (
        "malicious/1970/abcdef123456.pdf"
    )


def test_date_is_the_moment_of_the_scan() -> None:
    """Повтор доставки через сутки не должен переносить файл в другой каталог.

    Иначе объём за период перестал бы сходиться с историей проверок, а
    найденный по дате файл оказался бы не там, где его искали.
    """
    delivery = parse_delivery(GOOD)
    first = delivery.object_name("s", "a" * 64, "clean", ".pdf", 1_757_232_000.0)
    later = delivery.object_name("s", "a" * 64, "clean", ".pdf", 1_757_232_000.0 + 86_400 * 3)

    assert first != later, "дата обязана участвовать в имени"
    assert first == "2025/09/07/s.pdf"


# --- можно спросить, какая политика действует ------------------------------


async def test_effective_policy_shows_what_is_applied() -> None:
    """Файл на диске и действующая политика — разные вещи.

    Расходятся они молча: тенант без записи получает умолчания, негодный блок
    `delivery` оставляет пороги в силе и отключает выгрузку. Все три случая
    выглядят одинаково — сервис работает, файлы не приходят.
    """
    from types import SimpleNamespace

    from gateway_app.routes.admin import effective_policy
    from vscommon.keys import AccessKey
    from vscommon.policy import PolicyRegistry

    policy = TenantPolicy(
        tenant="team-a",
        delivery=parse_delivery({**GOOD, "key_template": "{filename}-{verdict}{ext}"}),
    )
    state = SimpleNamespace(
        policies=PolicyRegistry(TenantPolicy(), {"team-a": policy}),
        keys=SimpleNamespace(
            all_keys=lambda: [AccessKey(key_id="k", tenant="team-a", secret="s" * 32)]
        ),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(vs=state)))

    answer = await effective_policy(
        request, "team-a", admin=AccessKey(key_id="a", tenant="root", secret="s" * 32, admin=True)
    )

    assert answer["своя_политика"] is True
    assert answer["есть_ключи"] is True
    assert answer["delivery"]["хранит_имя_файла"] is True
    assert answer["delivery"]["пример_ключа"].startswith("vulnscan/")
    assert "пример-clean.pdf" in answer["delivery"]["пример_ключа"]


async def test_effective_policy_admits_falling_back_to_defaults() -> None:
    """Главный вопрос при разборе: применилась запись или взяли умолчания.

    Именно на нём мы и споткнулись: политика была названа по идентификатору
    ключа, не совпала с тенантом, и сервис молча работал на умолчаниях.
    """
    from types import SimpleNamespace

    from gateway_app.routes.admin import effective_policy
    from vscommon.keys import AccessKey
    from vscommon.policy import PolicyRegistry

    state = SimpleNamespace(
        policies=PolicyRegistry(TenantPolicy(), {}),
        keys=SimpleNamespace(all_keys=list),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(vs=state)))

    answer = await effective_policy(
        request, "team-a", admin=AccessKey(key_id="a", tenant="root", secret="s" * 32, admin=True)
    )

    assert answer["своя_политика"] is False
    assert answer["delivery"] is None


async def test_effective_policy_reports_a_broken_block() -> None:
    """«Настроена и сломана» видно снаружи, а не только в логах воркера."""
    from types import SimpleNamespace

    from gateway_app.routes.admin import effective_policy
    from vscommon.keys import AccessKey
    from vscommon.policy import PolicyRegistry, build_policy

    broken = build_policy(TenantPolicy(), "team-a", {"delivery": {"buckett": "x"}})
    state = SimpleNamespace(
        policies=PolicyRegistry(TenantPolicy(), {"team-a": broken}),
        keys=SimpleNamespace(all_keys=list),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(vs=state)))

    answer = await effective_policy(
        request, "team-a", admin=AccessKey(key_id="a", tenant="root", secret="s" * 32, admin=True)
    )

    assert answer["delivery"] is None
    assert answer["delivery_error"], "сломанный блок обязан быть виден"
