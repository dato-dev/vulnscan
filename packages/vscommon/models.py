"""Публичный контракт API и внутренний контракт очереди."""

from __future__ import annotations

import hashlib
import time
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl

from vscommon.delivery import Delivery

"""Версия правил скоринга. Входит в ключ кэша — менять при изменении порогов."""


class Verdict(StrEnum):
    """Результат детекта. Решение «блокировать» принимает клиент по политике."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNSUPPORTED = "unsupported"
    ENCRYPTED = "encrypted"
    ERROR = "error"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    SCANNING = "scanning"
    DONE = "done"
    FAILED = "failed"
    MANUAL_REVIEW = "manual_review"
    """Проверка не завершилась, задача в dead-letter и ждёт человека."""


REQUEST_DERIVED_CODES = frozenset({"MIME_MISMATCH", "EXT_MISMATCH"})
"""Признаки, описывающие не файл, а то, что заявил клиент.

В структурный кэш они не попадают: ключ строится по содержимому, и неверная
метка одного отправителя иначе досталась бы вердикту другого — того же рода
ошибка, что общий вердикт на разные политики тенантов.
"""


UNSCANNABLE_VERDICTS = frozenset({Verdict.ENCRYPTED, Verdict.UNSUPPORTED})
"""Содержимое проверить невозможно — не то же самое, что «проверили и чисто».

Такой файл не санитизируется (пересобирать нечего) и никогда не получает
вердикт `clean`. Что с ним делать, решает клиент: чаще всего — не пропускать.
"""


TERMINAL_STATUSES = frozenset({ScanStatus.DONE, ScanStatus.MANUAL_REVIEW})
"""Исходы, после которых повторная проверка того же скана не нужна.

`failed` сюда не входит: сбой CDR или дедлайн могут пройти со второй попытки.
"""


class DeadLetterReason(StrEnum):
    JOB_ABANDONED = "job_abandoned"
    """Исчерпан лимит повторных доставок."""

    PARSER_CRASH = "parser_crash"
    """Разбор файла обрывает процесс воркера."""

    SCAN_FAILED = "scan_failed"
    DELIVERY_FAILED = "delivery_failed"
    """Обезвреженная копия не доехала до хранилища клиента (M14).

    Приёмник пуст и при исправной работе, и при отказе выгрузки. Не оставив
    следа, мы сделали бы эти состояния неразличимыми и для клиента, который
    смотрит в ящик, и для дежурного."""

    CALLBACK_FAILED = "callback_failed"
    """Результат не доставлен клиенту.

    Молча потерянный результат для клиента неотличим от того, что файл не
    проверяли, — поэтому он попадает в разбор человеком, а не в пустоту."""
    """Ошибка обработки, вызванная самим файлом."""


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CdrProfile(StrEnum):
    LIGHT = "light"
    STANDARD = "standard"
    STRICT = "strict"


class ScanMode(StrEnum):
    DETECT = "detect"
    SANITIZE = "sanitize"
    BOTH = "both"


class FailMode(StrEnum):
    """Что считать вердиктом, если проверка не завершилась.

    Задаётся ТОЛЬКО серверной политикой тенанта. Клиент не может выбрать
    режим отказа полем запроса — иначе он отключает себе безопасность сам.
    """

    FAIL_CLOSED = "fail-closed"
    SUSPICIOUS = "suspicious"
    FAIL_OPEN = "fail-open"


class TenantPolicy(BaseModel):
    """Серверная политика. Загружается из конфигурации, не из запроса."""

    tenant: str = "default"
    fail_mode: FailMode = FailMode.SUSPICIOUS
    block_threshold: int = Field(default=80, ge=1, le=100)
    suspicious_threshold: int = Field(default=30, ge=1, le=100)
    default_profile: CdrProfile = CdrProfile.STANDARD
    max_wait_ms: int = Field(default=2_000, ge=0, le=10_000)
    shadow_mode: bool = False
    """Проверяем, но не действуем по вердикту.

    Вердикт остаётся честным — именно его и считаем. Клиенту он приходит с
    пометкой `shadow`, и тот по нему не блокирует. Заодно пересобирается даже
    то, что было бы заблокировано: иначе режим не покрывал бы как раз те
    случаи, ради которых нужен, — возможные ложные блокировки.
    """

    rate_limit_per_min: int = Field(default=1200, ge=0)
    """Запросов в минуту. 0 — без ограничения."""

    max_concurrent_scans: int = Field(default=64, ge=0)
    """Сколько проверок этого тенанта одновременно в очереди. 0 — без ограничения.

    Именно этот лимит защищает латентность соседей: он ограничивает долю
    очереди, которую способен занять один клиент.
    """

    max_upload_bytes: int = Field(default=0, ge=0)
    """Свой предел размера файла. 0 — общий лимит. Выше общего не поднимается."""

    public_rate_limit_per_min: int = Field(default=60, ge=0)
    """Частота выдачи талонов по публичному ключу сайта (M12.5).

    Отдельный лимит, а не общий с `rate_limit_per_min`, по двум причинам.

    Первая: у публичного ключа другой характер нагрузки. Его дёргают посетители
    сайта, а не бэкенд, и всплеск здесь — это не всплеск интеграции.

    Вторая важнее: общее ведро означало бы, что поток через виджет вытесняет
    собственные вызовы сайта. Форма под наплывом уронила бы его API — то есть
    наша защита сломала бы клиента.
    """

    widget_on_unavailable: Literal["block", "mark"] = "block"
    """Что делает виджет, когда проверка не состоялась (M12.9).

    `block` — файл к отправке не годится, поле очищается, посетителю сказано
    попробовать позже. `mark` — файл остаётся, но помечен непроверенным, и
    решение принимает сайт.

    Настройка серверная, и это принципиально. JavaScript на странице правит
    кто угодно: посетитель через консоль, сам сайт «чтобы форма не мешала»,
    расширение браузера. Оставь мы выбор там — «не смогли проверить» рано или
    поздно превратилось бы в «отправляем как есть», причём тихо.

    Умолчание `block`: непроверенный файл не должен выглядеть как проверенный.

    Настоящее решение всё равно за бэкендом сайта — браузеру верить нельзя
    вообще (M12.6). Эта настройка определяет, что виджет **сообщает** и что
    делает с полем, а не то, что физически возможно.
    """

    public_daily_tickets: int = Field(default=5_000, ge=0)
    """Сколько талонов в сутки может выдать один публичный ключ. 0 — без счёта.

    Частота в минуту не ограничивает суточную стоимость: шестьдесят запросов в
    минуту это восемьдесят шесть тысяч файлов в день. Публичный ключ виден
    всем, кто открыл страницу, и без суточного потолка чужой скрипт превращает
    его в способ разорить владельца — либо в бесплатный антивирус за его счёт.
    """

    delivery: Delivery | None = None
    """Куда складывать обезвреженную копию (M14). `None` — никуда, забирают у нас.

    Задаётся политикой и только ею. Поле с приёмником в запросе означало бы
    «просканируй и положи вот сюда» — примитив записи куда угодно и канал
    вывода данных наружу.
    """

    delivery_error: str = ""
    """Приёмник описан, но описание негодное.

    Отдельно от `delivery is None`, потому что это разные состояния: приёмника
    нет — штатная работа, приёмник сломан — авария. Свести их в одно значило бы
    превратить опечатку в имени поля в молчаливую потерю доставки: файлы
    перестали бы появляться в ящике, а сервис выглядел бы исправным.
    """

    weight_overrides: dict[str, int] = Field(default_factory=dict)
    """Свои веса признаков поверх общей таблицы: `{"PDF_EMBEDDED_FILE": 80}`.

    Только баллы — severity остаётся общей, иначе один и тот же признак
    описывался бы разными словами для разных клиентов.
    """


def _policy_fingerprint() -> str:
    """Отпечаток семантики скоринга. Считается, а не правится руками.

    Входит в ключ структурного кэша. Раньше это была константа: смену смысла
    вердиктов надо было заметить и поднять версию вручную — то есть ровно тот
    способ, которым в этом проекте уже несколько раз протухали кэшированные
    факты. Забытая правка означала, что записи, снятые по старой семантике,
    продолжали считаться действительными.

    Здесь именно **семантика**: состав вердиктов, статусов, непроверяемого и
    признаков, зависящих от запроса. Значения весов и семейства признаков сюда
    не входят — они покрыты отпечатком таблицы весов, который лежит в ключе
    рядом. Разделение не косметическое: иначе один и тот же факт учитывался бы
    дважды, а связность модулей выросла бы до цикла.
    """
    parts = [
        "verdicts:" + ",".join(sorted(v.value for v in Verdict)),
        "statuses:" + ",".join(sorted(s.value for s in ScanStatus)),
        "unscannable:" + ",".join(sorted(v.value for v in UNSCANNABLE_VERDICTS)),
        "request_derived:" + ",".join(sorted(REQUEST_DERIVED_CODES)),
    ]
    return "p" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


POLICY_VERSION = _policy_fingerprint()
"""Версия семантики скоринга. Вычисляется на импорте, руками не правится."""


class Finding(BaseModel):
    """Один признак. Стадии возвращают признаки, но не вердикт."""

    stage: str
    code: str = Field(description="Стабильный код, часть публичного контракта")
    severity: Severity
    detail: str | None = None
    score: int = Field(default=0, ge=0, le=100)


class ScanFacts(BaseModel):
    """Всё, что нужно для вердикта. Ничего сверх этого кэшировать не требуется.

    Кэшируются именно признаки, а не готовый вердикт: пороги и веса у тенантов
    разные, и общая запись с чужим вердиктом давала бы неверный ответ.
    """

    findings: list[Finding] = Field(default_factory=list)

    detected_mime: str | None = None
    """Тип, определённый по содержимому, а не по расширению.

    Факт о файле, а не о запросе: заявленный клиентом тип сюда не попадает.
    Кэшируется вместе с остальными признаками — иначе ответ из кэша не знал бы
    типа, хотя определялся он по тому же содержимому.
    """

    encrypted: bool = False
    supported: bool = True
    failed_stages: set[str] = Field(default_factory=set)

    def merge(self, other: ScanFacts) -> ScanFacts:
        """Склейка частей результата: структурной из кэша и свежей от AV."""
        seen = {f.code for f in self.findings}
        return ScanFacts(
            findings=self.findings + [f for f in other.findings if f.code not in seen],
            # Тип определяет структурная часть; у антивирусной его нет.
            detected_mime=self.detected_mime or other.detected_mime,
            encrypted=self.encrypted or other.encrypted,
            supported=self.supported and other.supported,
            failed_stages=self.failed_stages | other.failed_stages,
        )


class ObjectRef(BaseModel):
    """Ссылка на объект в хранилище вместо тела файла."""

    backend: Literal["s3", "local"] = "s3"
    bucket: str
    key: str
    size: int | None = None
    content_type: str | None = None


class SanitizedArtifact(BaseModel):
    ref: ObjectRef
    profile: CdrProfile
    transforms: list[str] = Field(default_factory=list)
    original_sha256: str
    sanitized_sha256: str
    expires_at: float | None = None


class StageTiming(BaseModel):
    stage: str
    elapsed_ms: int
    ok: bool = True


class ScanRequest(BaseModel):
    """Параметры запроса от клиента.

    Здесь только то, что клиенту решать можно. Режим отказа и пороги скоринга
    сюда не входят: они приходят из политики тенанта. Неизвестные поля
    (включая присланный клиентом `on_timeout`) молча игнорируются.
    """

    source: ObjectRef | None = None
    filename: str | None = None
    declared_mime: str | None = None
    mode: ScanMode = ScanMode.BOTH
    profile: CdrProfile | None = None
    """None — взять профиль из политики тенанта."""
    wait_ms: int = Field(default=400, ge=0, le=10_000)
    callback_url: HttpUrl | None = None
    tenant: str | None = None
    """Заполняется сервером из ключа. Значение от клиента игнорируется."""

    key_id: str = ""
    """Тоже сервером: клиент не выбирает, каким ключом подписывать ответ."""


class ScanResult(BaseModel):
    """Ответ API и тело коллбэка."""

    scan_id: str
    sha256: str
    status: ScanStatus
    verdict: Verdict
    score: int = Field(default=0, ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)
    sanitized: SanitizedArtifact | None = None
    engines: dict[str, Any] = Field(default_factory=dict)
    stages: list[StageTiming] = Field(default_factory=list)
    elapsed_ms: int = 0
    policy_version: str = POLICY_VERSION
    from_cache: bool = False
    shadow: bool = False
    """Вердикт получен в теневом режиме: действовать по нему не следует."""

    allowlisted: bool = False
    """Блокировка снята записью в списке доверенных. Признаки остаются видны."""

    deep: bool = False
    """Результат углублённой проверки. Приходит вторым, позже быстрого."""

    parent_scan_id: str = ""
    """Быстрый скан, к которому относится этот результат."""

    facts: ScanFacts | None = Field(default=None, exclude=True)
    """Внутреннее: из чего сложился вердикт. Клиенту не отдаётся."""

    created_at: float = Field(default_factory=time.time)

    def blocked(self) -> bool:
        return self.verdict is Verdict.MALICIOUS

    def unscannable(self) -> bool:
        """Содержимое недоступно: артефакта CDR не будет."""
        return self.verdict in UNSCANNABLE_VERDICTS


class DeliveryTask(BaseModel):
    """Задание положить обезвреженную копию в хранилище клиента (M14).

    Отдельная очередь от коллбэков, а не общая. Причина не в аккуратности:
    доставка файла может упираться в чужое хранилище часами, а коллбэк — это
    один HTTP-запрос. В общей очереди недоступный приёмник одного тенанта
    задерживал бы уведомления всем остальным.

    Выполняет доставку notifier: у воркера нет сетевого выхода наружу, и
    заводить его ради выгрузки значило бы разобрать периметр, ради которого
    воркер и заперт.

    Приёмник едет **в задании**, а не читается заново при доставке. Решение
    принято политикой, действовавшей на момент проверки; правка политики не
    должна переносить файл, который уже в пути.
    """

    scan_id: str
    tenant: str | None = None
    destination: Delivery

    artifact: ObjectRef | None = None
    """Что выгружать. `None` — выгружать нечего: файл не прошёл проверку.

    Задание при этом не отменяется: манифест уезжает всё равно. Иначе «файла
    нет» в приёмнике значило бы одновременно «заблокирован», «ещё в работе» и
    «сервис сломался».
    """

    name: str
    """Имя объекта в приёмнике. Исходное имя файла сюда не попадает: оно часто
    содержит персональные данные, и мы его не храним — только расширение."""

    payload: str
    """`ScanResult` в JSON. Из него собирается манифест."""

    traceparent: str = ""
    attempt: int = 0


class DeadLetter(BaseModel):
    """Запись в dead-letter: чего хватит человеку, чтобы разобраться.

    Содержимого файла здесь нет — только ссылка на объект в карантине.
    """

    scan_id: str
    sha256: str
    reason: DeadLetterReason
    verdict: Verdict
    detail: str | None = None
    stage: str | None = None
    """Стадия, на которой всё оборвалось, если известна."""
    delivered: int | None = None
    """Сколько раз задача выдавалась воркерам."""
    tenant: str | None = None
    source: ObjectRef
    created_at: float = Field(default_factory=time.time)


class CachedStructural(BaseModel):
    """Часть результата, не зависящая от версии антивирусных баз.

    Живёт долго: структура файла и наши правила меняются редко, а базы
    ClamAV обновляются несколько раз в сутки.
    """

    sha256: str
    profile: CdrProfile
    facts: ScanFacts
    engines: dict[str, Any] = Field(default_factory=dict)
    sanitized: SanitizedArtifact | None = None
    rules_version: str
    stages: list[StageTiming] = Field(default_factory=list)


class CachedAv(BaseModel):
    """Результат антивируса. Живёт до следующего обновления баз."""

    sha256: str
    facts: ScanFacts
    engines: dict[str, Any] = Field(default_factory=dict)
    av_db_version: str


class CallbackTask(BaseModel):
    """Задание на доставку результата клиенту.

    Отдельная очередь, а не отправка прямо из воркера, по двум причинам.

    Первая — секреты. Коллбэк подписывается ключом тенанта, и держать ключи
    всех тенантов в процессе, который разбирает враждебные файлы, значит
    менять одну дыру в парсере на компрометацию всех клиентов сразу.

    Вторая — время. Три попытки за несколько секунд хватает соседнему
    контейнеру и не хватает разрыву между площадками. Ретраи, растянутые на
    десятки минут, держать внутри обработки задачи нельзя: воркер занят.

    Сам секрет здесь НЕ хранится — только идентификатор ключа. Задание лежит
    в Redis, а Redis теперь пишет на диск.
    """

    scan_id: str
    tenant: str | None = None
    key_id: str = ""
    """Каким ключом подписывать. Секрет notifier берёт из своего реестра."""

    url: str
    payload: str
    """Готовое тело ответа. Подпись считается по нему же, поэтому пересобирать
    его на стороне доставки нельзя — подпись не сойдётся."""

    attempt: int = 0
    created_at: float = Field(default_factory=time.time)

    traceparent: str = ""
    """Контекст трассировки в форме W3C — тем же способом, что в `ScanJob`.

    Без него доставка начинала отдельный корневой трейс, и трейс скана
    обрывался на воркере. Вопрос «сервис ответил, а до клиента дошло?» —
    именно тот, ради которого в трассировку и лезут, — по такому дереву не
    отвечался: две половины лежали в разных трейсах и не были связаны ничем,
    кроме `scan_id`.

    Побочно: без связи граф сервисов не рисовал ребро воркер → notifier."""

    @property
    def host(self) -> str:
        """Только хост — URL целиком несёт параметры и не идёт в логи."""
        from urllib.parse import urlsplit

        return urlsplit(self.url).hostname or "unknown"


class ScanRecord(BaseModel):
    """Запись для истории. Едет в `ResultStream`, оседает в PostgreSQL.

    Отдельно от `ScanResult` намеренно: тот — публичный ответ клиенту, и
    засовывать в него тенанта и версии движков значило бы раздувать контракт
    ради чужой задачи. Истории же нужно больше, чем ответу: без тенанта и
    версий правил нельзя ни разобрать инцидент, ни объяснить, почему на том же
    файле вердикт изменился.

    Имени файла здесь нет и не будет — оно почти всегда содержит ПДн.
    """

    result: ScanResult
    tenant: str | None = None
    size: int = 0
    detected_mime: str | None = None
    rules_version: str = ""
    av_db_version: str = ""

    traceparent: str = ""
    """Контекст трассировки в форме W3C — как у `ScanJob` и `CallbackTask`.

    Без него writer был тупиком: трассировка в нём настраивалась, но ни одного
    спана он не отдавал, и трейс скана обрывался на публикации в поток. На
    вопрос «а запись-то доехала до базы?» трейс не отвечал — при том что
    `vs_history_lag_seconds` заведён ровно про это, и отставание, которое он
    показывает, разбирают по одному конкретному скану.
    """


class ScanJob(BaseModel):
    """Сообщение в Redis Stream. Внутренний контракт, не публичный."""

    scan_id: str
    sha256: str
    source: ObjectRef
    size: int
    filename_ext: str | None = None
    declared_mime: str | None = None
    mode: ScanMode = ScanMode.BOTH
    profile: CdrProfile = CdrProfile.STANDARD
    policy: TenantPolicy = Field(default_factory=TenantPolicy)
    """Снимок политики на момент постановки задачи — воркер не ходит за ней сам."""
    callback_url: str | None = None
    tenant: str | None = None
    cached: CachedStructural | None = None
    """Структурная часть уже в кэше — воркеру остаётся только антивирус."""

    deep: bool = False
    """Углублённая проверка: вне горячего пути, без ограничений на стоимость."""

    deep_reason: str = ""
    """Почему файл отправлен на углублённую проверку."""

    parent_scan_id: str = ""
    """Быстрая проверка, из которой выросла углублённая."""

    enqueued_at: float = Field(default_factory=time.time)

    key_id: str = ""
    """Каким ключом подписывать коллбэк. Секрета здесь нет — только его имя.

    Секрет знает notifier; воркер разбирает враждебные файлы, и держать в нём
    ключи всех тенантов значит менять одну дыру в парсере на компрометацию
    всех клиентов сразу.
    """

    traceparent: str = ""
    """Контекст трассировки в форме W3C.

    Заголовком его не передать: gateway и воркер разнесены во времени и по
    хостам, между ними Redis Stream. Значение ставит gateway из своего спана —
    от клиента оно не принимается, иначе чужой контекст склеил бы наш скан с
    посторонним трейсом.
    """
