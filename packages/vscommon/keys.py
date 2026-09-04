"""Ключи доступа тенантов.

Раньше секрет был один на всех, а тенант приходил заголовком — то есть любой,
кто мог обратиться к сервису, называл себя кем угодно и получал чужую политику
вместе с её порогами и режимом отказа. Это тот же класс ошибки, что и поле
`fail-open` в запросе, только этажом выше: поле выбирало не порог, а весь
набор порогов.

Здесь тенант выводится **из ключа** и ниоткуда больше.
"""

from __future__ import annotations

import hmac
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from vscommon.signing import Rejection, SignatureCheck, check_signature

logger = logging.getLogger(__name__)

KEY_ID_HEADER = "X-Vulnscan-Key"

MIN_SECRET_LEN = 32
"""Короткий секрет перебирается. Это не рекомендация, а условие приёма ключа."""


@dataclass(frozen=True, slots=True)
class AccessKey:
    key_id: str
    tenant: str
    secret: str
    disabled: bool = False
    admin: bool = False
    """Ключ администратора: заводит тенантов и выпускает другие ключи.

    Отдельный признак, а не отдельный список: иначе появился бы второй способ
    аутентификации, и один из них рано или поздно отстал бы от другого.
    """

    callback_hosts: tuple[str, ...] = ()
    """Куда этому тенанту разрешено слать коллбэк (M8.9).

    Пусто — коллбэки запрещены. Разрешать по умолчанию нельзя: `callback_url`
    приходит из запроса, и без списка сервис становится посредником для
    обращений во внутреннюю сеть.
    """

    public: bool = False
    """Ключ сайта: лежит открыто в HTML страницы (M12.3).

    Признак на том же объекте, а не отдельный список, — по той же причине, что
    и `admin`: второй способ аутентификации рано или поздно отстал бы от
    первого.

    Такой ключ умеет ровно одно — получить талон на загрузку. Подписывать им
    нельзя ФИЗИЧЕСКИ: его «секрет» знает каждый посетитель сайта, и проверка
    подписи таким ключом означала бы, что подписать может кто угодно. Поэтому
    `check()` отвергает его до сравнения подписи.
    """

    origins: tuple[str, ...] = ()
    """С каких origin принимать этот публичный ключ.

    Пусто — ключ не работает нигде. Это осознанный fail-closed: публичный ключ
    без списка origin годится для любого сайта в интернете.

    Проверка защищает от использования ключа на ЧУЖОЙ странице, а не от
    скрипта в консоли: `Origin` вне браузера подделывается. От второго
    защищают квоты (M12.5), и путать эти две защиты нельзя.
    """


class KeyRegistry:
    """Ключи из файла. Перезагружается на живом сервисе.

    Отзыв ключа обязан работать без рестарта: скомпрометированный ключ нельзя
    оставлять действующим до ближайшего окна обслуживания.
    """

    def __init__(self, keys: dict[str, AccessKey], degraded: bool = False) -> None:
        self._keys = keys
        self.degraded = degraded
        """Файл задан, но прочитать его не удалось.

        В отличие от политик, здесь деградация означает «никого не пускаем»:
        пустой реестр ключей отвергает все запросы. Работать на умолчаниях
        нельзя — умолчание в аутентификации это дыра.
        """

    def get(self, key_id: str) -> AccessKey | None:
        """Ключ по идентификатору. Отключённый не возвращается."""
        key = self._keys.get(key_id)
        if key is None or key.disabled:
            return None
        return key

    def resolve(self, key_id: str, body: bytes, timestamp: str, signature: str) -> AccessKey | None:
        """Ключ, которым действительно подписан запрос."""
        key, _check = self.check(key_id, body, timestamp, signature)
        return key

    def check(
        self, key_id: str, body: bytes, timestamp: str, signature: str
    ) -> tuple[AccessKey | None, SignatureCheck]:
        """То же, но с объяснением отказа — оно нужно в логе, не в ответе.

        Сравнение идёт по конкретному ключу, а не перебором всех: перебор дал
        бы измеримую разницу во времени между «ключа нет» и «подпись не сошлась».
        """
        key = self.get(key_id)
        if key is None:
            return None, SignatureCheck(Rejection.MISMATCH)
        if key.public:
            # Секрет публичного ключа публичен. Проверять им подпись — значит
            # принимать подпись от любого, кто открыл исходный код страницы.
            # Отказ здесь, а не в вызывающем коде: место одно, и обойти его
            # нельзя, забыв проверку на стороне маршрута.
            logger.warning(
                "публичный ключ предъявлен как подписывающий", extra={"key_id": key_id}
            )
            return None, SignatureCheck(Rejection.MISMATCH)
        check = check_signature(key.secret, body, timestamp, signature)
        return (key if check.ok else None), check

    def __len__(self) -> int:
        return len(self._keys)

    def all_keys(self) -> tuple[AccessKey, ...]:
        """Все записи, включая отключённые.

        Отключённые тоже отдаются: вызывающему может понадобиться отличить
        «ключа нет» от «ключ отозван». Кто этой разницей не пользуется —
        фильтрует сам, и это заметно в коде.
        """
        return tuple(self._keys.values())

    @property
    def tenants(self) -> tuple[str, ...]:
        return tuple(sorted({key.tenant for key in self._keys.values()}))

    def merged_with(self, extra: dict[str, AccessKey]) -> KeyRegistry:
        """Реестр из файла плюс заведённое через API.

        Записи из хранилища перекрывают файловые: отозвать ключ через API
        должно получаться и тогда, когда он остался в файле.
        """
        combined = dict(self._keys)
        combined.update(extra)
        return KeyRegistry(combined, degraded=self.degraded)

    @classmethod
    def load(cls, path_value: str | None) -> KeyRegistry:
        """Читает файл ключей. Отсутствие файла — пустой реестр, а не ошибка."""
        if not path_value:
            logger.warning("файл ключей не задан: подписанные запросы приниматься не будут")
            return cls({})

        path = Path(path_value)
        # Тот же случай, что уже ронял gateway: непримонтированный файл Docker
        # молча подменяет каталогом.
        if not path.is_file():
            logger.error("файл ключей недоступен, ни один запрос не будет принят")
            return cls({}, degraded=True)

        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            logger.exception("не удалось прочитать файл ключей")
            return cls({}, degraded=True)

        keys: dict[str, AccessKey] = {}
        for key_id, entry in (raw or {}).items():
            key = _parse(key_id, entry)
            if key is not None:
                keys[key_id] = key

        logger.info(
            "ключи загружены",
            extra={"ключей": len(keys), "тенантов": len({k.tenant for k in keys.values()})},
        )
        return cls(keys)

    def fingerprint(self) -> str:
        """Отпечаток состава реестра. Секреты в него не входят.

        Нужен, чтобы заметить перезагрузку, не сравнивая ключи между собой и
        не рискуя записать секрет в лог.
        """
        parts = sorted(f"{k.key_id}:{k.tenant}:{int(k.disabled)}" for k in self._keys.values())
        digest = hmac.new(b"key-registry", "|".join(parts).encode(), "sha256")
        return digest.hexdigest()[:12]


def _parse(key_id: str, entry: object) -> AccessKey | None:
    """Разбирает одну запись. Негодная пропускается, а не роняет реестр.

    Одна опечатка в файле не должна закрывать доступ всем остальным тенантам.
    """
    if key_id.startswith("_"):
        # Комментарий в файле, а не ключ. JSON своих комментариев не имеет,
        # поэтому пояснения кладут отдельным полем — ругаться на них нельзя:
        # ERROR при каждом старте на штатной записи обесценивает сам уровень.
        return None

    if not isinstance(entry, dict):
        logger.error("запись ключа не является объектом", extra={"key_id": key_id})
        return None

    tenant = entry.get("tenant")
    secret = entry.get("secret")
    if not isinstance(tenant, str) or not tenant:
        logger.error("у ключа не указан тенант", extra={"key_id": key_id})
        return None
    if not isinstance(secret, str) or len(secret) < MIN_SECRET_LEN:
        # Секрет в лог не попадает — только факт, что он не годится.
        logger.error(
            "секрет короче допустимого, ключ не загружен",
            extra={"key_id": key_id, "минимум": MIN_SECRET_LEN},
        )
        return None

    hosts = entry.get("callback_hosts") or []
    if not isinstance(hosts, list):
        logger.error("список адресов коллбэка не является массивом", extra={"key_id": key_id})
        hosts = []

    origins = entry.get("origins") or []
    if not isinstance(origins, list):
        logger.error("список origin не является массивом", extra={"key_id": key_id})
        origins = []

    public = bool(entry.get("public", False))
    if public and entry.get("admin"):
        # Публичный ключ администратора — это ключ администратора в HTML.
        # Не «нежелательно», а невозможно: запись не загружается вовсе.
        logger.error("ключ не может быть одновременно публичным и административным",
                     extra={"key_id": key_id})
        return None
    if public and not origins:
        # Загружаем, но предупреждаем: сам по себе такой ключ безвреден —
        # `origin_allowed` не пропустит с ним ни один адрес, — а вот молчание
        # оставило бы владельца в уверенности, что ключ работает.
        logger.warning(
            "у публичного ключа не задан ни один origin: он не будет работать нигде",
            extra={"key_id": key_id},
        )

    return AccessKey(
        key_id=key_id,
        tenant=tenant,
        secret=secret,
        disabled=bool(entry.get("disabled", False)),
        admin=bool(entry.get("admin", False)),
        callback_hosts=tuple(str(h).lower() for h in hosts if isinstance(h, str)),
        public=public,
        origins=tuple(str(o) for o in origins if isinstance(o, str)),
    )


def origin_allowed(key: AccessKey, origin: str) -> bool:
    """Разрешён ли этот `Origin` для публичного ключа сайта (M12.3).

    Сравнение точное и без подстановочных знаков. Причина не в лени: маска вида
    `*.example.com` превращает захват любого поддомена — заброшенного, чужого,
    поднятого через забытую CNAME — в кражу ключа. Список из трёх адресов
    руками дешевле, чем разбирательство, откуда взялись загрузки.

    Регистр схемы и хоста не значим, завершающая косая черта игнорируется:
    браузеры шлют `Origin` без неё, но настраивают список люди.
    """
    if not key.public or not key.origins:
        # Ветка ничего не охраняет: пустой список не совпал бы и так, а
        # `public` проверяет вызывающая сторона. Она здесь ради читателя —
        # чтобы «публичный ключ без origin не работает нигде» было видно
        # сразу, а не выводилось из того, что `any()` по пустому ложен.
        return False

    candidate = origin.strip().rstrip("/").lower()
    if not candidate or candidate == "null":
        # `Origin: null` шлют документы из песочницы и файлы с диска. Совпадать
        # с настроенным адресом оно не может, а выглядит как валидное значение.
        return False

    return any(candidate == allowed.strip().rstrip("/").lower() for allowed in key.origins)
