"""M11.15: гарантии из compose переехали в манифесты и не потерялись.

Это ровно то, что нельзя проверить чтением. Неверный `image:` роняет под — это
видно сразу. Пропущенный `readOnlyRootFilesystem` не роняет ничего: сервис
работает, файлы проверяются, и только периметр стал тоньше. Тот же класс, что
и весь M10, но цена ошибки выше.

Манифесты разбираются как файлы, а не через `kustomize build`: `make test`
обязан работать без внешних инструментов. Сборка проверяется отдельно и
пропускается там, где kubectl нет.
"""

from __future__ import annotations

import fnmatch
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).parent.parent
BASE = ROOT / "deploy/k8s/base"
BOT = ROOT / "deploy/k8s/bot"
POLICIES = ROOT / "deploy/k8s/policies"
GATEWAY = ROOT / "deploy/k8s/gateway"

# Периметр разбора недоверенного контента. Для этих двух правила строже.
UNTRUSTED = {"worker", "deepscan"}


def _documents(directory: Path) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        if path.name.endswith(".example.yaml"):
            # Шаблон секретов: в сборку не входит, проверять в нём нечего.
            continue
        found.extend(d for d in yaml.safe_load_all(path.read_text()) if d)
    return found


def _workloads(directory: Path = BASE) -> list[dict[str, Any]]:
    return [d for d in _documents(directory) if d.get("kind") in ("Deployment", "StatefulSet")]


def _pod(workload: dict[str, Any]) -> dict[str, Any]:
    return workload["spec"]["template"]["spec"]


def _name(workload: dict[str, Any]) -> str:
    return workload["metadata"]["name"]


def _policies(directory: Path = POLICIES) -> dict[str, dict[str, Any]]:
    return {
        d["metadata"]["name"]: d
        for d in _documents(directory)
        if d.get("kind") == "CiliumNetworkPolicy"
    }


# --- права процесса (M11.3) ------------------------------------------------


@pytest.mark.parametrize("workload", _workloads(), ids=_name)
def test_every_container_drops_privileges(workload: dict[str, Any]) -> None:
    """`cap_drop`, `no-new-privileges` и read-only корень переехали целиком.

    В compose это три строки на сервис. Здесь — два места (под и контейнер), и
    пропущенное поле выглядит точно так же, как намеренно опущенное.
    """
    for container in _pod(workload)["containers"]:
        security = container.get("securityContext", {})
        where = f"{_name(workload)}/{container['name']}"

        assert security.get("allowPrivilegeEscalation") is False, where
        assert security.get("capabilities", {}).get("drop") == ["ALL"], where
        assert security.get("readOnlyRootFilesystem") is True, where


@pytest.mark.parametrize("workload", _workloads(), ids=_name)
def test_nothing_runs_as_root(workload: dict[str, Any]) -> None:
    """Под не стартует от root, и профиль seccomp задан явно.

    `runAsNonRoot` без `runAsUser` недостаточно: образ без пользователя в
    метаданных тогда просто не запустится, и разбираться придётся на выкате.
    """
    pod = _pod(workload)

    assert pod["securityContext"]["runAsNonRoot"] is True, _name(workload)
    assert isinstance(pod["securityContext"].get("runAsUser"), int), _name(workload)
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault", _name(workload)


# --- учётные записи (M11.6) ------------------------------------------------


@pytest.mark.parametrize("workload", _workloads(), ids=_name)
def test_no_pod_carries_a_cluster_token(workload: dict[str, Any]) -> None:
    """Токен к API кластера не монтируется никому.

    Он монтируется ПО УМОЛЧАНИЮ, и для процесса, разбирающего враждебные
    файлы, это значит, что дыра в парсере даёт не «упал контейнер», а учётные
    данные к API. К API не ходит ни один наш сервис, поэтому исключений нет.
    """
    pod = _pod(workload)

    assert pod.get("automountServiceAccountToken") is False, _name(workload)
    assert pod.get("serviceAccountName") not in (None, "default"), _name(workload)


def test_every_workload_has_its_own_account() -> None:
    """Учётные записи не переиспользуются между сервисами.

    Прав нет ни у кого, и дело не в них: политики Cilium ссылаются на
    identity, и общая учётка лишает возможности их различать.
    """
    accounts = [_pod(w)["serviceAccountName"] for w in _workloads()]

    assert len(accounts) == len(set(accounts)), f"общая ServiceAccount: {accounts}"


# --- лимиты (M11.12) -------------------------------------------------------


@pytest.mark.parametrize("workload", _workloads(), ids=_name)
def test_every_container_has_limits(workload: dict[str, Any]) -> None:
    """Второй слой защиты от бомб.

    Первый — rlimits внутри `run_sandboxed`. Без внешнего разбор специально
    собранного файла выселит соседей по узлу.
    """
    for container in _pod(workload)["containers"]:
        limits = container.get("resources", {}).get("limits", {})
        where = f"{_name(workload)}/{container['name']}"

        assert limits.get("cpu"), where
        assert limits.get("memory"), where


# --- временные файлы (M11.2) -----------------------------------------------


@pytest.mark.parametrize("workload", [w for w in _workloads() if _name(w) in UNTRUSTED], ids=_name)
def test_scratch_space_lives_in_memory(workload: dict[str, Any]) -> None:
    """`WORK_DIR` — это память, а не диск.

    Правило «ничего не оседает на диске после обработки» держится именно на
    этом. `emptyDir` по умолчанию ДИСК, и разница не видна ни по логам, ни по
    вердиктам: сервис работает одинаково.

    `sizeLimit` обязателен: память тома считается в лимит пода, и без него
    бомба распаковки выселит под вместо того, чтобы упереться в лимит.
    """
    volumes = {v["name"]: v for v in _pod(workload)["volumes"]}

    for name in ("shm", "tmp"):
        empty = volumes[name].get("emptyDir")
        assert empty, f"{_name(workload)}: том {name} не emptyDir"
        assert empty.get("medium") == "Memory", f"{_name(workload)}: том {name} лёг на диск"
        assert empty.get("sizeLimit"), f"{_name(workload)}: у тома {name} нет sizeLimit"


# --- секреты не доезжают до разбора (D7) -----------------------------------


@pytest.mark.parametrize("workload", [w for w in _workloads() if _name(w) in UNTRUSTED], ids=_name)
def test_tenant_keys_never_reach_the_parser(workload: dict[str, Any]) -> None:
    """Воркеру монтируются политики, но не ключи тенантов.

    В compose `deploy/config` монтируется целиком, вместе с `keys.json`, и
    изоляция держится на незаданной переменной окружения, а не на правах
    доступа (D7). Здесь монтируется конкретный объект — и это тот самый
    момент, когда долг можно закрыть, а не перенести.
    """
    pod = _pod(workload)
    mounted = [v for v in pod["volumes"] if "secret" in v]

    assert not mounted, f"{_name(workload)}: смонтирован Secret {[v['name'] for v in mounted]}"

    for container in pod["containers"]:
        sources = [s for s in container.get("envFrom", []) if "secretRef" in s]
        names = [s["secretRef"]["name"] for s in sources]
        assert "vulnscan-keys" not in names, f"{_name(workload)}: ключи тенантов в окружении"


# --- сетевая изоляция (M11.1) ----------------------------------------------


def test_the_namespace_starts_from_deny() -> None:
    """Порядок «сначала запрет, потом разрешения» задан явно.

    Обратный («запретим лишнее») оставляет дыры, которых не видно. Пустые
    списки — это именно «ничего нельзя»: отсутствие ключа означало бы обратное.
    """
    deny = _policies()["default-deny"]

    assert deny["spec"]["endpointSelector"] == {}
    assert deny["spec"]["ingress"] == []
    assert deny["spec"]["egress"] == []


def test_the_parser_has_no_way_out() -> None:
    """У воркера нет ни одного правила, открывающего внешний мир.

    Это главная проверка файла политик. Добавленный сюда `toEntities: world`
    не сломает ничего видимого: файлы продолжат проверяться, и только выход в
    интернет у разбора враждебного контента появится.
    """
    egress = _policies()["worker"]["spec"]["egress"]

    for rule in egress:
        assert "toEntities" not in rule, f"воркеру открыт мир: {rule}"
        assert "toFQDNs" not in rule, f"воркеру открыто имя хоста: {rule}"
        assert "toCIDR" not in rule and "toCIDRSet" not in rule, f"воркеру открыт адрес: {rule}"
        assert "toEndpoints" in rule, f"правило без адресата: {rule}"


def test_the_policy_actually_selects_the_parser() -> None:
    """Политика воркера выбирает и worker, и deepscan.

    Селектор, промахнувшийся мимо пода, не ошибка применения: политика
    применится, а под останется под `default-deny` — или, если тот тоже
    промахнулся, без ограничений вовсе.
    """
    selector = _policies()["worker"]["spec"]["endpointSelector"]
    values = selector["matchExpressions"][0]["values"]

    assert set(values) == UNTRUSTED


ALLOWED_OUTWARD = {"cvdmirror", "notifier"}
"""Кому вообще можно наружу.

Зеркалу — за базами антивируса. Notifier — за коллбэками и выгрузкой копий в
хранилища клиентов. Больше никому, и в первую очередь не воркеру: он разбирает
враждебные файлы, и выход в сеть превращает дыру в парсере из «упал контейнер»
в канал наружу.
"""


def test_only_two_services_reach_the_internet() -> None:
    """Выход наружу есть ровно у двоих, и у обоих он ограничен портами.

    Ограничить зеркало ИМЕНЕМ хоста (`toFQDNs`) не вышло: это требует L7-прокси
    DNS, а он работает только когда Cilium подменяет kube-proxy. Список адресов
    CDN вместо имени — гонка, которую не выиграть, поэтому осталось честное
    «наружу по 443/80 с одного пода».

    Проверяется здесь то, что осталось проверяемым: список тех, кому наружу
    можно, и наличие ограничения по портам. Правило без `toPorts` открывает
    всё, включая то, о чём мы не подумали.
    """
    for name, policy in _policies().items():
        outward = [r for r in policy["spec"].get("egress", []) if "toEntities" in r]
        if not outward:
            continue

        assert name in ALLOWED_OUTWARD, f"{name} получил выход наружу"
        for rule in outward:
            assert "world" in rule["toEntities"], f"{name}: непонятная сущность {rule}"
            assert rule.get("toPorts"), f"{name}: выход наружу без ограничения по портам"


def test_the_mirror_can_fetch_databases() -> None:
    """У зеркала есть чем скачать базы.

    Пустой egress здесь означает, что базы не обновятся никогда, а заметно это
    станет через сутки — по возрасту баз, а не по отказу.
    """
    egress = _policies()["cvdmirror"]["spec"]["egress"]
    outward = [r for r in egress if "toEntities" in r or "toFQDNs" in r]

    assert outward, "зеркало никуда не ходит — базы не обновятся"


# --- состав поставки (M11.13) ----------------------------------------------


def test_clients_are_not_part_of_the_base() -> None:
    """Бот не приезжает «за компанию».

    Он не часть сервиса, а пример подключения: такой же интегратор, как форма
    обратной связи. У того, кто разворачивает проверку файлов для своей
    интеграции, бот не нужен, а без токена он ещё и не стартует.
    """
    names = {_name(w) for w in _workloads()}

    assert "bot" not in names
    assert "bot" in {_name(w) for w in _workloads(BOT)}


@pytest.mark.parametrize("target", [BASE, BOT], ids=["base", "bot"])
def test_no_component_builds_a_secret(target: Path) -> None:
    """Ни один компонент не раскатывает секреты вместе с манифестами.

    Шаблон со значениями «ЗАМЕНИТЕ», попав в `resources`, перезаписал бы
    рабочий токен заглушкой при первом же `apply -k`. У бота это выглядело бы
    как отвалившийся Telegram, у сервиса — как `401` на подписанные запросы,
    то есть как проблема на стороне клиента.
    """
    listed = yaml.safe_load((target / "kustomization.yaml").read_text())["resources"]

    for name in listed:
        path = target / name
        if not path.is_file():
            continue
        kinds = {d.get("kind") for d in yaml.safe_load_all(path.read_text()) if d}
        assert "Secret" not in kinds, f"{target.name}/{name}: Secret в сборке"


def test_the_secret_template_is_not_applied() -> None:
    """Шаблон секретов не входит в сборку.

    Попав в неё, он перезаписал бы настоящие ключи заглушками при первом же
    `apply -k`, и сервис отвечал бы `401` на подписанные запросы — а выглядело
    бы это как проблема на стороне клиента.
    """
    listed = yaml.safe_load((BASE / "kustomization.yaml").read_text())["resources"]

    assert "secrets.example.yaml" not in listed
    assert (BASE / "secrets.example.yaml").is_file(), "шаблон пропал — его нечем заменить"


def test_the_mirror_stays_alone() -> None:
    """У зеркала строго одна реплика.

    Ограничение внешнее: CDN ClamAV банит за частые скачивания, ради чего
    зеркало и заводилось. Две реплики качают одно и то же и ловят бан на двоих.
    """
    mirror = next(w for w in _workloads() if _name(w) == "cvdmirror")

    assert mirror["spec"]["replicas"] == 1


# --- метрики (M11.14) ------------------------------------------------------


def test_metrics_ports_match_the_agreement() -> None:
    """Порт задаётся в коде, в манифесте и в объекте скрейпа — и расходятся они
    молча (M10.9). Здесь сверяется манифест с договорённостью из docs/metrics.md.
    """
    expected = {"worker": 9100, "deepscan": 9100, "writer": 9101, "notifier": 9103}

    for workload in _workloads():
        name = _name(workload)
        if name not in expected:
            continue
        container = _pod(workload)["containers"][0]
        ports = {p["name"]: p["containerPort"] for p in container["ports"]}
        env = {e["name"]: e.get("value") for e in container["env"]}

        assert ports["metrics"] == expected[name], name
        assert env["METRICS_PORT"] == str(expected[name]), f"{name}: порт в env разошёлся"


# --- сборка ----------------------------------------------------------------


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="нужен kubectl для kustomize")
@pytest.mark.parametrize(
    "target",
    [BASE, POLICIES, BOT, GATEWAY, ROOT / "deploy/k8s/monitoring"],
    ids=["base", "policies", "bot", "gateway", "monitoring"],
)
def test_the_overlay_builds(target: Path) -> None:
    """`kustomize build` каждого оверлея. Сломанная база иначе обнаружится на выкате."""
    done = subprocess.run(
        ["kubectl", "kustomize", str(target)], capture_output=True, text=True, check=False
    )

    assert done.returncode == 0, done.stderr
    assert list(yaml.safe_load_all(done.stdout))


# --- состав сборки ---------------------------------------------------------


def _kustomization() -> dict[str, Any]:
    return yaml.safe_load((BASE / "kustomization.yaml").read_text())


def test_the_build_carries_no_secret() -> None:
    """В собранной базе нет ни одного объекта `Secret`.

    Рядом с манифестами лежит файл с настоящими ключами — он в `.gitignore` и
    в сборку не входит. Стоит ему попасть в `resources`, и `kubectl apply -k`
    начнёт раскатывать секреты вместе с манифестами: сначала это выглядит
    удобно, а заканчивается тем, что ротация ключа требует правки манифеста, а
    сам манифест нельзя показать никому.

    Секреты создаёт `deploy/k8s/secrets.sh` из тех же файлов, что читает
    compose.
    """
    listed = _kustomization()["resources"]
    offenders = []

    for name in listed:
        path = BASE / name
        if not path.is_file():
            continue
        kinds = {d.get("kind") for d in yaml.safe_load_all(path.read_text()) if d}
        if "Secret" in kinds:
            offenders.append(name)

    assert not offenders, f"Secret в сборке: {offenders}"


def test_every_manifest_is_listed() -> None:
    """Каждый манифест базы перечислен в `kustomization.yaml`.

    Файл, забытый в списке, не ломает сборку — он просто не применяется. Для
    политики Cilium это значит, что поды работают без неё, и выглядит это как
    исправная работа.

    Исключения только два: шаблон секретов и файл с настоящими значениями,
    если он у вас есть.
    """
    listed = set(_kustomization()["resources"])
    present = {
        path.name
        for path in BASE.glob("*.yaml")
        if path.name != "kustomization.yaml" and not path.name.startswith("secrets")
    }

    assert present - listed == set(), f"манифест не попал в сборку: {sorted(present - listed)}"
    assert listed - present == set(), f"в сборке файл, которого нет: {sorted(listed - present)}"


# --- внешний вход ----------------------------------------------------------


def _gateway() -> dict[str, Any]:
    return next(d for d in _documents(GATEWAY) if d.get("kind") == "Gateway")


def _route() -> dict[str, Any]:
    return next(d for d in _documents(BASE) if d.get("kind") == "HTTPRoute")


def test_the_gateway_lets_the_application_in() -> None:
    """Listener разрешает привязку маршрутов из namespace приложения.

    Разрешение живёт в Gateway, а не в маршруте, и это главная тихая поломка
    Gateway API: маршрут применяется без ошибки, объект существует, трафика
    нет. Причина написана только в `status.parents[].conditions` —
    `NotAllowedByListeners`.

    Здесь сверяется, что селектор listener'а указывает на тот же namespace,
    в который kustomize кладёт приложение. Переименуют namespace — тест
    упадёт, а не кластер.
    """
    namespace = yaml.safe_load((BASE / "kustomization.yaml").read_text())["namespace"]

    for listener in _gateway()["spec"]["listeners"]:
        allowed = listener["allowedRoutes"]["namespaces"]
        where = listener["name"]

        if allowed["from"] == "All":
            continue
        assert allowed["from"] == "Selector", f"{where}: непонятное правило привязки"
        labels = allowed["selector"]["matchLabels"]
        assert labels.get("kubernetes.io/metadata.name") == namespace, (
            f"listener {where} не пускает маршруты из namespace «{namespace}»"
        )


def test_the_route_hostname_fits_the_listener() -> None:
    """Имя хоста маршрута попадает под шаблон listener'а.

    Непересечение даёт `NoMatchingListenerHostname` — отказ того же рода:
    видимый только в статусе маршрута.
    """
    listeners = [listener.get("hostname") for listener in _gateway()["spec"]["listeners"]]
    hostnames = _route()["spec"].get("hostnames", [])

    assert hostnames, "маршрут без hostnames примет что угодно — так не задумано"
    for hostname in hostnames:
        fits = any(pattern is None or fnmatch.fnmatch(hostname, pattern) for pattern in listeners)
        assert fits, f"{hostname} не попадает ни под один listener: {listeners}"


def test_clamd_starts_without_root() -> None:
    """clamd запускается непривилегированным скриптом образа.

    Штатный `/init` первым делом делает `chown -R` на каталоге баз — «на
    случай, если это смонтированный том». Под non-root без CAP_CHOWN это
    `Operation not permitted`, а скрипт идёт с `set -e`: под не стартует.

    Соблазнительный выход — разрешить поду root. Он и опасен: clamd разбирает
    враждебные файлы, и привилегии ему нужны ровно на одну строку стартового
    скрипта, которая нам не нужна вовсе (владельца тома выставляет `fsGroup`).
    Образ предусматривает `/init-unprivileged` — тот же скрипт без chown.

    Тест держит связку: вернёшь штатный entrypoint — придётся вернуть и root.
    """
    clamd = next(w for w in _workloads() if _name(w) == "clamd")
    container = _pod(clamd)["containers"][0]

    assert container.get("command") == ["/init-unprivileged"], (
        "clamd запускается штатным /init — он упадёт на chown под non-root"
    )
    assert _pod(clamd)["securityContext"]["runAsNonRoot"] is True


def test_the_freshclam_config_matches_the_one_that_works() -> None:
    """Конфигурация freshclam в кластере совпадает с рабочей из compose.

    Она здесь копией, и копия — источник ошибок: первая версия была написана
    заново, по памяти, и разъехалась с оригиналом сразу в трёх местах. Адрес
    без схемы («http://» подставляется как «https://», и freshclam стучится по
    TLS в порт простого HTTP), пропущенный `DNSDatabaseInfo no` и `Foreground
    true` вместо `yes`.

    Сообщение при этом — «Could not connect to server», по нему не догадаться
    ни про схему, ни про TXT-запрос.

    Сверяются все директивы, кроме адреса зеркала: он в кластере другой по
    определению. Держать один файл на оба выката нельзя — kustomize не пускает
    `configMapGenerator` за пределы своего каталога.
    """
    source = (ROOT / "deploy/config/freshclam.conf").read_text()
    config = next(
        d for d in _documents(BASE) if d.get("metadata", {}).get("name") == "vulnscan-freshclam"
    )
    deployed = config["data"]["freshclam.conf"]

    def directives(text: str) -> dict[str, str]:
        found = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(" ")
            found[key] = value.strip()
        return found

    want = directives(source)
    have = directives(deployed)
    want.pop("DatabaseMirror")
    mirror = have.pop("DatabaseMirror", "")

    assert have == want, f"конфигурация разошлась с deploy/config/freshclam.conf: {have} != {want}"
    assert mirror.startswith("http://"), (
        f"адрес зеркала без схемы — freshclam пойдёт по https: {mirror!r}"
    )


@pytest.mark.parametrize(
    "workload", [w for w in _workloads() if w["kind"] == "StatefulSet"], ids=_name
)
def test_a_volume_is_claimed_or_ephemeral_but_not_both(workload: dict[str, Any]) -> None:
    """Имя тома не объявлено одновременно в `volumes` и `volumeClaimTemplates`.

    Kubernetes такой манифест принимает и разрешает конфликт в пользу
    `volumes`: PVC создаётся, подключается к StatefulSet, показывается в
    `kubectl get pvc` — и не используется. Данные живут в emptyDir и исчезают
    с подом.

    Для clamd это значит полную перекачку баз при каждом перезапуске: снаружи
    похоже на медленный старт, а не на потерю тома.
    """
    volumes = {v["name"] for v in _pod(workload).get("volumes", [])}
    claims = {c["metadata"]["name"] for c in workload["spec"].get("volumeClaimTemplates", [])}

    assert not volumes & claims, (
        f"{_name(workload)}: том {sorted(volumes & claims)} объявлен дважды — PVC не используется"
    )


# --- выход наружу через прокси ---------------------------------------------


def _secret_refs(workload: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    for container in _pod(workload)["containers"]:
        for source in container.get("envFrom", []):
            if "secretRef" in source:
                refs.add(source["secretRef"]["name"])
    return refs


def test_the_proxy_stays_with_the_bot() -> None:
    """Адрес прокси не попадает ни в один сервис — только в бота.

    Прокси заведён ради одного: Telegram из России напрямую недоступен. Это
    свойство КЛИЕНТА, а не сервиса. В нём логин и пароль, и в общем namespace
    он оказался бы рядом с воркером, который разбирает враждебные файлы.
    """
    for workload in _workloads():
        refs = _secret_refs(workload)
        proxied = {name for name in refs if "proxy" in name}
        assert not proxied, f"{_name(workload)} получил адрес прокси: {sorted(proxied)}"


def test_the_bot_can_reach_telegram_through_a_proxy() -> None:
    """У бота прокси есть — и подключён необязательным.

    `optional` обязателен: там, где прокси не нужен, Secret отсутствует, и без
    флага под не стартовал бы вовсе.
    """
    bot = next(w for w in _workloads(BOT) if _name(w) == "bot")
    container = _pod(bot)["containers"][0]

    refs = [s["secretRef"] for s in container["envFrom"] if "secretRef" in s]
    proxy = next((r for r in refs if "proxy" in r["name"]), None)

    assert proxy, "бот не сможет выйти в Telegram там, где нужен прокси"
    assert proxy.get("optional") is True, "прокси обязателен — без него бот не стартует"


def test_the_callback_address_matches_the_bot_namespace() -> None:
    """`WEBHOOK_URL` указывает на namespace, в котором бот на самом деле живёт.

    Gateway проверяет адрес коллбэка ТОЧНЫМ совпадением хоста со списком в
    ключе, и делает это на приёме файла. Разошлись имена — запрос отвергнут, а
    сообщение намеренно не называет ожидаемый хост: ответ уходит клиенту, и
    подсказывать ему состав списка незачем.

    Здесь сверяется хотя бы то, что поддаётся проверке из репозитория: адрес в
    окружении бота и namespace, в который его кладёт kustomize.
    """
    namespace = yaml.safe_load((BOT / "kustomization.yaml").read_text())["namespace"]
    config = next(d for d in _documents(BOT) if d.get("metadata", {}).get("name") == "bot-env")
    webhook = config["data"]["WEBHOOK_URL"]

    assert f"bot.{namespace}.svc" in webhook, (
        f"адрес коллбэка {webhook!r} не совпадает с namespace «{namespace}»"
    )


# --- перезапуск при смене конфигурации -------------------------------------

RELOADER = "reloader.stakater.com/auto"


@pytest.mark.parametrize("workload", [*_workloads(), *_workloads(BOT)], ids=lambda w: _name(w))
def test_every_workload_restarts_on_config_change(workload: dict[str, Any]) -> None:
    """Смена секрета доезжает до процесса, а не остаётся в объекте.

    Нужно это ровно там, где обновление не приходит само. Переменные окружения
    читаются один раз при старте. Секреты, смонтированные через `subPath` —
    как `keys.json` и `delivery.json` у notifier, — не обновляются ВООБЩЕ: два
    разных Secret в один каталог иначе не положить.

    Без перезапуска ротация ключа выглядит завершённой: объект в кластере
    новый, процесс работает со старым, и обнаруживается это на первом
    подписанном запросе от клиента.
    """
    annotations = workload["metadata"].get("annotations", {})

    assert annotations.get(RELOADER) == "true", f"{_name(workload)}: нет автоперезапуска"


def test_the_policy_configmap_is_left_alone() -> None:
    """Политики перезагружаются на живую, и перезапускать под ради них нельзя.

    `PolicyRegistry` и `WeightTable` следят за mtime файла — правка порогов не
    должна ронять приём. Автоперезапуск отменил бы этот механизм: вместо
    горячей перезагрузки поды уходили бы в рестарт при каждой правке.

    Снаружи разницы почти не видно — кроме коротких отказов на приёме. То есть
    механизм остался бы, тесты на него остались бы, а работало бы другое.
    """
    config = next(
        d for d in _documents(BASE) if d.get("metadata", {}).get("name") == "vulnscan-policies"
    )

    assert config["metadata"]["annotations"]["reloader.stakater.com/ignore"] == "true"


# --- обновление образов ----------------------------------------------------


@pytest.mark.parametrize("workload", [*_workloads(), *_workloads(BOT)], ids=_name)
def test_the_pull_policy_is_left_to_kubernetes(workload: dict[str, Any]) -> None:
    """`imagePullPolicy` не задан явно, и это осознанно.

    Умолчание Kubernetes зависит от тега: `Always` для плавающего, вроде
    `latest`, и `IfNotPresent` для конкретного. Это ровно то поведение, которое
    нужно, и оно само подстраивается под то, чем помечен образ.

    Явный `IfNotPresent` ломает первую половину: узел, однажды скачавший
    `latest`, остаётся с ним навсегда. `rollout restart` при этом отрабатывает
    успешно, поды пересоздаются, версия не меняется — и выглядит это так,
    будто выкатили не то, что собрали.
    """
    containers = [*_pod(workload)["containers"], *_pod(workload).get("initContainers", [])]

    for container in containers:
        policy = container.get("imagePullPolicy")
        assert policy != "IfNotPresent", (
            f"{_name(workload)}/{container['name']}: IfNotPresent не даст обновить плавающий тег"
        )


def test_the_tag_is_set_in_one_place() -> None:
    """Версия образов задаётся в kustomization, а не в шести файлах.

    Разъехавшиеся теги дают самый неприятный вид отказа: часть сервиса новая,
    часть старая, и контракт между ними уже другой.
    """
    kustomization = yaml.safe_load((BASE / "kustomization.yaml").read_text())
    pinned = {entry["name"] for entry in kustomization.get("images", [])}

    used = set()
    for workload in _workloads():
        for container in _pod(workload)["containers"]:
            image = container["image"]
            if image.startswith("dato1/"):
                used.add(image.rsplit(":", 1)[0])

    assert used <= pinned, f"образ вне списка kustomization: {sorted(used - pinned)}"


# --- скрейп метрик (M11.14) ------------------------------------------------

MONITORING = ROOT / "deploy/k8s/monitoring"
COMPOSE_PROMETHEUS = ROOT / "deploy/lgtp/prometheus/prometheus.yml"

# Где сервис отдаёт метрики. У gateway отдельного порта нет — `/metrics` на
# его HTTP-порту (docs/metrics.md).
METRICS_PORT_NAME = {"gateway": "http"}


def _pod_monitors() -> list[dict[str, Any]]:
    return [d for d in _documents(MONITORING) if d.get("kind") == "PodMonitor"]


def _selects(selector: dict[str, Any], labels: dict[str, str]) -> bool:
    for key, value in selector.get("matchLabels", {}).items():
        if labels.get(key) != value:
            return False
    for expression in selector.get("matchExpressions", []):
        present = labels.get(expression["key"])
        if expression["operator"] == "In" and present not in expression["values"]:
            return False
        if expression["operator"] == "NotIn" and present in expression["values"]:
            return False
    return True


def _job_after_relabeling(endpoint: dict[str, Any], app: str) -> str | None:
    """Прогоняет `relabelings` так, как это сделает Prometheus, — для метки job.

    Поддержано ровно то, что используется: действие `replace` с источником
    `__meta_kubernetes_pod_label_app` или без источника. Встретится что-то
    другое — тест упадёт на KeyError, а не соврёт.
    """
    import re as _re

    job = None
    for rule in endpoint.get("relabelings", []):
        if rule.get("targetLabel") != "job":
            continue
        assert rule.get("action", "replace") == "replace", rule
        sources = rule.get("sourceLabels", [])
        value = ";".join(app if s == "__meta_kubernetes_pod_label_app" else "" for s in sources)
        match = _re.fullmatch(rule.get("regex", "(.*)"), value)
        if match:
            job = match.expand(rule.get("replacement", "$1").replace("$1", r"\1"))
    return job


def _compose_jobs_by_host() -> dict[str, str]:
    """Хост цели → имя job в стеке compose. Источник контракта для панелей."""
    config = yaml.safe_load(COMPOSE_PROMETHEUS.read_text())
    jobs: dict[str, str] = {}
    for job in config["scrape_configs"]:
        if not job["job_name"].startswith("vulnscantg-"):
            continue
        for static in job.get("static_configs", []):
            for target in static["targets"]:
                jobs[target.split(":")[0]] = job["job_name"]
    return jobs


def _scraped(workload: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Пары (монитор, endpoint), которые снимают метрики с этого пода."""
    namespace = workload["metadata"].get("namespace")
    labels = workload["spec"]["template"]["metadata"]["labels"]
    port = METRICS_PORT_NAME.get(_name(workload), "metrics")

    found = []
    for monitor in _pod_monitors():
        if monitor["metadata"]["namespace"] != namespace:
            continue
        if not _selects(monitor["spec"]["selector"], labels):
            continue
        for endpoint in monitor["spec"]["podMetricsEndpoints"]:
            if endpoint["port"] == port:
                found.append((monitor, endpoint))
    return found


def _serves_metrics(workload: dict[str, Any]) -> bool:
    ports = {p["name"] for c in _pod(workload)["containers"] for p in c.get("ports", [])}
    return METRICS_PORT_NAME.get(_name(workload), "metrics") in ports


@pytest.mark.parametrize(
    "workload",
    [w for w in [*_workloads(), *_workloads(BOT)] if _serves_metrics(w)],
    ids=_name,
)
def test_every_metrics_port_is_scraped(workload: dict[str, Any]) -> None:
    """Под, отдающий метрики, выбран монитором — ровно одним.

    Правило M10.9 в манифестах: порт задаётся в коде, в манифесте и в объекте
    скрейпа, и расходятся они молча. Не выбранный монитором под не даёт
    ошибки — у него просто нет цели в Prometheus, и панели по нему пусты так
    же, как при отсутствии событий. Два монитора на один под дали бы двойной
    счёт в каждом `sum()`.
    """
    scraped = _scraped(workload)

    assert scraped, f"{_name(workload)} отдаёт метрики, но ни один монитор их не снимает"
    assert len(scraped) == 1, f"{_name(workload)} снимается дважды: двойной счёт в панелях"


@pytest.mark.parametrize(
    "workload",
    [w for w in [*_workloads(), *_workloads(BOT)] if _serves_metrics(w)],
    ids=_name,
)
def test_job_names_match_the_compose_stack(workload: dict[str, Any]) -> None:
    """Имя job в кластере то же, что в compose.

    Панели и алерты ищут сервисы по `job=~"vulnscantg.*"`. PodMonitor по
    умолчанию называет job `<namespace>/<монитор>` — под шаблон это не
    попадает, и панели пустеют без единой ошибки: цели зелёные, метрики
    собираются, запрос к ним возвращает пустоту.

    Сверка идёт с compose, а не с шаблоном: одинаковые имена в обоих выкатах
    значат, что любая панель и любой алерт работают там и там, в том числе
    написанные потом с точным совпадением.
    """
    expected = _compose_jobs_by_host()[_name(workload)]
    ((_, endpoint),) = _scraped(workload)

    assert _job_after_relabeling(endpoint, _name(workload)) == expected


def test_the_mirror_file_server_is_not_scraped() -> None:
    """Порт раздачи баз у зеркала не принимается за порт метрик.

    Он тоже называется `http`, как у gateway, и общий монитор по имени порта
    снимал бы `cvdmirror:8000/metrics`, получал 404 и держал в Prometheus
    вечно красную цель — то есть приучал бы не смотреть на красные.
    """
    mirror = next(w for w in _workloads() if _name(w) == "cvdmirror")
    labels = mirror["spec"]["template"]["metadata"]["labels"]

    for monitor in _pod_monitors():
        if not _selects(monitor["spec"]["selector"], labels):
            continue
        ports = {e["port"] for e in monitor["spec"]["podMetricsEndpoints"]}
        assert "http" not in ports, f"{monitor['metadata']['name']} снимает раздачу файлов"


def test_monitoring_is_not_part_of_the_base() -> None:
    """Мониторы не входят в базу.

    PodMonitor — CRD prometheus-operator. В кластере без него
    `kubectl apply -k base` падал бы на «no matches for kind», и сервис не
    разворачивался бы из-за мониторинга.
    """
    kinds = {d.get("kind") for d in _documents(BASE)}

    assert not kinds & {"PodMonitor", "ServiceMonitor", "PrometheusRule"}


def test_the_scraper_is_let_in_everywhere_the_same_way() -> None:
    """Политики пускают скрейп на порт метрик — из одного и того же namespace.

    Порт метрик живёт в трёх местах: в контейнере, в мониторе и в политике.
    Разойдись третье, и после применения политик цель станет недоступной —
    с той же пустотой на панелях. А namespace Prometheus записан в каждой
    политике отдельно; разные значения в разных правилах означали бы, что
    часть сервисов снимается, а часть нет.
    """
    policies = _policies()
    scrapers: set[str] = set()

    for workload in _workloads():
        if not _serves_metrics(workload):
            continue
        name = _name(workload)
        port_name = METRICS_PORT_NAME.get(name, "metrics")
        number = next(
            p["containerPort"]
            for c in _pod(workload)["containers"]
            for p in c.get("ports", [])
            if p["name"] == port_name
        )
        labels = workload["spec"]["template"]["metadata"]["labels"]

        allowed = set()
        for policy in policies.values():
            if not policy["spec"].get("endpointSelector") or not _selects(
                policy["spec"]["endpointSelector"], labels
            ):
                continue
            for rule in policy["spec"].get("ingress", []):
                ports = {p["port"] for tp in rule.get("toPorts", []) for p in tp["ports"]}
                if str(number) not in ports:
                    continue
                for peer in rule.get("fromEndpoints", []):
                    namespace = peer.get("matchLabels", {}).get("io.kubernetes.pod.namespace")
                    if namespace and namespace != "vulnscan":
                        allowed.add(namespace)

        assert allowed, f"{name}: политика не пускает скрейп на порт {number}"
        scrapers |= allowed

    assert len(scrapers) == 1, f"скрейп пускается из разных namespace: {sorted(scrapers)}"


def test_gateway_trusts_scheme_from_gateway_api() -> None:
    """За Gateway API до gateway доходит HTTP, а браузер видит HTTPS.

    Без `FORWARDED_ALLOW_IPS` uvicorn верит `X-Forwarded-Proto` только с
    127.0.0.1, считает схему `http`, и рамка виджета со своим Origin
    `https://…` не узнаёт в сервисе себя: талон не выдаётся, посетитель видит
    «ключ сайта недействителен». Найдено на живом кластере.
    """
    import yaml

    documents = yaml.safe_load_all((BASE / "10-config.yaml").read_text())
    env = next(d for d in documents if d and d.get("metadata", {}).get("name") == "vulnscan-env")

    assert env["data"].get("FORWARDED_ALLOW_IPS"), "gateway не доверяет схеме от Gateway API"
