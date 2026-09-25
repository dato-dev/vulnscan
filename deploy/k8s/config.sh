#!/bin/sh
# Заливает policies.json и weights.json в ConfigMap — но только если они годны.
#
#   sh deploy/k8s/config.sh
#
# Зачем обёртка вокруг одной команды kubectl. `create configmap --from-file`
# кладёт в кластер что угодно: JSON с пропущенной запятой уедет молча и
# останется там жить. Сервис при этом НЕ ПАДАЕТ — он пишет ERROR и работает на
# значениях по умолчанию, то есть проверяет файлы по чужим порогам и не
# выгружает копии. В `kubectl get pods` всё зелёное.
#
# Так и вышло: битый policies.json пролежал в кластере, gateway каждые
# полминуты писал «файл политик не читается», а искали причину в notifier.
#
# Проверка идёт НАСТОЯЩИМ загрузчиком сервиса, а не `json.tool`: годный JSON
# и годная политика — разные вещи. Опечатка в имени поля даёт валидный JSON и
# неработающий приёмник.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
NS="${NAMESPACE:-vulnscan}"
POLICIES="$ROOT/deploy/config/policies.json"
WEIGHTS="$ROOT/deploy/config/weights.json"

for file in "$POLICIES" "$WEIGHTS"; do
	[ -f "$file" ] || { echo "ОШИБКА: нет $file" >&2; exit 1; }
done

PY="${PY:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY=python3

"$PY" - "$POLICIES" <<'CHECK' || exit 1
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "packages"))
root = Path(sys.argv[0]).resolve().parent.parent.parent
sys.path.insert(0, str(root / "packages"))

from vscommon.models import TenantPolicy
from vscommon.policy import build_policy

path = Path(sys.argv[1])
try:
    raw = json.loads(path.read_text())
except json.JSONDecodeError as exc:
    print(f"ОШИБКА: {path.name} не разбирается как JSON: {exc}", file=sys.stderr)
    print(f"  строка {exc.lineno}, столбец {exc.colno}", file=sys.stderr)
    raise SystemExit(1) from None

if not isinstance(raw, dict):
    print(f"ОШИБКА: {path.name} должен быть объектом «тенант → политика»", file=sys.stderr)
    raise SystemExit(1)

problems = 0
sinks = 0
for tenant, payload in raw.items():
    policy = build_policy(TenantPolicy(), tenant, payload)
    if policy.delivery_error:
        print(f"ОШИБКА: приёмник тенанта «{tenant}» негоден: {policy.delivery_error}", file=sys.stderr)
        problems += 1
    elif policy.delivery is not None:
        sinks += 1

if problems:
    raise SystemExit(1)

print(f"политик: {len(raw)}, с приёмником: {sinks}")
print("тенанты:", ", ".join(sorted(raw)))
CHECK

echo
echo "Имя тенанта — это НЕ идентификатор ключа доступа. Сверьте со списком выше:"
echo "  кому какой тенант принадлежит — видно в deploy/config/keys.json (поле tenant)."
echo

kubectl -n "$NS" create configmap vulnscan-policies \
	--from-file=policies.json="$POLICIES" \
	--from-file=weights.json="$WEIGHTS" \
	--dry-run=client -o yaml | kubectl apply -f -

echo
echo "Перезапускать ничего не нужно: ConfigMap смонтирован каталогом, gateway"
echo "перечитает его сам в течение минуты. Проверить, что подхватилось:"
echo "  kubectl -n $NS logs deployment/gateway --tail 50 | grep 'политики тенантов'"
