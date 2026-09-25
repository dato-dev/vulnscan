#!/bin/sh
# Режим аудита политик Cilium: правила считаются, но не применяются.
#
#   sh deploy/k8s/audit.sh on  clamd-0 cvdmirror-0
#   sh deploy/k8s/audit.sh off clamd-0 cvdmirror-0
#   sh deploy/k8s/audit.sh status clamd-0
#
# Зачем это, а не «снять политики на время». Снятая политика не отвечает на
# вопрос, чего не хватало: под работает, и список нужных разрешений приходится
# угадывать. В режиме аудита трафик проходит, а Hubble помечает вердиктом
# `AUDIT` ровно то, что было бы отброшено, — то есть выдаёт готовый список.
#
# Смотреть результат:
#   hubble observe --namespace vulnscan --verdict AUDIT --last 100
#
# ВАЖНО: режим живёт на endpoint, а не на поде. Пересоздали под — включайте
# заново. Это защита от того, чтобы аудит остался включённым навсегда: забытый
# аудит выглядит как работающая политика и не защищает ничего.
set -eu

action="${1:?укажите on | off | status}"
shift || true
[ "$#" -gt 0 ] || { echo "укажите имена подов, например clamd-0" >&2; exit 1; }

case "$action" in
on) value=Enabled ;;
off) value=Disabled ;;
status) value="" ;;
*) echo "неизвестное действие: $action" >&2; exit 1 ;;
esac

for pod in "$@"; do
	node=$(kubectl -n vulnscan get pod "$pod" -o jsonpath='{.spec.nodeName}')
	[ -n "$node" ] || { echo "$pod: под не найден" >&2; continue; }

	agent=$(kubectl -n kube-system get pod -l k8s-app=cilium \
		--field-selector "spec.nodeName=$node" \
		-o jsonpath='{.items[0].metadata.name}')
	[ -n "$agent" ] || { echo "$pod: на узле $node нет агента cilium" >&2; continue; }

	# Идентификатор endpoint'а ищем по имени пода, а не глазами в таблице:
	# в списке их десятки, и ошибиться строкой — значит включить аудит
	# чужому поду.
	id=$(kubectl -n kube-system exec "$agent" -c cilium-agent -- \
		cilium-dbg endpoint list -o json |
		python3 -c "
import json, sys
name = '$pod'
for endpoint in json.load(sys.stdin):
    ids = endpoint.get('status', {}).get('external-identifiers', {})
    if ids.get('k8s-pod-name') == name:
        print(endpoint['id'])
        break
")
	[ -n "$id" ] || { echo "$pod: endpoint не найден на $node" >&2; continue; }

	if [ -z "$value" ]; then
		echo "$pod (endpoint $id, узел $node):"
		kubectl -n kube-system exec "$agent" -c cilium-agent -- \
			cilium-dbg endpoint get "$id" -o json |
			python3 -c "
import json, sys
spec = json.load(sys.stdin)[0].get('spec', {})
print('  PolicyAuditMode:', spec.get('options', {}).get('PolicyAuditMode', '?'))
"
	else
		kubectl -n kube-system exec "$agent" -c cilium-agent -- \
			cilium-dbg endpoint config "$id" "PolicyAuditMode=$value" >/dev/null
		echo "$pod (endpoint $id, узел $node): PolicyAuditMode=$value"
	fi
done

[ "$action" = "on" ] && cat <<'NOTE'

Дальше:
  hubble observe --namespace vulnscan --verdict AUDIT --last 100

Каждая строка AUDIT — это правило, которого не хватает. Соберите список,
допишите политики, выключите аудит (`audit.sh off ...`) и убедитесь, что
записей AUDIT больше нет.
NOTE
exit 0
