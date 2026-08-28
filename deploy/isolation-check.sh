#!/bin/sh
# Проверка изоляции воркера: он разбирает недоверенные файлы и не должен
# иметь связи с внешним миром. Запускать после каждого изменения сети.
#
#   sh deploy/isolation-check.sh                      # локально
#   DOCKER_CONTEXT=prod sh deploy/isolation-check.sh   # на сервере
set -u
fail=0
say() { printf '  %-44s %s\n' "$1" "$2"; }
bad() { say "$1" "ПРОБЛЕМА: $2"; fail=1; }

svc() { docker compose ps -q "$1" 2>/dev/null | head -1; }
worker=$(svc worker)
[ -n "$worker" ] || { echo "воркер не запущен"; exit 1; }

echo "Изоляция воркера"

probe() {  # host port ожидание метка
    if docker exec "$worker" python -c "
import socket,sys
try: socket.create_connection(('$1', $2), timeout=5).close()
except Exception: sys.exit(1)
" 2>/dev/null; then got=да; else got=нет; fi
    if [ "$got" = "$3" ]; then say "$4" "доступен=$got"; else bad "$4" "доступен=$got, ожидалось $3"; fi
}

probe redis   6379 да  "redis — нужен для очереди"
probe minio   9000 да  "хранилище — нужно для файлов"
probe clamd   3310 да  "clamd — нужен для проверки"
probe 1.1.1.1 443  нет "произвольный адрес в интернете"
probe 169.254.169.254 80 нет "метаданные облака"

if docker exec "$worker" python -c "import socket; socket.gethostbyname('example.com')" 2>/dev/null; then
    bad "разрешение внешних имён" "работает"
else
    say "разрешение внешних имён" "не работает"
fi

echo
echo "Права воркера"
user=$(docker exec "$worker" id -u 2>/dev/null)
[ "$user" != "0" ] && say "пользователь" "uid $user, не root" || bad "пользователь" "root"

ro=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$worker" 2>/dev/null)
[ "$ro" = "true" ] && say "корневая ФС" "только чтение" || bad "корневая ФС" "доступна на запись"

caps=$(docker inspect -f '{{.HostConfig.CapDrop}}' "$worker" 2>/dev/null)
case "$caps" in *ALL*) say "capabilities" "сброшены";; *) bad "capabilities" "не сброшены: $caps";; esac

opts=$(docker inspect -f '{{.HostConfig.SecurityOpt}}' "$worker" 2>/dev/null)
case "$opts" in *no-new-privileges*) say "no-new-privileges" "включено";;
                *) bad "no-new-privileges" "выключено";; esac

runtime=$(docker inspect -f '{{.HostConfig.Runtime}}' "$worker" 2>/dev/null)
case "$runtime" in
    runsc*) say "рантайм" "$runtime (gVisor)";;
    *) say "рантайм" "$runtime — обычный, без ядерной изоляции";;
esac

echo
if [ "$fail" -eq 0 ]; then
  echo "Изоляция на месте."
else
  echo "Изоляция нарушена — см. ПРОБЛЕМА выше."
  echo
  echo "Если воркер подключён к сети мониторинга (lgtp) ради трейсов — это"
  echo "ожидаемо и временно. Она обычная bridge, и выход в интернет приходит"
  echo "вместе с ней. Вернуть изоляцию: убрать lgtp у worker и deepscan,"
  echo "поднять мост профилем observability и переключить их OTEL_ENDPOINT"
  echo "на http://vs-collector:4318/v1/traces"
fi
exit "$fail"
