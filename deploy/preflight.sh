#!/bin/sh
# Проверка перед запуском. Ловит то, что иначе всплывает циклом перезапуска.
set -u
fail=0

say()  { printf '  %-46s %s\n' "$1" "$2"; }
bad()  { say "$1" "ПРОБЛЕМА: $2"; fail=1; }

echo "Проверка каталога $(pwd)"

[ -f docker-compose.yml ] && say "docker-compose.yml" "есть" \
  || bad "docker-compose.yml" "файла нет — вы в том каталоге?"

if [ -f .env ]; then
  say ".env" "есть"
  for key in TELEGRAM_TOKEN HMAC_SECRET S3_ACCESS_KEY S3_SECRET_KEY; do
    value=$(grep "^$key=" .env 2>/dev/null | cut -d= -f2-)
    [ -n "$value" ] && say "  $key" "заполнен" || bad "  $key" "пустой"
  done
else
  bad ".env" "нет — скопируйте из .env.example"
fi

# Ровно тот случай, который валил gateway: Docker подменяет отсутствующий
# файл каталогом, и сервис получает «это каталог» вместо конфигурации.
if [ -d config ]; then
  say "config/" "есть"
  # Файлы, монтируемые в контейнер ПООТДЕЛЬНОСТИ. Отсутствующий Docker молча
  # создаёт каталогом, и контейнер падает с «not a directory» — именно так
  # однажды не поднялся clamd. Каталог тут хуже отсутствия: сервис получит
  # «это каталог» вместо конфигурации.
  for f in freshclam.conf; do
    if [ -d "config/$f" ]; then
      bad "  config/$f" "это КАТАЛОГ — Docker создал его вместо файла: rm -rf config/$f"
    elif [ -f "config/$f" ]; then
      say "  config/$f" "есть"
    else
      bad "  config/$f" "ОБЯЗАТЕЛЕН: без него clamd не стартует"
    fi
  done

  # Ключи доступа: без них gateway отвергает ВСЕ запросы. Умолчание в
  # аутентификации — дыра, поэтому пустого варианта здесь нет.
  if [ -d "config/keys.json" ]; then
    bad "  config/keys.json" "это КАТАЛОГ — удалите: rm -rf config/keys.json"
  elif [ -f "config/keys.json" ]; then
    say "  config/keys.json" "есть"
  else
    bad "  config/keys.json" "нет: gateway отвергнет все запросы, включая бота"
  fi

  for f in policies.json weights.json; do
    if [ -d "config/$f" ]; then
      bad "  config/$f" "это КАТАЛОГ — удалите: rm -rf config/$f"
    elif [ -f "config/$f" ]; then
      say "  config/$f" "есть"
    else
      say "  config/$f" "нет — будут встроенные значения"
    fi
  done
else
  say "config/" "нет — будут встроенные значения"
fi

for stale in policies.json weights.json; do
  [ -d "$stale" ] && bad "$stale" "каталог от прежней схемы, удалите: rm -rf $stale"
done

# Файлы профилей монтируются каталогом, поэтому «нет файла» больше не роняет
# контейнер — сервис скажет об этом сам. Но каталог на их месте остаётся от
# прежних неудачных запусков и мешает: он попадёт в контейнер вместо файла.
for f in prometheus.yml alerts.yml otel-collector.yaml Caddyfile; do
  if [ -d "config/$f" ]; then
    bad "  config/$f" "КАТАЛОГ от прежнего запуска — удалите: rm -rf config/$f"
  elif [ -f "config/$f" ]; then
    say "  config/$f" "есть"
  else
    say "  config/$f" "нет — нужен только для своего профиля"
  fi
done

# Обязательные переменные: compose падает без них намеренно.
if [ -f .env ]; then
  for key in POSTGRES_PASSWORD; do
    value=$(grep "^$key=" .env 2>/dev/null | cut -d= -f2-)
    [ -n "$value" ] && say "  $key" "заполнен" \
      || bad "  $key" "пустой: postgres не запустится"
  done
fi

command -v docker >/dev/null && say "docker" "$(docker --version | cut -d, -f1)" \
  || bad "docker" "не установлен"
docker compose version >/dev/null 2>&1 && say "docker compose" "есть" \
  || bad "docker compose" "плагин не установлен"

echo
[ "$fail" -eq 0 ] && echo "Всё в порядке: docker compose pull && docker compose up -d" \
  || echo "Есть проблемы — исправьте и запустите проверку снова."
exit "$fail"
