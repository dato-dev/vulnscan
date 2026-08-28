#!/bin/sh
# Установка gVisor и включение его как рантайма для воркера.
#
# Что делает: ставит пакет runsc, прописывает его в /etc/docker/daemon.json и
# ПЕРЕЗАПУСКАЕТ демон Docker. Перезапуск демона останавливает все контейнеры
# на хосте — выполнять в окно обслуживания.
#
# После установки поднимать с оверлеем:
#   docker compose -f docker-compose.yml -f docker-compose.gvisor.yml up -d
set -eu

echo "Будет установлен gVisor и перезапущен демон Docker."
echo "Все контейнеры на хосте остановятся. Продолжить? [y/N]"
read -r answer
[ "$answer" = "y" ] || { echo "отменено"; exit 1; }

ARCH=$(uname -m)
URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"

for file in runsc containerd-shim-runsc-v1; do
    wget -q "${URL}/${file}" "${URL}/${file}.sha512"
    sha512sum -c "${file}.sha512"
    rm -f "${file}.sha512"
    chmod 755 "$file"
    mv "$file" /usr/local/bin/
done

# Прописываем рантайм, сохраняя остальную конфигурацию демона.
python3 - <<'PY'
import json, pathlib
path = pathlib.Path("/etc/docker/daemon.json")
config = json.loads(path.read_text()) if path.exists() else {}
# Под runsc встроенный DNS Docker не работает: резолвер слушает на 127.0.0.11
# в сетевом пространстве хоста, а gVisor поднимает собственный стек со своим
# loopback. Флаг --reproduce-nat это НЕ лечит (проверено на сервере): он
# переносит правила NAT, но не самого слушателя. Обход — статические адреса
# и extra_hosts у воркера, см. deploy/docker-compose.yml.
config.setdefault("runtimes", {})["runsc"] = {"path": "/usr/local/bin/runsc"}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(config, indent=2))
print("рантайм runsc добавлен в", path)
PY

systemctl restart docker
echo
echo "Готово. Проверить: docker info --format '{{json .Runtimes}}'"
echo "Включить: docker compose -f docker-compose.yml -f docker-compose.gvisor.yml up -d"
echo "После включения обязательно замерьте латентность: gVisor её увеличивает."
