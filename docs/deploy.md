# Сборка и деплой

Прод — x86_64. Разработка может идти на arm64, поэтому платформа задаётся явно,
а не берётся из архитектуры машины сборки.

## Образы

```bash
make buildx-setup              # builder + эмуляция чужих архитектур, один раз
make images                    # собрать под linux/amd64, локально
make release NAMESPACE=dato1   # показать, что будет запушено
make push    NAMESPACE=dato1   # собрать и запушить
```

Текущие образы в Docker Hub:

```
dato1/vulnscantg-gateway
dato1/vulnscantg-worker
dato1/vulnscantg-bot
```

Переменные: `NAMESPACE` (аккаунт), `REGISTRY` (пусто — Docker Hub, иначе
`ghcr.io` и подобные), `PROJECT` (`vulnscantg`), `TAG` (короткий хэш коммита),
`PLATFORMS` (`linux/amd64`), `SERVICES`.

Docker Hub не поддерживает вложенные пространства имён, поэтому сервис входит
в имя образа через дефис, а не через слэш.

Мультиарх собирается тем же вызовом:
`make push NAMESPACE=... PLATFORMS=linux/amd64,linux/arm64`.

Перед push нужен `docker login`. Учётные данные в репозиторий не попадают.

**Видимость репозиториев.** На бесплатном тарифе Docker Hub новый репозиторий
создаётся публичным. Секретов в образах нет — конфигурация монтируется на
запуске, — но если образы должны быть приватными, переключите видимость в
настройках репозитория после первого push.

## Разворачивание на сервере

Сборки на сервере нет, только pull:

```bash
export IMAGE_TAG=<тег>          # или latest
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Оверлей `docker-compose.prod.yml` подменяет сборку на готовые образы, включает
подпись запросов и JSON-логи, снимает эмуляцию с `clamd` (на x86 она не нужна).
Секреты берутся из `.env` рядом с compose-файлом.

## Что нужно на хосте

| Компонент | Замечание |
|---|---|
| Redis | очередь, кэш, лимиты |
| S3-совместимое хранилище | карантин и обезвреженные файлы |
| clamd | официальный образ публикуется **только под amd64** |
| PostgreSQL | пока не используется, появится в M4 |

`clamav/clamav` под arm64 не собирается — на Apple Silicon в
`docker-compose.yml` для него задан `platform: linux/amd64` и он идёт через
эмуляцию. На x86-хосте это нативный запуск, и строку можно убрать.

## Обязательно поменять перед продом

```bash
HMAC_SECRET=<длинный случайный секрет>
REQUIRE_SIGNATURE=true
LOG_FORMAT=json
S3_ACCESS_KEY / S3_SECRET_KEY=<не minioadmin>
```

Плюс то, что помечено в [architecture.md §10](architecture.md): воркер должен
идти в песочнице (gVisor/nsjail) и иметь egress только в Redis, S3 и clamd.

## Проверка после развёртывания

```bash
curl -s http://ХОСТ:8080/readyz
```

```json
{"ready": true, "redis": true, "engine": "ClamAV 1.4.1/27100",
 "libmagic": "on", "dlq_size": 0}
```

Разбор ответа:

- `engine: unavailable` — воркер ещё не обращался к clamd. Появится после
  первого скана; если не появляется — демон недоступен, и с M1.7 это значит,
  что `clean` не будет выдаваться вовсе.
- `libmagic: off` — тип файла определяется только своей таблицей сигнатур.
  Работает, но беднее.
- `dlq_size` растёт — файлы не удаётся проверить, нужен разбор через
  `GET /v1/ops/dlq`.

Дымовой прогон:

```bash
make samples && make smoke
```

## Телеграм-бот

```bash
TELEGRAM_BOT_TOKEN=<токен от @BotFather> docker compose --profile bot up -d bot
```

Токен читается только из окружения. Без него контейнер поднимется, напишет об
этом в лог и остановится — это намеренно: молча работающий без токена бот
выглядел бы живым.

Бот забирает вложение, отправляет его сканеру и возвращает обезвреженную копию
либо отказ. Через Bot API скачиваются файлы до 20 МБ; для больших нужен
локальный Bot API server.
