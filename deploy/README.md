# Разворачивание на сервере

Нужен Linux x86_64 с Docker и compose-плагином. Сборки на сервере нет — только
готовые образы из Docker Hub.

Структура каталога:

```
docker-compose.yml
.env               ← создаётся из .env.example, в git не попадает
preflight.sh
config/
  policies.json    ← необязателен: без него работают встроенные значения
  weights.json     ← то же
```

Конфигурация монтируется **каталогом**, а не отдельными файлами: Docker молча
подменяет отсутствующий файл bind-mount каталогом, и сервис получал бы
«это каталог» вместо настроек.

## 1. Перенести каталог

```bash
scp -r deploy/ пользователь@сервер:~/vulnscan
ssh пользователь@сервер
cd ~/vulnscan
```

## 2. Заполнить .env

```bash
cp .env.example .env
```

Три обязательных значения:

```bash
# токен бота — получить у @BotFather, никому не показывать
TELEGRAM_TOKEN=...

# секреты — сгенерировать прямо на сервере
HMAC_SECRET=$(openssl rand -hex 32)
S3_ACCESS_KEY=$(openssl rand -hex 16)
S3_SECRET_KEY=$(openssl rand -hex 24)
```

Быстрый вариант для последних трёх:

```bash
sed -i "s|^HMAC_SECRET=.*|HMAC_SECRET=$(openssl rand -hex 32)|;
        s|^S3_ACCESS_KEY=.*|S3_ACCESS_KEY=$(openssl rand -hex 16)|;
        s|^S3_SECRET_KEY=.*|S3_SECRET_KEY=$(openssl rand -hex 24)|" .env
```

Токен впишите руками — в командную строку он попадать не должен, она
сохраняется в истории shell.

## 3. Проверить перед запуском

```bash
./preflight.sh
```

Ловит заполненность `.env` и подмену конфигурационных файлов каталогами —
Docker создаёт каталог на месте отсутствующего файла bind-mount, и это самый
частый способ получить цикл перезапуска.

## 4. Запустить

```bash
docker compose pull
docker compose up -d
```

Первый запуск занимает несколько минут: `clamd` скачивает сигнатурные базы
(около 300 МБ). До этого он не в состоянии `healthy`, и воркеры ждут его.

## 5. Проверить

```bash
docker compose ps
docker compose exec gateway python -c "
import urllib.request; print(urllib.request.urlopen('http://localhost:8080/readyz').read().decode())"
```

Ожидается:

```json
{"ready": true, "redis": true,
 "engine": "ClamAV 1.4.x/...", "libmagic": "on", "dlq_size": 0}
```

- `engine: unavailable` — воркер не достучался до clamd. С этим сервис работает,
  но вердикт `clean` выдаваться не будет вовсе: проверка считается неполной.
- `libmagic: off` — тип файла определяется только своей таблицей сигнатур.
- `dlq_size` растёт — файлы не удаётся проверить, смотрите `/v1/ops/dlq`.
- `config: degraded` — файл политик или весов задан, но не читается. Сервис
  работает на встроенных значениях, то есть настройки тенантов не применены.

## 6. Попробовать бота

Напишите боту в Telegram и пришлите PDF или фотографию. Ожидаемое поведение:

| Что отправили | Что придёт |
|---|---|
| обычный PDF или фото | 🟢 обезвреженная копия файлом |
| документ с активным содержимым | 🔴 заблокирован |
| файл под паролем | ⚠️ содержимое проверить не удалось |
| больше 20 МБ | сообщение о лимите Telegram |

Логи:

```bash
docker compose logs -f bot worker
```

## Настройка поведения

Два параметра в `.env` меняют работу сервиса сильнее прочих:

- `DEFAULT_FAIL_MODE` — что делать, когда проверку **выполнить не удалось**.
  На уже найденные признаки не влияет.
- `DEFAULT_CDR_PROFILE` — насколько глубоко пересобирать файл. На вердикт не
  влияет вовсе.

- `DEFAULT_SHADOW_MODE` — проверять весь поток, но **не блокировать**. Нужен на
  обкатке: показывает, скольким отказали бы, не задев пользователей.

```bash
# включить тень на время обкатки
sed -i 's|^DEFAULT_SHADOW_MODE=.*|DEFAULT_SHADOW_MODE=true|' .env
docker compose up -d

# посмотреть, во что обошлись бы блокировки
docker compose exec gateway python -c "
import json,urllib.request,os,sys
sys.path.insert(0,'/app')
from vscommon.signing import sign, SIGNATURE_HEADER, TIMESTAMP_HEADER
ts,sig = sign(os.environ['HMAC_SECRET'], b'')
r = urllib.request.Request('http://localhost:8080/v1/ops/shadow',
                           headers={TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sig})
print(json.dumps(json.loads(urllib.request.urlopen(r).read()), ensure_ascii=False, indent=2))"
```

Разбор всех настроек, включая порядок работы с теневым режимом —
в `docs/policies.md` репозитория.

## Что важно знать

- **Порты наружу не публикуются.** Бот ходит к сканеру по внутренней сети
  Docker. Если понадобится внешний доступ к API — ставьте reverse proxy с TLS
  и переключайте `REQUIRE_SIGNATURE=true`.
- **Воркер запущен в ограниченном режиме**: read-only ФС, без capabilities,
  временные файлы в tmpfs. Полноценная песочница (gVisor/nsjail) — задача M5.
- **Данных на диске не остаётся** сверх томов `minio-data` и `clamav-db`.
  Карантин и обезвреженные файлы лежат в MinIO; TTL-политики — задача M4.5.
- **Обновление**: `docker compose pull && docker compose up -d`. Конкретную
  версию можно закрепить через `IMAGE_TAG` в `.env`.

## Остановка

```bash
docker compose down          # оставить данные
docker compose down -v       # удалить и данные тоже
```
