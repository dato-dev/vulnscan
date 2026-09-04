# vulnscan-client

Клиент сервиса проверки вложений vulnscantg для Node.

**Библиотека серверная.** В браузере ей делать нечего: там нельзя держать
секрет, а без секрета нельзя подписать запрос. Ключ, попавший в бандл, — это
ключ, отданный всем посетителям сайта.

Зависимостей нет. Нужен Node 18 или новее — из него берутся `fetch`,
`FormData` и `node:crypto`.

## Быстрый старт

```js
import { VulnscanClient } from "vulnscan-client";

const client = new VulnscanClient({
  baseUrl: process.env.SCANNER_URL,
  keyId: process.env.SCANNER_KEY_ID,
  secret: process.env.SCANNER_SECRET,
});

const outcome = await client.scan(bytes, { filename: "скан.pdf" });

if (outcome.blocked) {
  return reply("Вложение заблокировано");
}
if (!outcome.safe) {
  return reply("Вложение не удалось проверить");
}
const clean = await client.downloadClean(outcome.scanId);
```

Три ветки, а не две. `!blocked` и `safe` — **разные вещи**: между ними
`suspicious`, `unsupported`, `encrypted` и `error`. Ни одно не заблокировано, и
ни одно не безопасно. Это самая частая ошибка интеграции и единственная, которая
не проявляется никак — код работает, тесты проходят, файлы принимаются.

## Приём коллбэка

```js
import express from "express";
import { verifyCallback, CallbackVerificationError } from "vulnscan-client";

app.post("/webhooks/vulnscan", express.raw({ type: "application/json" }), (req, res) => {
  try {
    const payload = verifyCallback(process.env.SCANNER_SECRET, req.body, req.headers);
    // ...
    res.sendStatus(200);
  } catch (error) {
    if (error instanceof CallbackVerificationError) return res.sendStatus(401);
    throw error;
  }
});
```

`express.raw()` здесь обязателен. `express.json()` разбирает тело, и подписывать
приходится уже пересобранные байты — порядок ключей и пробелы меняются, подпись
не сходится. Ошибка выглядит как «сервис шлёт неверную подпись».

Проверять подпись обязательно: эндпоинт без проверки принимает вердикт от кого
угодно, и «файл чист» пришлёт тот, кто этот файл и подсунул.

## Когда сервис недоступен

Повторяются только `429`, `5xx` и сетевые сбои; задержка удваивается от
полусекунды. `400` и `401` не повторяются — через секунду будет то же самое.

Исчерпав попытки, метод бросает `VulnscanError`. Ловить обязательно, а дальше
вариантов ровно два: **не принимать вложение** либо **принять и пометить
непроверенным**. Принять как чистое нельзя.

## Совместимость

Реализация сверяется с общими векторами протокола:

```bash
npm run vectors
```

Те же векторы прогоняет Python-клиент, и оба проверяются в `make test`. Файл —
[`tests/vectors/protocol.json`](../../tests/vectors/protocol.json), протокол
целиком — [`docs/protocol.md`](../../docs/protocol.md).

## TypeScript

Типы в `index.d.ts`, написаны руками: собственной сборки у пакета нет и не
планируется. Библиотеку, подписывающую запросы чужими секретами, полезнее уметь
прочитать целиком, чем собрать. Совпадение объявлений с экспортом проверяется
тестом.
