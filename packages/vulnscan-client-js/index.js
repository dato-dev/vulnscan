/**
 * Клиент сервиса проверки вложений vulnscantg.
 *
 * Порт опорной Python-библиотеки. Протокол один и тот же и описан в
 * docs/protocol.md; расхождение между реализациями — ошибка, а не особенность
 * языка, и проверяется общими векторами (tests/vectors/protocol.json).
 *
 * ВАЖНО: библиотека серверная. В браузере ей делать нечего — там нельзя
 * держать секрет, а с ним нельзя подписать запрос. Тому, кому нужна загрузка
 * из браузера, нужен другой механизм (см. docs/ideas.md, раздел про виджет),
 * а не эта библиотека с ключом в бандле.
 *
 * Зависимостей нет: всё берётся из Node (`node:crypto`, глобальные `fetch`,
 * `FormData`, `Blob`). Библиотека, которая едет к чужой команде, не должна
 * тащить за собой чужие пакеты.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const SIGNATURE_HEADER = "X-Vulnscan-Signature";
export const TIMESTAMP_HEADER = "X-Vulnscan-Timestamp";
export const KEY_ID_HEADER = "X-Vulnscan-Key";

export const MAX_SKEW_S = 300;

/**
 * Что считается пригодным без оговорок.
 *
 * Список положительный, а не отрицательный, намеренно: незнакомый вердикт —
 * например, добавленный в сервисе позже — должен считаться небезопасным.
 * Список запрещённого молча пропустил бы его.
 */
export const SAFE_VERDICTS = new Set(["clean"]);

const RETRY_STATUS = new Set([429, 500, 502, 503, 504]);

export class VulnscanError extends Error {
  constructor(message) {
    super(message);
    this.name = "VulnscanError";
  }
}

export class CallbackVerificationError extends VulnscanError {
  constructor(message) {
    super(message);
    this.name = "CallbackVerificationError";
  }
}

/**
 * Подпись: HMAC-SHA256 по `timestamp + "." + payload`.
 *
 * Точка обязательна. Без неё подпись без отметки времени совпала бы с
 * подписью, где отметка пуста, и повтор старого запроса стал бы возможен.
 */
function sign(secret, payload, timestamp) {
  const ts = String(timestamp ?? Math.floor(Date.now() / 1000));
  const mac = createHmac("sha256", Buffer.from(secret, "utf8"));
  mac.update(Buffer.from(`${ts}.`, "utf8"));
  mac.update(Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8"));
  return [ts, `sha256=${mac.digest("hex")}`];
}

/**
 * Канонический запрос: `METHOD\nPATH\nKEY_ID`.
 *
 * Подписывается он, а не тело, там где тело — multipart: сервис проверяет
 * подпись ДО чтения тела, иначе неаутентифицированный файл пришлось бы сперва
 * принять целиком.
 */
function canonicalRequest(method, path, keyId) {
  return Buffer.from(`${method.toUpperCase()}\n${path}\n${keyId}`, "utf8");
}

/**
 * Сравнение за постоянное время.
 *
 * Обычное `===` на строках раскрывает подпись побайтово по времени ответа.
 * Разная длина сравнивается отдельно: `timingSafeEqual` на буферах разной
 * длины бросает исключение, а исключение внутри проверки подписи — это способ
 * отличить «неверная длина» от «неверные байты».
 */
function constantTimeEquals(expected, candidate) {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(candidate, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Проверяет подпись входящего коллбэка и возвращает разобранное тело.
 *
 * Вызывать ОБЯЗАТЕЛЬНО. Без проверки эндпоинт принимает вердикт от кого
 * угодно, и «файл чист» пришлёт тот, кто этот файл и подсунул.
 *
 * `body` — сырые байты до разбора JSON. Разбор и повторная сериализация
 * меняют их (порядок ключей, пробелы, экранирование), и подпись не сойдётся.
 * В Express это `express.raw()`, в Fastify — `rawBody`.
 */
export function verifyCallback(secret, body, headers) {
  const lower = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    lower[name.toLowerCase()] = value;
  }

  const timestamp = lower[TIMESTAMP_HEADER.toLowerCase()] ?? "";
  const signature = lower[SIGNATURE_HEADER.toLowerCase()] ?? "";
  if (!timestamp || !signature) {
    throw new CallbackVerificationError("коллбэк не подписан");
  }

  const parsed = Number.parseInt(timestamp, 10);
  if (!Number.isFinite(parsed)) {
    throw new CallbackVerificationError("некорректная отметка времени");
  }

  const skew = Math.abs(Math.floor(Date.now() / 1000) - parsed);
  if (skew > MAX_SKEW_S) {
    throw new CallbackVerificationError(
      `расхождение часов ${skew} с при допустимых ${MAX_SKEW_S} — ` +
        "проверьте синхронизацию времени",
    );
  }

  const raw = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  const [, expected] = sign(secret, raw, parsed);
  if (!constantTimeEquals(expected, signature)) {
    throw new CallbackVerificationError("подпись не сошлась");
  }

  return JSON.parse(raw.toString("utf8"));
}

/**
 * Результат проверки.
 *
 * Три свойства вместо двух — не избыточность. `blocked` и `safe` не отрицают
 * друг друга: между ними помещаются `suspicious`, `unsupported`, `encrypted` и
 * `error`. Ни одно не заблокировано, и ни одно не безопасно.
 */
export class ScanOutcome {
  constructor(payload) {
    const status = String(payload.status ?? "");
    this.scanId = String(payload.scan_id ?? "");
    this.verdict = String(payload.verdict ?? "");
    this.score = Number(payload.score ?? 0);
    this.status = status;
    this.pending = status === "queued" || status === "scanning";
    this.sanitized = Boolean(payload.sanitized);
    this.findings = Array.isArray(payload.findings) ? payload.findings : [];
    /** Ответ целиком — на случай, если нужно поле, которого библиотека не разобрала. */
    this.raw = payload;
  }

  /** Файл нельзя отдавать пользователю. */
  get blocked() {
    return this.verdict === "malicious";
  }

  /**
   * Пригоден без оговорок.
   *
   * Обратите внимание: `!blocked` и `safe` — разные вещи. Файл, который не
   * удалось проверить, не заблокирован, но и безопасным не является. Это самая
   * частая ошибка интеграции и единственная, которая не проявляется никак.
   */
  get safe() {
    return SAFE_VERDICTS.has(this.verdict);
  }

  /** Проверить не удалось: формат не поддержан, файл зашифрован. */
  get unscannable() {
    return this.verdict === "unsupported" || this.verdict === "encrypted";
  }
}

const sleep = (seconds) => new Promise((resolve) => setTimeout(resolve, seconds * 1000));

export class VulnscanClient {
  /**
   * @param {object} options
   * @param {string} options.baseUrl адрес сервиса
   * @param {string} options.keyId идентификатор ключа
   * @param {string} options.secret секрет; из окружения, не из кода
   * @param {number} [options.timeoutMs] таймаут одного запроса
   * @param {number} [options.waitMs] сколько сервис ждёт вердикт до ответа 202
   * @param {string} [options.callbackUrl] куда прислать результат вебхуком
   * @param {number} [options.retries] попыток на запрос
   * @param {() => string | null} [options.traceContext] текущий traceparent
   */
  constructor({
    baseUrl,
    keyId,
    secret,
    timeoutMs = 30_000,
    waitMs = 2000,
    callbackUrl = null,
    retries = 3,
    traceContext = null,
  }) {
    if (!baseUrl || !keyId || !secret) {
      throw new VulnscanError("нужны baseUrl, keyId и secret");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.keyId = keyId;
    this.secret = secret;
    this.timeoutMs = timeoutMs;
    this.waitMs = waitMs;
    this.callbackUrl = callbackUrl;
    this.retries = retries;
    this.traceContext = traceContext;
  }

  #headers(payload) {
    const [timestamp, signature] = sign(this.secret, payload);
    const headers = {
      [KEY_ID_HEADER]: this.keyId,
      [TIMESTAMP_HEADER]: timestamp,
      [SIGNATURE_HEADER]: signature,
    };

    // Контекст трассировки, если вызывающая сторона его ведёт. В подпись
    // заголовок не входит: подписывается канонический запрос, поэтому
    // добавление безопасно и не ломает совместимость.
    const traceparent = this.traceContext?.();
    if (traceparent) {
      headers.traceparent = traceparent;
    }
    return headers;
  }

  /**
   * Отправляет файл на проверку.
   *
   * Возвращает готовый вердикт либо `pending: true`, если сервис не уложился
   * в `waitMs`. `pending` — штатный исход, а не ошибка.
   */
  async scan(content, { filename, contentType = "application/octet-stream", profile } = {}) {
    if (!filename) {
      throw new VulnscanError("filename обязателен: по нему определяется тип");
    }

    const path = "/v1/scan";
    const meta = { wait_ms: this.waitMs, filename };
    if (profile) meta.profile = profile;
    if (this.callbackUrl) meta.callback_url = this.callbackUrl;

    const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const headers = this.#headers(canonicalRequest("POST", path, this.keyId));
    // Ключ идемпотентности — sha256 файла, а не случайная строка: два клиента,
    // приславшие один файл, должны попасть в одну проверку.
    headers["Idempotency-Key"] = createHash("sha256").update(bytes).digest("hex");

    const form = new FormData();
    form.append("file", new Blob([bytes], { type: contentType }), filename);
    form.append("meta", JSON.stringify(meta));

    const payload = await this.#request("POST", path, { headers, body: form });
    return new ScanOutcome(payload);
  }

  /**
   * Забирает результат по идентификатору.
   *
   * `null` означает «нет такого скана»: либо его не существует, либо он чужой.
   * Это НЕ «ещё не готов» — незавершённый скан возвращается объектом с
   * `pending: true`.
   */
  async result(scanId) {
    const path = `/v1/scan/${scanId}`;
    const headers = this.#headers(canonicalRequest("GET", path, this.keyId));
    try {
      return new ScanOutcome(await this.#request("GET", path, { headers }));
    } catch (error) {
      if (error instanceof VulnscanError && error.message.includes("404")) {
        return null;
      }
      throw error;
    }
  }

  /** Скачивает обезвреженную копию. */
  async downloadClean(scanId) {
    const path = `/v1/scan/${scanId}/clean`;
    const headers = this.#headers(canonicalRequest("GET", path, this.keyId));
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      throw new VulnscanError(`обезвреженная копия недоступна: ${response.status}`);
    }
    return Buffer.from(await response.arrayBuffer());
  }

  /**
   * Повторяет только то, что осмысленно повторять.
   *
   * `401` и `400` повторять бессмысленно: через секунду будет то же самое, а
   * лишние попытки съедают квоту.
   */
  async #request(method, path, { headers, body } = {}) {
    let last = null;

    for (let attempt = 1; attempt <= this.retries; attempt += 1) {
      try {
        const response = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers,
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
        });

        if (response.ok) {
          return await response.json();
        }
        if (!RETRY_STATUS.has(response.status)) {
          throw new VulnscanError(`сервис отклонил запрос: ${response.status}`);
        }
        last = new VulnscanError(`сервис ответил ${response.status}`);
      } catch (error) {
        if (error instanceof VulnscanError && error.message.startsWith("сервис отклонил")) {
          throw error;
        }
        last = error;
      }

      if (attempt < this.retries) {
        await sleep(0.5 * 2 ** (attempt - 1));
      }
    }

    throw new VulnscanError(`сервис недоступен: ${last?.message ?? last}`);
  }
}

// Экспортируются и низкоуровневые части: тому, кто подписывает запросы сам,
// они нужнее готового клиента, а держать вторую копию алгоритма — верный
// способ разойтись.
export { sign, canonicalRequest };
