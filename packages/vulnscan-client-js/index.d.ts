/**
 * Типы клиента vulnscantg.
 *
 * Объявления написаны руками, а не собраны из TypeScript-исходника: собственной
 * сборки у пакета нет, и это сознательный выбор. Библиотека без шага сборки
 * работает и в Node, и в бандлере, и её можно прочитать целиком одним файлом —
 * для кода, который подписывает запросы чужими секретами, это важнее удобства
 * авторов.
 *
 * Плата за это — возможность разойтись с реализацией. Совпадение имён
 * проверяется тестом (tests/test_js_client.py).
 */

export declare const SIGNATURE_HEADER: string;
export declare const TIMESTAMP_HEADER: string;
export declare const KEY_ID_HEADER: string;

/** Допустимое расхождение часов, секунды. Больше — запрос отклоняется. */
export declare const MAX_SKEW_S: number;

/**
 * Вердикты, считающиеся безопасными без оговорок.
 *
 * Список положительный намеренно: незнакомый вердикт обязан считаться
 * небезопасным.
 */
export declare const SAFE_VERDICTS: ReadonlySet<string>;

export declare class VulnscanError extends Error {}

export declare class CallbackVerificationError extends VulnscanError {}

/** Признак, найденный проверкой. Коды — часть публичного контракта. */
export interface Finding {
  stage: string;
  code: string;
  severity: string;
  detail?: string;
  score?: number;
}

export declare class ScanOutcome {
  constructor(payload: Record<string, unknown>);

  readonly scanId: string;
  readonly verdict: string;
  readonly score: number;
  readonly status: string;
  /** Вердикта ещё нет: `queued` или `scanning`. Штатный исход, не ошибка. */
  readonly pending: boolean;
  readonly sanitized: boolean;
  readonly findings: Finding[];
  /** Ответ целиком — для полей, которых библиотека не разбирает. */
  readonly raw: Record<string, unknown>;

  /** Файл нельзя отдавать пользователю. */
  readonly blocked: boolean;
  /**
   * Пригоден без оговорок.
   *
   * НЕ равно `!blocked`: между ними `suspicious`, `unsupported`, `encrypted` и
   * `error` — не заблокированы и не безопасны.
   */
  readonly safe: boolean;
  /** Проверить не удалось: формат не поддержан либо файл зашифрован. */
  readonly unscannable: boolean;
}

export interface VulnscanClientOptions {
  baseUrl: string;
  keyId: string;
  /** Секрет. Из окружения или хранилища, не из кода и не из бандла. */
  secret: string;
  timeoutMs?: number;
  /** Верхняя граница синхронного ответа; сервис ограничивает её политикой. */
  waitMs?: number;
  callbackUrl?: string | null;
  retries?: number;
  /** Текущий `traceparent` в формате W3C, если трассировка ведётся. */
  traceContext?: (() => string | null) | null;
}

export interface ScanOptions {
  /** Обязателен: по нему определяется тип. В ответ не возвращается. */
  filename: string;
  contentType?: string;
  profile?: "light" | "standard" | "strict";
}

export declare class VulnscanClient {
  constructor(options: VulnscanClientOptions);

  scan(content: Uint8Array | Buffer, options: ScanOptions): Promise<ScanOutcome>;
  /** `null` — скана нет либо он чужой. Это НЕ «ещё не готов». */
  result(scanId: string): Promise<ScanOutcome | null>;
  downloadClean(scanId: string): Promise<Buffer>;
}

/**
 * Проверяет подпись коллбэка и возвращает разобранное тело.
 *
 * `body` — сырые байты до разбора JSON: повторная сериализация меняет их, и
 * подпись не сойдётся.
 */
export declare function verifyCallback(
  secret: string,
  body: Uint8Array | Buffer | string,
  headers: Record<string, string>,
): Record<string, unknown>;

/** Подпись: `[timestamp, "sha256=<hex>"]`. Нужна тем, кто подписывает сам. */
export declare function sign(
  secret: string,
  payload: Uint8Array | Buffer | string,
  timestamp?: number,
): [string, string];

/** Канонический запрос `METHOD\nPATH\nKEY_ID` в UTF-8. */
export declare function canonicalRequest(
  method: string,
  path: string,
  keyId: string,
): Buffer;
