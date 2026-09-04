/**
 * Прогон реализации по общим векторам протокола.
 *
 * Тот же файл векторов, что и у Python-клиента: tests/vectors/protocol.json.
 * Смысл именно в общем файле — две реализации, сверяемые каждая со своими
 * ожиданиями, разойдутся и обе останутся «зелёными».
 *
 * Запуск: node scripts/check-vectors.js
 * Код возврата 0 — совпало, 1 — расхождение с описанием списком.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { MAX_SKEW_S, SAFE_VERDICTS, canonicalRequest, sign } from "../index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(here, "../../../tests/vectors/protocol.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

const failures = [];

for (const vector of vectors.signatures) {
  const payload = Buffer.from(vector.payload_hex, "hex");
  const [, signature] = sign(vector.secret, payload, vector.timestamp);
  if (signature !== vector.signature) {
    failures.push(
      `подпись «${vector.name}» (${vector.description}):\n` +
        `  ожидалось ${vector.signature}\n  получено   ${signature}`,
    );
  }
}

for (const item of vectors.canonical_request) {
  const produced = canonicalRequest(item.method, item.path, item.key_id);
  if (produced.toString("hex") !== item.bytes_hex) {
    failures.push(
      `канонический запрос ${item.method} ${item.path}:\n` +
        `  ожидалось ${item.bytes_hex}\n  получено   ${produced.toString("hex")}`,
    );
  }
}

if (vectors.algorithm.max_skew_s !== MAX_SKEW_S) {
  failures.push(
    `окно расхождения часов: ожидалось ${vectors.algorithm.max_skew_s}, получено ${MAX_SKEW_S}`,
  );
}

const safe = [...SAFE_VERDICTS].sort().join(",");
const expectedSafe = [...vectors.verdicts.safe].sort().join(",");
if (safe !== expectedSafe) {
  failures.push(`список безопасных вердиктов: ожидалось «${expectedSafe}», получено «${safe}»`);
}

if (failures.length > 0) {
  console.error("расхождение с векторами протокола:\n\n" + failures.join("\n\n"));
  process.exit(1);
}

const checks = vectors.signatures.length + vectors.canonical_request.length + 2;
console.log(`векторы протокола пройдены: проверок ${checks}`);
