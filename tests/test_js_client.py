"""M9.4: JS-клиент проверяется теми же векторами, что и Python.

Смысл именно в **общем файле векторов**. Две реализации, сверяемые каждая со
своими ожиданиями, разойдутся и обе останутся зелёными — расхождение всплывёт у
интегратора в виде `401` без объяснений.

Node в общем прогоне не обязателен: нет — тесты пропускаются. `make test`
обязан работать на машине, где ставили только Python.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
PACKAGE = ROOT / "packages/vulnscan-client-js"

node = pytest.mark.skipif(shutil.which("node") is None, reason="Node не установлен")


def _run(script: str) -> subprocess.CompletedProcess[str]:
    """Выполняет модуль ESM, импортирующий библиотеку."""
    return subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        cwd=PACKAGE,
        timeout=60,
        check=False,
    )


@node
def test_vectors_pass() -> None:
    """Штатный прогон по векторам — тот же скрипт, что и в `npm run vectors`."""
    result = subprocess.run(
        ["node", "scripts/check-vectors.js"],
        capture_output=True,
        text=True,
        cwd=PACKAGE,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert "векторы протокола пройдены" in result.stdout


@node
def test_vector_checker_actually_checks() -> None:
    """Проверка самой проверки.

    Скрипт, который печатает «пройдено» при любом входе, хуже отсутствующего.
    Подменяем ожидаемую подпись и убеждаемся, что он падает.
    """
    vectors = json.loads((ROOT / "tests/vectors/protocol.json").read_text())
    broken = dict(vectors)
    broken["signatures"] = [dict(v) for v in vectors["signatures"]]
    broken["signatures"][0]["signature"] = "sha256=" + "0" * 64

    script = f"""
    import {{ sign }} from "./index.js";
    const vectors = {json.dumps(broken, ensure_ascii=False)};
    const v = vectors.signatures[0];
    const [, signature] = sign(v.secret, Buffer.from(v.payload_hex, "hex"), v.timestamp);
    if (signature === v.signature) {{
        console.log("СОВПАЛО");
    }} else {{
        console.log("РАСХОЖДЕНИЕ");
    }}
    """
    result = _run(script)

    assert result.returncode == 0, result.stderr
    assert "РАСХОЖДЕНИЕ" in result.stdout, "подменённая подпись не была замечена"


@node
def test_verdict_handling_matches_python() -> None:
    """`blocked`, `safe` и `unscannable` ведут себя одинаково в обеих библиотеках.

    Это то место, где расхождение опаснее всего: разъехавшись, реализации дадут
    разный ответ на один и тот же файл — и одна из них в опасную сторону.
    """
    from vulnscan_client.client import _to_outcome

    cases = ["clean", "suspicious", "malicious", "unsupported", "encrypted", "error"]
    script = f"""
    import {{ ScanOutcome }} from "./index.js";
    const out = {{}};
    for (const verdict of {json.dumps(cases)}) {{
        const o = new ScanOutcome({{ scan_id: "x", verdict, score: 0, status: "done" }});
        out[verdict] = [o.blocked, o.safe, o.unscannable];
    }}
    console.log(JSON.stringify(out));
    """
    result = _run(script)
    assert result.returncode == 0, result.stderr
    js = json.loads(result.stdout)

    for verdict in cases:
        outcome = _to_outcome({"scan_id": "x", "verdict": verdict, "score": 0, "status": "done"})
        expected = [outcome.blocked, outcome.safe, outcome.unscannable]
        assert js[verdict] == expected, (
            f"вердикт «{verdict}»: python {expected}, js {js[verdict]} "
            "(порядок: blocked, safe, unscannable)"
        )


@node
def test_callback_verification_matches_python() -> None:
    """Проверка коллбэка принимает подпись, сделанную другой реализацией.

    Прямая проверка совместимости: подписываем на Python, проверяем на Node.
    Именно так это и работает в бою — подписывает наш сервис, проверяет клиент.
    """
    import time

    from vscommon.signing import sign

    secret = "vector-secret-do-not-use-in-production"
    body = b'{"scan_id":"abc","verdict":"clean","score":0}'
    timestamp, signature = sign(secret, body, int(time.time()))

    script = f"""
    import {{ verifyCallback }} from "./index.js";
    const payload = verifyCallback(
        {json.dumps(secret)},
        Buffer.from({json.dumps(body.decode())}, "utf8"),
        {{ "X-Vulnscan-Timestamp": {json.dumps(timestamp)},
           "X-Vulnscan-Signature": {json.dumps(signature)} }},
    );
    console.log(payload.verdict);
    """
    result = _run(script)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "clean"


@node
def test_callback_rejects_tampered_body() -> None:
    """Подменённое тело не проходит.

    Без этой проверки предыдущий тест доказывал бы только то, что функция
    что-то возвращает.
    """
    import time

    from vscommon.signing import sign

    secret = "vector-secret-do-not-use-in-production"
    timestamp, signature = sign(secret, b'{"verdict":"malicious"}', int(time.time()))

    script = f"""
    import {{ verifyCallback, CallbackVerificationError }} from "./index.js";
    try {{
        verifyCallback(
            {json.dumps(secret)},
            Buffer.from('{{"verdict":"clean"}}', "utf8"),
            {{ "X-Vulnscan-Timestamp": {json.dumps(timestamp)},
               "X-Vulnscan-Signature": {json.dumps(signature)} }},
        );
        console.log("ПРИНЯТО");
    }} catch (error) {{
        console.log(error instanceof CallbackVerificationError ? "ОТКЛОНЕНО" : "ДРУГАЯ ОШИБКА");
    }}
    """
    result = _run(script)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ОТКЛОНЕНО"


# --- объявления типов не отстают от реализации ---------------------------


@node
def test_type_declarations_cover_every_export() -> None:
    """Всё, что модуль экспортирует, объявлено в `index.d.ts`.

    Объявления написаны руками — сборки у пакета нет. Плата за это ровно одна:
    они могут разойтись с кодом, и TypeScript тогда либо не увидит имени, либо
    увидит несуществующее. Здесь проверяется первое.
    """
    result = _run('import * as m from "./index.js"; console.log(Object.keys(m).join(","));')
    assert result.returncode == 0, result.stderr

    exported = set(result.stdout.strip().split(","))
    declarations = (PACKAGE / "index.d.ts").read_text()
    missing = [name for name in exported if name not in declarations]

    assert not missing, f"экспортируется, но не объявлено в index.d.ts: {sorted(missing)}"


@node
def test_type_declarations_have_no_ghosts() -> None:
    """И наоборот: объявленного имени нет в модуле.

    Такое опаснее пропуска: TypeScript пропустит вызов, а падать будет во время
    выполнения у интегратора.
    """
    result = _run('import * as m from "./index.js"; console.log(Object.keys(m).join(","));')
    assert result.returncode == 0, result.stderr

    exported = set(result.stdout.strip().split(","))
    declared = set(
        re.findall(
            r"export declare (?:class|function|const) (\w+)",
            (PACKAGE / "index.d.ts").read_text(),
        )
    )

    assert declared <= exported, f"объявлено, но не экспортируется: {sorted(declared - exported)}"


def test_package_has_no_dependencies() -> None:
    """У библиотеки нет зависимостей, и это требование, а не совпадение.

    Она едет к чужой команде. Каждая зависимость — то, что подключающийся
    обязан впустить к себе вместе с нашим кодом, и то, чем мы можем сломать
    его сборку. Node даёт `fetch`, `FormData` и `node:crypto` — этого хватает.
    """
    manifest = json.loads((PACKAGE / "package.json").read_text())

    assert manifest.get("dependencies") == {}, "появилась зависимость — нужно обоснование"
    assert "devDependencies" not in manifest, "сборки у пакета нет, dev-зависимости не нужны"
