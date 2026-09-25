"""Исходники сайта документации для GitHub Pages.

Документация живёт рядом с кодом, а не в отдельном каталоге для сайта: README
сервиса лежит у сервиса, README примера — у примера. MkDocs же собирает сайт
из одного каталога. Поэтому здесь все нужные `.md` копируются в
`build/pages-src` **с сохранением путей** — и относительные ссылки между
документами продолжают работать без правки, ровно как на GitHub.

Ссылки на всё, что не документ (`../deploy/k8s/base/10-config.yaml`,
`../services/worker/`), на сайте вели бы в пустоту. Они переписываются в
ссылки на файл в репозитории. Ссылка на файл, которого нет вовсе, — ошибка
сборки, а не молча битая ссылка: так документация и расходится с кодом.

Запуск: python docs/pages.py && mkdocs build --strict
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "pages-src"
REPO = "https://github.com/dato-dev/vulnscan"
BRANCH = "main"

SOURCES = (
    "README.md",
    "ROADMAP.md",
    "CLAUDE.md",
    "docs/*.md",
    "examples/*/README.md",
    "deploy/README.md",
    "deploy/*/README.md",
    "corpus/README.md",
    "packages/vulnscan-client-js/README.md",
)

LINK = re.compile(r"(?<!!)\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)(?P<title>\s+\"[^\"]*\")?\)")


def sources() -> list[Path]:
    found: list[Path] = []
    for pattern in SOURCES:
        found.extend(sorted(ROOT.glob(pattern)))
    return found


def rewrite(text: str, source: Path) -> tuple[str, list[str]]:
    """Ссылки на не-документы — в репозиторий. Возвращает текст и ошибки."""
    problems: list[str] = []
    documents = {path.resolve() for path in sources()}

    def replace(match: re.Match[str]) -> str:
        target = match.group("target")
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            return match.group(0)  # внешняя ссылка или якорь на той же странице
        path_part, _, anchor = target.partition("#")
        resolved = (source.parent / path_part).resolve()
        if resolved in documents:
            return match.group(0)  # документ сайта — ссылка работает как есть
        if not resolved.exists():
            problems.append(f"{source.relative_to(ROOT)}: ссылка на несуществующее {target}")
            return match.group(0)
        relative = resolved.relative_to(ROOT).as_posix()
        kind = "tree" if resolved.is_dir() else "blob"
        url = f"{REPO}/{kind}/{BRANCH}/{relative}" + (f"#{anchor}" if anchor else "")
        return f"[{match.group('text')}]({url}{match.group('title') or ''})"

    return LINK.sub(replace, text), problems


def build() -> list[str]:
    if OUT.exists():
        shutil.rmtree(OUT)
    problems: list[str] = []
    for source in sources():
        text, found = rewrite(source.read_text(), source)
        problems.extend(found)
        target = OUT / source.relative_to(ROOT)
        # Корневой README — главная страница сайта.
        if source == ROOT / "README.md":
            target = OUT / "index.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return problems


def main() -> int:
    problems = build()
    for line in problems:
        print(line, file=sys.stderr)
    print(f"исходники сайта: {OUT.relative_to(ROOT)}, документов: {len(sources())}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
