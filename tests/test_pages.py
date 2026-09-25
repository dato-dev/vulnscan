"""Сайт документации: исходники собираются, ссылки целы, навигация не врёт.

Сам сайт собирается в CI (`pages.yml`). Здесь — то, что дешевле поймать до
пуша: битая ссылка в документе, страница в навигации, которой нет, документ
из CLAUDE.md, не попавший на сайт.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def pages():
    spec = importlib.util.spec_from_file_location("pages", ROOT / "docs/pages.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["pages"] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop("pages", None)


@pytest.fixture(scope="module")
def staged(pages, tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("pages-src")
    pages.OUT = out
    problems = pages.build()
    assert problems == [], "\n".join(problems)
    return out


def test_no_broken_links(staged: Path) -> None:
    """Ссылка на несуществующий файл — отказ сборки, а не страница «не найдено»."""
    assert (staged / "index.md").exists()


def test_every_documented_file_is_on_the_site(staged: Path) -> None:
    """Всё, что CLAUDE.md называет документацией, попадает на сайт."""
    table = (ROOT / "CLAUDE.md").read_text()
    listed = set(re.findall(r"^\| \[[^\]]+\]\(([^)]+\.md)\)", table, re.M))
    assert listed, "таблица документов в CLAUDE.md изменила форму"

    missing = [name for name in listed if not (staged / name).exists()]
    assert not missing, f"документы из CLAUDE.md не попадают на сайт: {missing}"


def test_navigation_points_to_real_pages(staged: Path) -> None:
    """Пункт навигации без страницы MkDocs в строгом режиме не пропустит —
    но узнаем мы об этом уже в CI."""
    # Свой файл: теги MkDocs нужно только пропустить, не исполнять.
    config = yaml.load(
        (ROOT / "mkdocs.yml").read_text(), Loader=_TolerantLoader
    )

    def walk(items: list) -> list[str]:
        found: list[str] = []
        for item in items:
            for value in item.values():
                found.extend(walk(value) if isinstance(value, list) else [value])
        return found

    missing = [page for page in walk(config["nav"]) if not (staged / page).exists()]
    assert not missing, f"в навигации страницы, которых нет: {missing}"


def test_code_links_go_to_the_repository(pages, staged: Path) -> None:
    """Ссылка на файл конфигурации на сайте ведёт в репозиторий, а не в пустоту."""
    text = (staged / "docs/api.md").read_text()

    assert f"{pages.REPO}/blob/main/deploy/config/policies.example.json" in text


class _TolerantLoader(yaml.SafeLoader):
    """`mkdocs.yml` содержит теги `!!python/...` — для проверки навигации их
    достаточно пропустить, исполнять незачем."""


_TolerantLoader.add_multi_constructor(
    "tag:yaml.org,2002:python/", lambda loader, suffix, node: None
)
