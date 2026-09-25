"""CDR для ZIP: новый архив из пересобранных вложений.

Архив не патчится, а собирается заново: каждое вложение проходит свой
санитайзер с тем же профилем и его верификацию. Пути нормализуются, ссылки
и служебные файлы macOS не переносятся, комментарии и даты исходника тоже.

Вложение, которое пересобрать нечем, — отказ всего архива, а не пропуск:
архив с молча выброшенным файлом пользователь принял бы за полный. До CDR
такой архив и не доходит — конвейер ставит ему `unsupported`, — так что
отказ здесь страхует от расхождения двух мест, а не от штатного случая.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import zipfile
from contextvars import ContextVar
from pathlib import Path, PurePosixPath

from vscommon.limits import MAX_ARCHIVE_DEPTH, MAX_SANITIZED_BYTES
from vscommon.models import CdrProfile

from ..archive import (
    UnpackBudget,
    display_name,
    extract,
    inspect,
    is_os_metadata,
    open_archive,
    safe_name,
)
from ..stages.filetype_detect import ZIP_MIME, sniff
from .base import SanitizeError, SanitizeOutcome, Sanitizer

logger = logging.getLogger(__name__)

_DEPTH: ContextVar[int] = ContextVar("zip_cdr_depth", default=0)
_BUDGET: ContextVar[UnpackBudget | None] = ContextVar("zip_cdr_budget", default=None)
"""Глубина и бюджет всего дерева при пересборке вложенных архивов.

Контекстная переменная, а не аргумент: вложенный архив пересобирается через
общий реестр санитайзеров, у которого одна сигнатура на все форматы. Каждый
вызов CDR идёт в своём потоке с копией контекста, так что параллельные
пересборки друг другу не мешают.
"""

EQUIVALENT = {".jpg": {".jpg", ".jpeg"}, ".tif": {".tif", ".tiff"}}


def _renamed(name: str, suffix: str) -> str:
    """Расширение по содержимому пересобранного файла.

    GIF пересобирается в PNG, и оставить ему имя `.gif` — значит отдать
    файл, который откроется не той программой. А запись `счёт.pdf.exe`, в
    которой лежал PDF, выйдет `счёт.pdf.pdf` — зато не `.exe`.
    """
    current = PurePosixPath(name).suffix.lower()
    if current in EQUIVALENT.get(suffix, {suffix}):
        return name
    return f"{name}{suffix}" if not current else f"{name[: -len(current)]}{suffix}"


def _unique(name: str, taken: set[str]) -> str:
    candidate, n = name, 1
    while candidate.lower() in taken:
        n += 1
        path = PurePosixPath(name)
        candidate = str(path.with_name(f"{path.stem}-{n}{path.suffix}"))
    taken.add(candidate.lower())
    return candidate


class ZipSanitizer(Sanitizer):
    name = "zip"
    mimes = frozenset({ZIP_MIME})

    def sanitize(self, src: Path, dst_dir: Path, profile: CdrProfile) -> SanitizeOutcome:
        # Реестр импортирует этот модуль, поэтому обратный импорт — здесь.
        from .registry import sanitize as sanitize_member

        depth = _DEPTH.get()
        if depth > MAX_ARCHIVE_DEPTH:
            raise SanitizeError("вложенность архивов глубже предела")
        budget = _BUDGET.get() or UnpackBudget(root_size=src.stat().st_size)

        dst = dst_dir / "clean.zip"
        work = Path(tempfile.mkdtemp(prefix="unzip-", dir=dst_dir))
        depth_token = _DEPTH.set(depth + 1)
        budget_token = _BUDGET.set(budget)
        transforms = {"rebuild_archive"}
        taken: set[str] = set()
        total = 0
        try:
            with open_archive(src) as zf:
                inventory = inspect(zf, budget, depth)
                infos = [info for info in zf.infolist() if not info.is_dir()]
            if inventory.bomb or inventory.encrypted or inventory.incomplete:
                raise SanitizeError("архив не проверен целиком")
            selected = {member.info.filename for member in inventory.members}

            with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as out:
                for index, info in enumerate(infos, start=1):
                    if is_os_metadata(info):
                        transforms.add("drop_os_metadata")
                        continue
                    if info.filename not in selected:
                        if info.file_size == 0 and not info.flag_bits & 0x1:
                            name = _unique(safe_name(display_name(info), index), taken)
                            out.writestr(_entry(name), b"")
                            continue
                        # Ссылка или то, что опись не отдала на проверку.
                        transforms.add("drop_unscanned")
                        continue

                    raw = extract(src, info, work / f"{index:05d}.bin", budget)
                    member_dir = work / f"{index:05d}"
                    member_dir.mkdir()
                    outcome = sanitize_member(raw, member_dir, sniff(raw), profile)
                    total += outcome.path.stat().st_size
                    if total > MAX_SANITIZED_BYTES:
                        raise SanitizeError("выход CDR превысил лимит размера")

                    original = display_name(info)
                    name = safe_name(original, index)
                    if name != original.replace("\\", "/"):
                        transforms.add("normalize_paths")
                    name = _unique(_renamed(name, outcome.path.suffix), taken)
                    with outcome.path.open("rb") as handle, out.open(_entry(name), "w") as target:
                        shutil.copyfileobj(handle, target)
                    transforms.update(f"member:{t}" for t in outcome.transforms)
                    raw.unlink(missing_ok=True)
                    shutil.rmtree(member_dir, ignore_errors=True)
        finally:
            _DEPTH.reset(depth_token)
            _BUDGET.reset(budget_token)
            shutil.rmtree(work, ignore_errors=True)

        if dst.stat().st_size > MAX_SANITIZED_BYTES:
            dst.unlink(missing_ok=True)
            raise SanitizeError("выход CDR превысил лимит размера")
        return SanitizeOutcome(path=dst, content_type=ZIP_MIME, transforms=sorted(transforms))

    def verify(self, path: Path) -> list[str]:
        """Каждое вложение выхода проверяется верификатором своего формата."""
        from .registry import find_sanitizer

        depth = _DEPTH.get()
        if depth > MAX_ARCHIVE_DEPTH:
            return ["depth"]
        budget = _BUDGET.get() or UnpackBudget(root_size=path.stat().st_size)
        problems: set[str] = set()
        work = Path(tempfile.mkdtemp(prefix="verify-", dir=path.parent))
        depth_token = _DEPTH.set(depth + 1)
        budget_token = _BUDGET.set(budget)
        try:
            with open_archive(path) as zf:
                inventory = inspect(zf, budget, depth)
                leftovers = [i for i in zf.infolist() if is_os_metadata(i)]
            problems.update(code for code, _ in inventory.problems)
            if inventory.incomplete:
                problems.add("incomplete")
            if leftovers:
                problems.add("os_metadata")
            for member in inventory.members:
                raw = extract(path, member.info, work / f"{member.index:05d}.bin", budget)
                sanitizer = find_sanitizer(sniff(raw))
                if sanitizer is None:
                    problems.add(f"{member.label}: тип не пересобирается")
                else:
                    problems.update(f"{member.label}: {left}" for left in sanitizer.verify(raw))
                raw.unlink(missing_ok=True)
        finally:
            _DEPTH.reset(depth_token)
            _BUDGET.reset(budget_token)
            shutil.rmtree(work, ignore_errors=True)
        return sorted(problems)


def _entry(name: str) -> zipfile.ZipInfo:
    """Запись без следов исходника: фиксированная дата, обычные права."""
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info
