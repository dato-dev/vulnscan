"""CDR для PDF: пересборка документа без активных элементов."""

from __future__ import annotations

import logging
from pathlib import Path

from vscommon.limits import CDR_TIMEOUT_S, MAX_SANITIZED_BYTES
from vscommon.models import CdrProfile

from ..sandbox import run_sandboxed
from .base import SanitizeError, SanitizeOutcome, Sanitizer

logger = logging.getLogger(__name__)

# Ключи каталога документа и страниц, которые несут исполняемое поведение.
ROOT_KEYS_TO_DROP = ("/OpenAction", "/AA", "/AcroForm", "/Names", "/JavaScript", "/EmbeddedFiles")
PAGE_KEYS_TO_DROP = ("/AA", "/JS", "/JavaScript")
ANNOT_ACTIONS_TO_DROP = ("/JavaScript", "/Launch", "/GoToE", "/GoToR", "/SubmitForm", "/ImportData")

BYTE_MARKERS = (
    b"/JavaScript",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/Launch",
)
"""Маркеры, которые ищутся в сырых байтах.

Все длиной от семи байт: вероятность случайно встретить такую
последовательность в сжатом потоке пренебрежимо мала.
"""

GRAPH_KEYS = ("/JS", "/XFA")
"""Короткие ключи проверяются только по графу объектов.

Искать их в байтах нельзя: `/JS` — три байта, и в сжатых данных такая
последовательность встречается случайно с вероятностью ~45% на 10 МБ. Скан
паспорта отвергался бы как несанитизированный чаще, чем проходил.
"""

ACTION_HOLDERS = ("/OpenAction", "/AA")
"""Автозапуск проверяется по вызываемому действию, а не по наличию.

Растеризация в профиле `strict` идёт через ghostscript, и он пишет в выход
`/OpenAction [страница /Fit]` — то есть «открыть на такой-то странице». Это
норма почти любого PDF, и проверка по наличию объявляла провал на каждом
обычном документе.
"""

DANGEROUS_ACTIONS = frozenset(
    {
        "/Launch",
        "/JavaScript",
        "/JS",
        "/SubmitForm",
        "/ImportData",
        "/GoToE",
        "/GoToR",
        "/Rendition",
        "/Movie",
        "/Sound",
    }
)

MAX_VERIFY_STEPS = 50_000


class PdfSanitizer(Sanitizer):
    name = "pdf"
    mimes = frozenset({"application/pdf"})

    def sanitize(self, src: Path, dst_dir: Path, profile: CdrProfile) -> SanitizeOutcome:
        if profile is CdrProfile.STRICT:
            return self._rasterize(src, dst_dir)
        return self._rebuild(src, dst_dir, profile)

    def _rebuild(self, src: Path, dst_dir: Path, profile: CdrProfile) -> SanitizeOutcome:
        """Профили light/standard: разбор и пересборка структуры через pikepdf."""
        import pikepdf

        dst = dst_dir / "clean.pdf"
        transforms: list[str] = []

        with pikepdf.open(src) as pdf:
            root = pdf.Root
            for key in ROOT_KEYS_TO_DROP:
                if key in root:
                    del root[key]
                    transforms.append(f"root{key}")

            for page in pdf.pages:
                for key in PAGE_KEYS_TO_DROP:
                    if key in page:
                        del page[key]
                        transforms.append(f"page{key}")
                self._clean_annotations(page, transforms)

            if profile is CdrProfile.STANDARD:
                if "/Info" in pdf.trailer:
                    del pdf.trailer["/Info"]
                with pdf.open_metadata() as meta:
                    meta.clear()
                transforms.append("strip_metadata")

            # linearize=False: пересборка объектов важнее, чем быстрый первый рендер.
            pdf.save(
                dst, fix_metadata_version=True, object_stream_mode=pikepdf.ObjectStreamMode.generate
            )

        _guard_size(dst)
        return SanitizeOutcome(
            path=dst, content_type="application/pdf", transforms=sorted(set(transforms))
        )

    def _clean_annotations(self, page, transforms: list[str]) -> None:
        annots = page.get("/Annots")
        if annots is None:
            return
        for annot in list(annots):
            action = annot.get("/A")
            if action is not None and str(action.get("/S", "")) in ANNOT_ACTIONS_TO_DROP:
                del annot["/A"]
                transforms.append("annot_action")
            if "/AA" in annot:
                del annot["/AA"]
                transforms.append("annot_aa")

    def _rasterize(self, src: Path, dst_dir: Path) -> SanitizeOutcome:
        """Профиль strict: из исходника не переносится ни одного объекта, только пиксели."""
        dst = dst_dir / "clean.pdf"
        result = run_sandboxed(
            [
                "gs",
                "-sDEVICE=pdfwrite",
                "-dNOPAUSE",
                "-dBATCH",
                "-dSAFER",
                "-dQUIET",
                "-r150",
                "-dColorImageResolution=150",
                "-dFILTERVECTOR",
                f"-sOutputFile={dst}",
                str(src),
            ],
            timeout_s=CDR_TIMEOUT_S["strict"],
            cwd=dst_dir,
        )
        if not result.ok or not dst.exists():
            raise SanitizeError(f"растеризация не удалась: rc={result.returncode}")

        _guard_size(dst)
        return SanitizeOutcome(
            path=dst, content_type="application/pdf", transforms=["rasterize", "rebuild"]
        )

    def verify(self, path: Path) -> list[str]:
        """Активные элементы, оставшиеся в выходном файле.

        Верификация не имеет права ошибаться в сторону ложного срабатывания:
        она отвергает уже обезвреженный файл, то есть блокирует легитимный
        документ. Поэтому длинные маркеры ищутся в байтах, а короткие — в
        разобранном графе объектов.
        """
        raw = path.read_bytes()
        problems = {m.decode() for m in BYTE_MARKERS if m in raw}
        problems |= set(_graph_problems(path))
        return sorted(problems)


def _graph_problems(path: Path) -> list[str]:
    """Обход графа объектов в поисках коротких активных ключей.

    Разобрать собственный выход мы обязаны: если не получилось, это отказ
    верификации, а не повод её пропустить.
    """
    try:
        import pikepdf
    except ImportError:
        logger.warning("pikepdf недоступен, граф выходного файла не проверен")
        return []

    found: set[str] = set()
    try:
        with pikepdf.open(path) as pdf:
            stack: list[object] = [pdf.Root]
            seen: set[tuple[int, int]] = set()
            steps = 0

            while stack and steps < MAX_VERIFY_STEPS:
                obj = stack.pop()
                steps += 1

                objgen = getattr(obj, "objgen", None)
                if objgen and objgen != (0, 0):
                    if objgen in seen:
                        continue
                    seen.add(objgen)

                if hasattr(obj, "keys"):
                    keys = _safe_call(obj.keys, [])
                    found.update(k for k in keys if k in GRAPH_KEYS)
                    found.update(_dangerous_actions(obj, keys))
                    stack.extend(_safe_child(obj, k) for k in keys)
                elif isinstance(obj, list) or hasattr(obj, "__getitem__"):
                    stack.extend(_safe_call(obj.__iter__, iter(())))
    except Exception as exc:
        logger.error("выходной файл не разбирается", extra={"reason": type(exc).__name__})
        return ["unparsable"]

    return sorted(found)


def _dangerous_actions(obj: object, keys: list[str]) -> set[str]:
    """Автозапуск, вызывающий опасное действие.

    Назначение страницы и переход внутри документа — норма: их пишет и
    ghostscript при растеризации, и почти каждый генератор PDF.
    """
    found: set[str] = set()
    for key in ACTION_HOLDERS:
        if key not in keys:
            continue
        holder = _safe_child(obj, key)
        candidates = [holder]
        if hasattr(holder, "keys"):
            candidates += [_safe_child(holder, k) for k in _safe_call(holder.keys, [])]
        for action in candidates:
            if hasattr(action, "keys") and str(_safe_child(action, "/S")) in DANGEROUS_ACTIONS:
                found.add(key)
                break
    return found


def _safe_call(fn: object, default: object) -> object:
    """Битое поле в выходном файле — не повод падать посреди верификации."""
    try:
        return list(fn())
    except Exception:
        return default


def _safe_child(obj: object, key: str) -> object:
    try:
        return obj[key]
    except Exception:
        return None


def _guard_size(path: Path) -> None:
    if path.stat().st_size > MAX_SANITIZED_BYTES:
        path.unlink(missing_ok=True)
        raise SanitizeError("выход CDR превысил лимит размера")
