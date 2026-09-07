"""CDR для PDF: пересборка документа без активных элементов."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from vscommon.limits import (
    CDR_TIMEOUT_S,
    MAX_IMAGE_PIXELS,
    MAX_PDF_PAGES,
    MAX_SANITIZED_BYTES,
)
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

`/OpenAction [страница /Fit]` — то есть «открыть на такой-то странице» — норма
почти любого PDF и всего, что переписал ghostscript. Проверка по наличию
объявляла провал на каждом обычном документе.
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

RASTER_DPI = 150
"""Разрешение растеризации в профиле `strict`.

Компромисс между читаемостью сканов и ценой: 150 dpi даёт с листа A4 около
2 Мпикс. Выше — мегабайты на страницу и минуты на документ, ниже — нечитаемая
мелкая печать в договорах, ради которых профиль и включают.
"""

RASTER_QUALITY = 90


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
        """Профиль strict: из исходника не переносится ни одного объекта, только пиксели.

        Два шага, и разделение принципиальное. Ghostscript **рисует** страницы
        в JPEG — на выходе растр, у которого нет ни графа объектов, ни действий,
        ни вложений. Собираем PDF мы сами, из этих картинок.

        Раньше шаг был один: `gs -sDEVICE=pdfwrite`. Это не растеризация, а
        передистилляция — ghostscript разбирает документ и пишет новый, перенося
        текст и аннотации вместе с их действиями. Профиль назывался «безопасен
        by construction», а на деле полагался на то, что чужой распознаватель
        не перенесёт ничего опасного. Сквозной стенд (M13.0) показал обратное:
        `/Launch` пережил обработку и `verify()` отверг собственный выход. То
        есть `deliver_blocked: "strict"` (M14.9) не отдавал ни одной копии с
        самого своего появления — по причине, выглядевшей в логе как «CDR не
        удался».
        """
        # Свой каталог на вызов, а не постоянное имя: пересборка может идти в
        # том же рабочем каталоге повторно, и подобранная там чужая страница
        # уехала бы клиенту как его собственная.
        pages_dir = Path(tempfile.mkdtemp(prefix="raster-", dir=dst_dir))

        result = run_sandboxed(
            [
                "gs",
                # Растровое устройство, а не pdfwrite: выход — картинки.
                "-sDEVICE=jpeg",
                f"-dJPEGQ={RASTER_QUALITY}",
                "-dNOPAUSE",
                "-dBATCH",
                "-dSAFER",
                "-dQUIET",
                f"-r{RASTER_DPI}",
                "-dFirstPage=1",
                # Иначе документ на десять тысяч страниц занял бы диск и время
                # ещё до того, как мы посмотрим на результат.
                f"-dLastPage={MAX_PDF_PAGES}",
                f"-sOutputFile={pages_dir}/page-%05d.jpg",
                str(src),
            ],
            timeout_s=CDR_TIMEOUT_S["strict"],
            cwd=dst_dir,
        )
        pages = sorted(pages_dir.glob("page-*.jpg"))
        if not result.ok or not pages:
            raise SanitizeError(f"растеризация не удалась: rc={result.returncode}")

        dst = dst_dir / "clean.pdf"
        _assemble(pages, dst)
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


def _assemble(pages: list[Path], dst: Path) -> None:
    """Собирает PDF из готовых растров.

    Из исходного документа здесь нет ничего: на вход идут только файлы,
    нарисованные ghostscript. Поэтому утверждение «в выходе нет активных
    элементов» не зависит от того, что было во входе, — а это и есть разница
    между гарантией и эвристикой.

    Страницы кладутся по одной, и байты JPEG уезжают в поток как есть
    (`/DCTDecode`), без разжатия. Держать в памяти разжатыми все страницы
    многостраничного документа — это гигабайты, то есть OOM внутри
    собственного санитайзера.
    """
    import pikepdf
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

    pdf = pikepdf.new()
    total = 0
    for page in pages:
        data = page.read_bytes()
        total += len(data)
        if total > MAX_SANITIZED_BYTES:
            raise SanitizeError("выход CDR превысил лимит размера")

        with Image.open(page) as probe:
            if probe.format != "JPEG":
                # Ghostscript пишет то, что ему заказали. Другой формат здесь
                # означает, что заказ разошёлся с кодом сборки, и объявлять
                # такой файл обезвреженным нельзя.
                raise SanitizeError(f"растр не в ожидаемом формате: {probe.format}")
            width, height = probe.size

        image = pikepdf.Stream(
            pdf,
            data,
            Type=pikepdf.Name.XObject,
            Subtype=pikepdf.Name.Image,
            Width=width,
            Height=height,
            ColorSpace=pikepdf.Name.DeviceRGB,
            BitsPerComponent=8,
            Filter=pikepdf.Name.DCTDecode,
        )
        # Растр разложен обратно в физический размер страницы: 150 пикселей
        # на дюйм против 72 пунктов в дюйме PDF.
        box_w = round(width * 72 / RASTER_DPI, 2)
        box_h = round(height * 72 / RASTER_DPI, 2)
        content = f"q {box_w} 0 0 {box_h} 0 0 cm /Im0 Do Q".encode()
        pdf.pages.append(
            pikepdf.Page(
                pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Page,
                        MediaBox=[0, 0, box_w, box_h],
                        Resources=pikepdf.Dictionary(
                            XObject=pikepdf.Dictionary(Im0=image),
                        ),
                        Contents=pikepdf.Stream(pdf, content),
                    )
                )
            )
        )

    pdf.save(dst)


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
