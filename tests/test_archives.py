"""M6.1, M6.2: архивы — бомбы, общий бюджет, вложения и их признаки."""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import office_samples as samples
import pytest

from vscommon.models import ObjectRef, ScanJob, ScanMode, TenantPolicy, Verdict
from vscommon.storage import LocalStore
from worker_app import archive
from worker_app import pipeline as pipeline_module
from worker_app.pipeline import Pipeline
from worker_app.stages.base import ScanContext, Stage
from worker_app.stages.filetype import FiletypeStage
from worker_app.stages.structure import StructureStage

pikepdf = pytest.importorskip("pikepdf")

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class FakeAv(Stage):
    """Антивирус, который видит EICAR в байтах файла — и только в них.

    Как и настоящий по отношению к сжатому потоку: EICAR внутри deflate
    этими байтами не выглядит.
    """

    name = "clamav"

    def __init__(self) -> None:
        self.seen = 0

    def run(self, ctx: ScanContext) -> None:
        self.seen += 1
        if EICAR in ctx.path.read_bytes():
            ctx.add(self.name, "AV_SIGNATURE_MATCH", "Eicar-Signature")


class QuietYara(Stage):
    name = "yara"

    def run(self, ctx: ScanContext) -> None:
        return None


def _pdf(launch: bool = False) -> bytes:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    if launch:
        pdf.Root["/OpenAction"] = pdf.make_indirect(
            pikepdf.Dictionary(S=pikepdf.Name("/Launch"), F=pikepdf.String("calc.exe"))
        )
    buffer = io.BytesIO()
    pdf.save(buffer)
    return buffer.getvalue()


@pytest.fixture()
def scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Прогон конвейера на настоящих стадиях разбора и поддельном антивирусе."""
    monkeypatch.setattr(pipeline_module.settings, "work_dir", str(tmp_path / "work"))
    root = tmp_path / "store"
    (root / "raw" / "a").mkdir(parents=True)

    async def run(data: bytes, *, av: FakeAv | None = None, **job_fields: object):
        (root / "raw" / "a" / "aaa").write_bytes(data)
        job = ScanJob(
            scan_id="scan-1",
            sha256="a" * 64,
            source=ObjectRef(backend="local", bucket="raw", key="a/aaa"),
            size=len(data),
            mode=job_fields.pop("mode", ScanMode.DETECT),
            filename_ext=".zip",
            declared_mime="application/zip",
            **job_fields,
        )
        stages = (FiletypeStage(), StructureStage(), av or FakeAv(), QuietYara())
        return await Pipeline(LocalStore(str(root)), stages=stages).process(job)

    return run


def _codes(result) -> set[str]:
    return {f.code for f in result.findings}


# --- M6.2: вложения ---


async def test_malicious_pdf_inside_zip_is_not_clean(scan) -> None:
    """Критерий M6.2: ZIP с вредоносным PDF внутри не получает `clean`."""
    result = await scan(samples.zip_of({"Счёт.pdf": _pdf(launch=True)}))

    assert result.verdict is not Verdict.CLEAN
    finding = next(f for f in result.findings if f.code == "PDF_LAUNCH")
    # Откуда признак — по номеру записи, а не по имени: имя — это ПДн.
    assert finding.detail.startswith("вложение #1 (.pdf)")
    assert "Счёт" not in finding.detail


async def test_antivirus_sees_what_compression_hides(scan) -> None:
    """Сжатый EICAR антивирус по архиву не видит; вложение он видит.

    Проверка того, что вложения действительно прогоняются через стадии, а не
    только упоминаются в описи.
    """
    data = samples.zip_of({"doc.pdf": _pdf(), "tools/eicar.bin": EICAR})
    assert EICAR not in data

    result = await scan(data)

    assert result.verdict is Verdict.MALICIOUS
    assert "AV_SIGNATURE_MATCH" in _codes(result)


async def test_clean_archive_of_documents_is_clean(scan) -> None:
    result = await scan(samples.zip_of({"a.pdf": _pdf(), "b/c.pdf": _pdf()}))

    assert result.verdict is Verdict.CLEAN, result.findings


async def test_unsupported_member_makes_archive_unsupported(scan) -> None:
    """Непроверенное вложение делает непроверенным весь архив."""
    result = await scan(samples.zip_of({"a.pdf": _pdf(), "notes.txt": b"hello"}))

    assert result.verdict is Verdict.UNSUPPORTED


async def test_member_does_not_inherit_request_labels(scan) -> None:
    """Заявленные клиентом тип и расширение — про архив, а не про PDF внутри."""
    result = await scan(samples.zip_of({"a.pdf": _pdf()}))

    assert not _codes(result) & {"MIME_MISMATCH", "EXT_MISMATCH"}


async def test_macos_metadata_does_not_spoil_archive(scan) -> None:
    """Архив с Mac кладёт `__MACOSX/._*` и `.DS_Store`. Непроверяемым он от
    этого стать не должен."""
    data = samples.zip_of(
        {
            "doc.pdf": _pdf(),
            "__MACOSX/._doc.pdf": b"\x00\x05\x16\x07" + b"\x00" * 60,
            ".DS_Store": b"\x00\x00\x00\x01Bud1" + b"\x00" * 100,
        }
    )

    result = await scan(data)

    assert result.verdict is Verdict.CLEAN, result.findings


def test_metadata_exemption_is_narrow() -> None:
    """`__MACOSX/` — не место, куда прячут непроверяемое."""
    big = zipfile.ZipInfo("__MACOSX/._x")
    big.file_size = archive.CHUNK + 1
    elsewhere = zipfile.ZipInfo("docs/._x")
    elsewhere.file_size = 10

    assert not archive.is_os_metadata(big)
    assert not archive.is_os_metadata(elsewhere)


async def test_scan_stops_once_archive_is_blocked(scan) -> None:
    """Уже заблокированный архив дальше не распаковывается."""
    av = FakeAv()
    members = {"eicar.bin": EICAR, **{f"{i}.pdf": _pdf() for i in range(20)}}

    result = await scan(samples.zip_of(members), av=av)

    assert result.verdict is Verdict.MALICIOUS
    assert av.seen < 5


async def test_member_files_do_not_outlive_scan(scan, tmp_path: Path) -> None:
    await scan(samples.zip_of({"a.pdf": _pdf(), "b.pdf": _pdf()}))

    leftovers = [p for p in (tmp_path / "work").rglob("*") if p.is_file()]
    assert leftovers == []


# --- M6.1: бомбы и общий бюджет ---


async def test_ten_megabytes_to_ten_gigabytes_is_blocked(scan, monkeypatch) -> None:
    """Критерий M6.1: 10 МБ → 10 ГБ блокируется, и до распаковки.

    Заявленные размеры подменены в каталоге: сжимать 10 ГБ в тесте незачем,
    опись обязана отказать по каталогу, не распаковав ни байта.
    """
    padding = os.urandom(10 * 1024 * 1024)
    data = samples.with_declared_size(
        samples.zip_of(
            {"pad.bin": padding, "a.bin": b"1", "b.bin": b"2"},
            compression=zipfile.ZIP_STORED,
        ),
        3_500_000_000,
    )
    assert 10 * 1024 * 1024 < len(data) < 11 * 1024 * 1024

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("бомба распакована")

    monkeypatch.setattr(archive, "extract", forbidden)
    result = await scan(data)

    assert result.verdict is Verdict.MALICIOUS
    assert "ARCHIVE_BOMB" in _codes(result)


def _zeros_zip(size: int) -> bytes:
    return samples.zip_of({"zeros.bin": b"\x00" * size})


async def test_budget_is_shared_by_whole_tree(scan, monkeypatch) -> None:
    """Критерий M6.1: бюджет общий, а не на каждый архив.

    Три вложенных архива по 400 КБ нулей при бюджете в мегабайт: каждый
    по отдельности проходит, вместе — нет. Так устроен 42.zip.
    """
    monkeypatch.setattr(archive, "MAX_UNPACKED_BYTES", 1024 * 1024)
    inner = _zeros_zip(400 * 1024)

    alone = archive.inspect(
        zipfile.ZipFile(io.BytesIO(inner)), archive.UnpackBudget(root_size=len(inner)), 1
    )
    assert not alone.bomb and not alone.incomplete

    data = samples.zip_of({f"part{i}.zip": inner for i in range(3)})
    result = await scan(data)

    assert result.verdict is Verdict.MALICIOUS
    assert "ARCHIVE_BOMB" in _codes(result)


async def test_large_but_compressible_like_documents_is_incomplete(scan, monkeypatch) -> None:
    """Превышение бюджета без бомбового сжатия — не бомба, а «не проверили»."""
    from PIL import Image

    def noise() -> bytes:
        buffer = io.BytesIO()
        Image.frombytes("RGB", (100, 70), os.urandom(100 * 70 * 3)).save(buffer, "PNG")
        return buffer.getvalue()

    monkeypatch.setattr(archive, "MAX_UNPACKED_BYTES", 64 * 1024)
    # Шум не сжимается: архив большой, но не бомба.
    data = samples.zip_of({f"{i}.png": noise() for i in range(5)})

    result = await scan(data)

    assert "ARCHIVE_BOMB" not in _codes(result)
    assert "ARCHIVE_INCOMPLETE" in _codes(result)
    assert result.verdict is Verdict.UNSUPPORTED


async def test_nesting_deeper_than_limit_is_not_clean(scan) -> None:
    """Архив в архиве глубже предела — непроверенный. Так же кончается квайн."""
    data = _pdf()
    for level in range(8):
        data = samples.zip_of({f"level{level}.zip" if level else "doc.pdf": data})

    result = await scan(data)

    assert result.verdict is Verdict.UNSUPPORTED
    assert any("вложенность" in (f.detail or "") for f in result.findings)


async def test_lying_declared_size_is_not_trusted(scan) -> None:
    """Заявлено меньше, чем лежит: распаковщик не доверяет и не выдаёт `clean`."""
    data = samples.with_declared_size(samples.zip_of({"a.pdf": _pdf()}), 10)

    result = await scan(data)

    assert result.verdict is not Verdict.CLEAN
    assert "ARCHIVE_MALFORMED" in _codes(result)


def test_extract_counts_real_bytes(tmp_path: Path, monkeypatch) -> None:
    """Счёт распакованного свой, а не по заявленному размеру."""
    monkeypatch.setattr(archive, "MAX_UNPACKED_BYTES", 1000)
    src = tmp_path / "a.zip"
    src.write_bytes(_zeros_zip(5000))
    budget = archive.UnpackBudget(root_size=src.stat().st_size)
    with zipfile.ZipFile(src) as zf:
        info = zf.infolist()[0]

    with pytest.raises(archive.BudgetExceededError):
        archive.extract(src, info, tmp_path / "out.bin", budget)
    assert not (tmp_path / "out.bin").exists()


def test_huge_central_directory_is_refused_before_opening(tmp_path: Path, monkeypatch) -> None:
    """Каталог на миллион записей — это память, занятая до первой проверки."""
    monkeypatch.setattr(archive, "MAX_CENTRAL_ENTRIES", 10)
    src = tmp_path / "many.zip"
    src.write_bytes(samples.zip_of({f"{i}.txt": b"" for i in range(11)}))

    assert archive.central_entries(src) == 11
    with pytest.raises(archive.BudgetExceededError):
        archive.open_archive(src)


async def test_time_budget_leaves_archive_unchecked(scan, monkeypatch) -> None:
    monkeypatch.setattr(archive, "ARCHIVE_TIME_BUDGET_S", -1.0)

    result = await scan(samples.zip_of({"a.pdf": _pdf()}))

    assert result.verdict is Verdict.UNSUPPORTED
    assert "ARCHIVE_INCOMPLETE" in _codes(result)


# --- M6.1: пути, ссылки, исполняемое, пароль ---


async def test_path_traversal_flagged(scan) -> None:
    result = await scan(samples.zip_of({"../../etc/cron.d/x.pdf": _pdf()}))

    assert "ARCHIVE_PATH_TRAVERSAL" in _codes(result)


@pytest.mark.parametrize("name", ["/etc/x.pdf", "C:\\Windows\\x.pdf", "a/../../x.pdf"])
def test_escaping_names(name: str) -> None:
    assert archive.escapes_root(name)


def test_plain_names_do_not_escape() -> None:
    assert not archive.escapes_root("папка/Договор..v2.pdf")


async def test_symlink_flagged(scan) -> None:
    result = await scan(samples.zip_with_symlink())

    assert "ARCHIVE_SYMLINK" in _codes(result)


async def test_executable_name_flagged(scan) -> None:
    result = await scan(samples.zip_of({"счёт.pdf.exe": _pdf()}))

    assert "ARCHIVE_EXECUTABLE" in _codes(result)


async def test_encrypted_archive_is_encrypted(scan) -> None:
    result = await scan(samples.mark_encrypted(samples.zip_of({"a.pdf": _pdf()})))

    assert result.verdict is Verdict.ENCRYPTED


async def test_broken_archive_is_not_clean(scan) -> None:
    result = await scan(b"PK\x03\x04" + b"\x00" * 200)

    assert result.verdict is not Verdict.CLEAN
    assert "ARCHIVE_MALFORMED" in _codes(result)


async def test_fail_open_does_not_whitewash_unchecked_archive(scan) -> None:
    """Непроверенное — `unsupported`, а не сбой: режим отказа его не касается."""
    result = await scan(
        samples.zip_of({"notes.txt": b"x"}),
        policy=TenantPolicy(fail_mode="fail-open"),
    )

    assert result.verdict is Verdict.UNSUPPORTED


# --- определение типа ---


def _detect(tmp_path: Path, data: bytes) -> ScanContext:
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    ctx = ScanContext(
        job=ScanJob(
            scan_id="s",
            sha256="a" * 64,
            source=ObjectRef(backend="local", bucket="b", key="k"),
            size=len(data),
        ),
        path=path,
    )
    FiletypeStage().safe_run(ctx)
    return ctx


def test_docx_is_told_apart_from_zip(tmp_path: Path) -> None:
    ctx = _detect(tmp_path, samples.clean_docx())

    assert ctx.detected_mime == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert ctx.supported


def test_macro_document_detected_as_docm(tmp_path: Path) -> None:
    assert _detect(tmp_path, samples.macro_docm()).detected_mime == (
        "application/vnd.ms-word.document.macroEnabled.12"
    )


def test_jar_is_executable(tmp_path: Path) -> None:
    """JAR — тоже ZIP, но запускается одним щелчком."""
    data = samples.zip_of({"META-INF/MANIFEST.MF": b"Main-Class: A\n", "A.class": b"\xca\xfe"})

    ctx = _detect(tmp_path, data)

    assert "TYPE_EXECUTABLE" in {f.code for f in ctx.findings}


def test_spreadsheet_is_not_supported_yet(tmp_path: Path) -> None:
    data = samples.zip_of({"[Content_Types].xml": b"<Types/>", "xl/workbook.xml": b"<w/>"})

    ctx = _detect(tmp_path, data)

    assert not ctx.supported


# --- пересборка через конвейер ---


async def test_clean_archive_gets_rebuilt_copy(scan, tmp_path: Path) -> None:
    result = await scan(samples.zip_of({"a.pdf": _pdf()}), mode=ScanMode.BOTH)

    assert result.verdict is Verdict.CLEAN
    assert result.sanitized is not None
    assert result.sanitized.ref.key.endswith(".zip")


async def test_macro_document_in_archive_is_delivered_without_macro(scan, tmp_path: Path) -> None:
    """Макрос — `suspicious`, а не блокировка: копия уходит, и макроса в ней нет."""
    result = await scan(samples.zip_of({"a.docm": samples.macro_docm()}), mode=ScanMode.BOTH)

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.sanitized is not None
    stored = tmp_path / "store" / result.sanitized.ref.bucket / result.sanitized.ref.key
    with zipfile.ZipFile(stored) as outer:
        inner = zipfile.ZipFile(io.BytesIO(outer.read("a.docm")))
        assert not any("vba" in name.lower() for name in inner.namelist())


def test_parallel_archive_rebuilds_do_not_share_budget(tmp_path: Path, monkeypatch) -> None:
    """Бюджет и глубина пересборки — в контекстных переменных, не в объекте.

    Санитайзер один на процесс, а CDR идёт в пуле потоков. Будь бюджет полем
    объекта, параллельные пересборки делили бы его, и одна отказывала бы из-за
    объёма другой.
    """
    from concurrent.futures import ThreadPoolExecutor

    from vscommon.models import CdrProfile
    from worker_app.cdr.archive import ZipSanitizer

    # Одной пересборке трёх записей хватает, двум общим — уже нет.
    monkeypatch.setattr(archive, "MAX_ARCHIVE_ENTRIES", 4)
    sanitizer = ZipSanitizer()
    data = samples.zip_of({f"{i}.pdf": _pdf() for i in range(3)})

    def rebuild(n: int) -> list[str]:
        work = tmp_path / f"run{n}"
        work.mkdir()
        src = work / "in.zip"
        src.write_bytes(data)
        outcome = sanitizer.sanitize(src, work, CdrProfile.STANDARD)
        return sanitizer.verify(outcome.path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(rebuild, range(16)))

    assert results == [[]] * 16
