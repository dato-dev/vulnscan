"""ZIP: бюджет распаковки на всё дерево, опись записей, извлечение (M6.1).

Модуль общий для стадии разбора и для CDR: и там и там архив открывается
заново, и оба обязаны соблюдать один и тот же бюджет. Разойдись они — и
санитайзер распаковал бы то, от чего анализ отказался.

Решение «что это значит для вердикта» здесь не принимается. Опись сообщает,
что нашла, а признаки из неё делает стадия.
"""

from __future__ import annotations

import logging
import stat
import struct
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from vscommon.limits import (
    ARCHIVE_BOMB_RATIO,
    ARCHIVE_TIME_BUDGET_S,
    MAX_ARCHIVE_DEPTH,
    MAX_ARCHIVE_ENTRIES,
    MAX_ARCHIVE_MEMBER_BYTES,
    MAX_UNPACKED_BYTES,
)

logger = logging.getLogger(__name__)

CHUNK = 1024 * 1024

MAX_CENTRAL_ENTRIES = 20 * MAX_ARCHIVE_ENTRIES
"""Сколько записей в центральном каталоге допустимо хотя бы прочитать.

`zipfile` читает каталог целиком и держит объект на каждую запись. Загрузка
в 64 МБ вмещает больше миллиона пустых записей — это полгигабайта памяти ещё
до первой проверки. Поэтому число записей читается из концевой записи архива
до того, как архив открыт.
"""

SUPPORTED_METHODS = frozenset(
    {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}
)

EXECUTABLE_NAMES = frozenset(
    {
        ".exe", ".scr", ".com", ".pif", ".cpl", ".dll", ".msi", ".msp",
        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1",
        ".bat", ".cmd", ".lnk", ".jar", ".apk", ".reg", ".sh",
        # Образы дисков: внутри них файлы теряют отметку «скачано из
        # интернета», и Windows запускает их без предупреждения.
        ".iso", ".img", ".vhd", ".vhdx",
    }
)  # fmt: skip
"""Расширения, которые в архиве с документами легитимно не встречаются.

Проверяется имя, а не содержимое: содержимое вложения проверяют стадии, а
имя — единственное, что видно у записи, которую распаковать не удалось.
"""


class ArchiveError(Exception):
    """Архив или запись не читается. Сам по себе признак, а не сбой сервиса."""


class BudgetExceededError(ArchiveError):
    """Распаковано больше, чем заявлено или чем позволяет бюджет дерева."""


@dataclass(slots=True)
class UnpackBudget:
    """Бюджет на всё дерево вложенности одного загруженного файла.

    Один объект на скан: его передают от контейнера вложениям, а не создают
    заново. Именно это и делает бюджет общим.
    """

    root_size: int
    declared: int = 0
    """Сколько обещают распаковать описи всех архивов дерева."""

    unpacked: int = 0
    """Сколько распаковано на самом деле. Заявленному размеру не верим."""

    entries: int = 0
    deadline: float = field(default_factory=lambda: time.monotonic() + ARCHIVE_TIME_BUDGET_S)

    def expired(self) -> bool:
        return time.monotonic() > self.deadline

    @property
    def ratio(self) -> float:
        return self.declared / max(self.root_size, 1)


@dataclass(frozen=True, slots=True)
class Member:
    """Запись, которую нужно распаковать и проверить."""

    index: int
    """Номер в архиве с единицы. В признаках вместо имени: имя — это ПДн."""

    info: zipfile.ZipInfo

    @property
    def ext(self) -> str | None:
        return extension(self.info.filename)

    @property
    def label(self) -> str:
        return f"#{self.index} ({self.ext or 'без расширения'})"


@dataclass(slots=True)
class Inventory:
    members: list[Member] = field(default_factory=list)
    problems: list[tuple[str, str]] = field(default_factory=list)
    """(код признака, подробность). Имён записей здесь нет — только номера."""

    encrypted: bool = False
    incomplete: list[str] = field(default_factory=list)
    """Почему проверено не всё. Непусто — архив нельзя считать проверенным."""

    bomb: bool = False

    def problem(self, code: str, detail: str) -> None:
        if all(existing != code for existing, _ in self.problems):
            self.problems.append((code, detail))


def human(size: int) -> str:
    value = float(size)
    for unit in ("Б", "КБ", "МБ"):
        if value < 1024:
            return f"{value:.0f} {unit}"
        value /= 1024
    return f"{value:.1f} ГБ"


def extension(name: str) -> str | None:
    suffix = PurePosixPath(name.replace("\\", "/")).suffix.lower()[:16]
    return suffix or None


def central_entries(path: Path) -> int | None:
    """Число записей из концевой записи архива, без чтения каталога.

    `None` — концевая запись не найдена: такой архив `zipfile` не откроет, и
    признак о битом архиве поставит уже он.
    """
    size = path.stat().st_size
    with path.open("rb") as handle:
        # Концевая запись — 22 байта плюс комментарий до 64 КБ.
        tail_size = min(size, 22 + 0xFFFF)
        handle.seek(size - tail_size)
        tail = handle.read(tail_size)
        found = tail.rfind(b"PK\x05\x06")
        if found == -1 or found + 22 > len(tail):
            return None
        total = int(struct.unpack("<H", tail[found + 10 : found + 12])[0])
        if total != 0xFFFF:
            return total

        # ZIP64: настоящее число — в отдельной записи, на которую указывает
        # локатор прямо перед концевой.
        locator = found - 20
        if locator < 0 or tail[locator : locator + 4] != b"PK\x06\x07":
            return None
        offset = struct.unpack("<Q", tail[locator + 8 : locator + 16])[0]
        if offset + 56 > size:
            return None
        handle.seek(offset)
        record = handle.read(56)
        if record[:4] != b"PK\x06\x06":
            return None
        return int(struct.unpack("<Q", record[32:40])[0])


def open_archive(path: Path) -> zipfile.ZipFile:
    """Открывает архив, если его каталог вообще можно прочитать."""
    entries = central_entries(path)
    if entries is not None and entries > MAX_CENTRAL_ENTRIES:
        raise BudgetExceededError(f"в каталоге {entries} записей")
    try:
        return zipfile.ZipFile(path)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError) as exc:
        raise ArchiveError(type(exc).__name__) from exc


def is_symlink(info: zipfile.ZipInfo) -> bool:
    return info.create_system == 3 and stat.S_ISLNK(info.external_attr >> 16)


def escapes_root(name: str) -> bool:
    """Путь выводит за каталог распаковки: `../`, абсолютный путь, диск Windows."""
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return True
    return ".." in normalized.split("/")


def is_os_metadata(info: zipfile.ZipInfo) -> bool:
    """Служебные файлы, которые кладёт архиватор macOS.

    Их нет смысла проверять как документы: это не документы, и признать
    архив из-за них непроверяемым значило бы признать непроверяемым почти
    любой архив с Mac. Совпадение строгое — иначе `__MACOSX/` стал бы
    местом, куда прячут то, что проверять не хочется. Имя такой записи
    всё равно проходит проверку на исполняемое расширение.
    """
    parts = info.filename.replace("\\", "/").split("/")
    base = parts[-1]
    if info.file_size > CHUNK:
        return False
    return base == ".DS_Store" or (parts[0] == "__MACOSX" and base.startswith("._"))


def inspect(
    zf: zipfile.ZipFile, budget: UnpackBudget, depth: int, *, collect: bool = True
) -> Inventory:
    """Опись архива: что в нём не так и что из него проверять.

    Ничего не распаковывает — работает по центральному каталогу. Заявленные
    размеры списываются с общего бюджета сразу: так бомба видна до того, как
    распакован первый байт.

    `collect=False` — для документа Word: он тоже ZIP, и бомба в нём та же, но
    его части — не файлы для проверки, их разбирает стадия документа.
    """
    inventory = Inventory()
    files = [info for info in zf.infolist() if not info.is_dir()]

    for index, info in enumerate(files, start=1):
        label = f"#{index} ({extension(info.filename) or 'без расширения'})"
        if escapes_root(info.filename):
            inventory.problem("ARCHIVE_PATH_TRAVERSAL", label)
        if is_symlink(info):
            inventory.problem("ARCHIVE_SYMLINK", label)
        if extension(info.filename) in EXECUTABLE_NAMES:
            inventory.problem("ARCHIVE_EXECUTABLE", label)
        if info.flag_bits & 0x1:
            inventory.encrypted = True

    if inventory.encrypted:
        inventory.problem("ARCHIVE_ENCRYPTED", "записи под паролем")

    declared = sum(info.file_size for info in files)
    budget.declared += declared
    if budget.declared > MAX_UNPACKED_BYTES:
        if budget.ratio >= ARCHIVE_BOMB_RATIO:
            inventory.bomb = True
            inventory.problem(
                "ARCHIVE_BOMB",
                f"{human(budget.declared)} из {human(budget.root_size)}, x{int(budget.ratio)}",
            )
            return inventory
        inventory.incomplete.append(f"объём {human(budget.declared)}")

    if not collect:
        return inventory
    if depth > MAX_ARCHIVE_DEPTH:
        inventory.incomplete.append(f"вложенность глубже {MAX_ARCHIVE_DEPTH}")
        return inventory

    room = MAX_UNPACKED_BYTES - (budget.declared - declared)
    for index, info in enumerate(files, start=1):
        if info.flag_bits & 0x1 or is_symlink(info) or is_os_metadata(info):
            continue
        if info.file_size == 0:
            continue  # проверять нечего
        if info.compress_type not in SUPPORTED_METHODS:
            inventory.incomplete.append(f"метод сжатия {info.compress_type}")
            continue
        if info.file_size > MAX_ARCHIVE_MEMBER_BYTES or info.file_size > room:
            inventory.incomplete.append("вложение больше предела")
            continue
        if budget.entries >= MAX_ARCHIVE_ENTRIES:
            inventory.incomplete.append(f"больше {MAX_ARCHIVE_ENTRIES} записей")
            break
        budget.entries += 1
        room -= info.file_size
        inventory.members.append(Member(index=index, info=info))

    return inventory


def extract(archive: Path, info: zipfile.ZipInfo, dst: Path, budget: UnpackBudget) -> Path:
    """Распаковывает одну запись, считая настоящие байты, а не заявленные.

    `zipfile` сам обрезает выход по заявленному размеру и сверяет CRC, но
    полагаться на одну проверку в чужом коде там, где цена ошибки — память
    воркера, не хочется: счёт здесь свой.
    """
    written = 0
    try:
        with open_archive(archive) as zf, zf.open(info) as src, dst.open("wb") as out:
            while chunk := src.read(CHUNK):
                written += len(chunk)
                if written > info.file_size or budget.unpacked + written > MAX_UNPACKED_BYTES:
                    raise BudgetExceededError("распаковано больше заявленного")
                out.write(chunk)
    except ArchiveError:
        dst.unlink(missing_ok=True)
        raise
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, EOFError) as exc:
        # RuntimeError — запись под паролем; NotImplementedError — метод сжатия;
        # BadZipFile — CRC или перекрывающиеся записи (бомба без рекурсии).
        dst.unlink(missing_ok=True)
        raise ArchiveError(type(exc).__name__) from exc
    finally:
        budget.unpacked += written
    return dst


def read_limited(zf: zipfile.ZipFile, name: str, limit: int) -> bytes:
    """Читает часть целиком, но не больше `limit` байт распакованного."""
    info = zf.getinfo(name)
    if info.file_size > limit:
        raise BudgetExceededError(f"часть больше {limit // (1024 * 1024)} МБ")
    try:
        with zf.open(info) as src:
            data = src.read(limit + 1)
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error, EOFError) as exc:
        raise ArchiveError(type(exc).__name__) from exc
    if len(data) > limit:
        raise BudgetExceededError("распаковано больше заявленного")
    return data


def display_name(info: zipfile.ZipInfo) -> str:
    """Имя записи в той кодировке, в которой его писали.

    Без флага UTF-8 `zipfile` читает имя как cp437. Проводник Windows с
    русской локалью пишет cp866, и «Договор.pdf» превращается в мусор.
    """
    if info.flag_bits & 0x800:
        return info.filename
    try:
        raw = info.filename.encode("cp437")
    except UnicodeEncodeError:
        return info.filename
    for encoding in ("utf-8", "cp866"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return info.filename


def safe_name(name: str, index: int) -> str:
    """Относительный путь, который никуда не выводит. Для архива на выходе CDR."""
    parts = []
    for part in name.replace("\\", "/").split("/"):
        cleaned = "".join(ch for ch in part if ch.isprintable()).strip()
        if cleaned in ("", ".", "..") or (len(cleaned) == 2 and cleaned[1] == ":"):
            continue
        parts.append(cleaned[:128])
    return "/".join(parts) or f"file-{index}"
