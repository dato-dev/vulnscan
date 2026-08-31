"""Метрики зеркала баз ClamAV.

M10.10. Зеркало — единственный компонент, который ходит наружу, и единственный,
чей отказ ничем себя не проявляет: `cvd serve` продолжает раздавать то, что уже
скачано, clamd продолжает отвечать, проверки продолжают идти. Разница только в
том, что базы стареют, а узнать об этом можно было бы по вердиктам — то есть
поздно и по факту пропуска.

Отдельный процесс, а не часть `cvd serve`: обёртывать чужую утилиту ради метрик
дороже, чем смотреть на результат её работы со стороны. Результат её работы —
файлы в каталоге, и возраст самого свежего отвечает на нужный вопрос целиком.

Метрики намеренно с префиксом `cvd_mirror_`, а не `vs_`: `vs_` принадлежит
нашему коду, а здесь измеряется поведение внешней утилиты.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from prometheus_client import Gauge, start_http_server

logger = logging.getLogger(__name__)

DB_DIR = Path(os.environ.get("CVD_DB_DIR", "/db"))
PORT = int(os.environ.get("METRICS_PORT", "9104"))
INTERVAL_S = 60.0

# Расширения, ради которых зеркало существует. `.cvd` — полные базы, `.cdiff` —
# инкременты; последние появляются между полными выкладками, и их отсутствие
# само по себе ни о чём не говорит.
DB_SUFFIXES = (".cvd", ".cdiff")

age = Gauge("cvd_mirror_db_age_seconds", "Возраст файла базы", ("db",))
newest = Gauge("cvd_mirror_newest_db_age_seconds", "Возраст самого свежего файла базы")
files = Gauge("cvd_mirror_db_files", "Файлов баз в каталоге")
size = Gauge("cvd_mirror_db_bytes", "Суммарный размер баз")


def collect(directory: Path = DB_DIR) -> None:
    """Снимает состояние каталога баз.

    Возраст считается по времени изменения файла: `cvd` перезаписывает базу
    целиком, а не дописывает, поэтому mtime и есть время последнего успешного
    обновления. Разбирать заголовок CVD ради даты сборки не нужно — нас
    интересует, когда мы её получили, а не когда её собрали.
    """
    found = [p for p in directory.glob("*") if p.suffix in DB_SUFFIXES]
    files.set(len(found))
    size.set(sum(p.stat().st_size for p in found))

    if not found:
        # Пустой каталог — это работающая раздача без единой базы. Явный ноль
        # лучше отсутствия ряда: отсутствие неотличимо от неработающего
        # экспортёра.
        newest.set(0)
        return

    now = time.time()
    ages = []
    for path in found:
        seconds = max(0.0, now - path.stat().st_mtime)
        age.labels(db=path.name).set(seconds)
        ages.append(seconds)
    newest.set(min(ages))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    start_http_server(PORT)
    logger.info("экспортёр зеркала слушает %s, каталог %s", PORT, DB_DIR)

    while True:
        try:
            collect()
        except Exception:
            # Экспортёр не имеет права уронить зеркало: раздача важнее метрик.
            logger.exception("не удалось снять состояние каталога баз")
        time.sleep(INTERVAL_S)


if __name__ == "__main__":
    main()
