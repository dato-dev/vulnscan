"""Таблица весов Risk Engine.

Стадия сообщает, ЧТО она нашла. Сколько это весит — решает таблица.
Раньше вес был литералом в коде стадии, и правка порога срабатывания
требовала пересборки образа.

Значения по умолчанию живут здесь, а не только в файле: сервис обязан
работать и без внешней конфигурации. Файл их переопределяет и дополняет.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from vscommon.models import Severity

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Rule:
    score: int
    severity: Severity


def _r(score: int, severity: Severity) -> Rule:
    return Rule(score=score, severity=severity)


DEFAULT_WEIGHTS: dict[str, Rule] = {
    # --- определение типа ---
    "TYPE_UNKNOWN": _r(25, Severity.MEDIUM),
    "TYPE_UNSUPPORTED": _r(30, Severity.MEDIUM),
    "TYPE_EXECUTABLE": _r(100, Severity.CRITICAL),
    "MIME_MISMATCH": _r(25, Severity.MEDIUM),
    "EXT_DANGEROUS": _r(60, Severity.HIGH),
    "EXT_MISMATCH": _r(15, Severity.LOW),
    "POLYGLOT_ARCHIVE": _r(70, Severity.HIGH),
    # Сигнатура не в начале файла: документ открывается просмотрщиком, но
    # обходит наивную проверку нулевого смещения.
    "TYPE_SIGNATURE_OFFSET": _r(35, Severity.MEDIUM),
    # Таблица сигнатур и libmagic назвали разные известные типы.
    "TYPE_DETECTOR_CONFLICT": _r(45, Severity.HIGH),
    # --- структура PDF ---
    "PDF_OPENACTION": _r(45, Severity.HIGH),
    "PDF_AUTO_ACTION": _r(40, Severity.HIGH),
    "PDF_JAVASCRIPT": _r(45, Severity.HIGH),
    "PDF_JS": _r(40, Severity.HIGH),
    "PDF_LAUNCH": _r(85, Severity.CRITICAL),
    "PDF_EMBEDDED_FILE": _r(50, Severity.HIGH),
    "PDF_EMBEDDED_NAMES": _r(50, Severity.HIGH),
    "PDF_RICHMEDIA": _r(35, Severity.MEDIUM),
    "PDF_XFA": _r(30, Severity.MEDIUM),
    "PDF_GOTOE": _r(30, Severity.MEDIUM),
    "PDF_GOTOR": _r(15, Severity.LOW),
    "PDF_SUBMITFORM": _r(30, Severity.MEDIUM),
    "PDF_JBIG2": _r(25, Severity.MEDIUM),
    "PDF_OBJSTM": _r(5, Severity.INFO),
    "PDF_EXTERNAL_URI": _r(10, Severity.LOW),
    "PDF_TOO_MANY_PAGES": _r(30, Severity.MEDIUM),
    "PDF_ENCRYPTED": _r(40, Severity.HIGH),
    "PDF_ENCRYPTED_OWNER": _r(20, Severity.MEDIUM),
    "PDF_MALFORMED": _r(35, Severity.MEDIUM),
    "PDF_IMPORTDATA": _r(35, Severity.MEDIUM),
    "PDF_SETOCGSTATE": _r(15, Severity.LOW),
    "PDF_RENDITION": _r(30, Severity.MEDIUM),
    "PDF_MOVIE": _r(25, Severity.MEDIUM),
    "PDF_SOUND": _r(25, Severity.MEDIUM),
    # --- аномалии xref и хвоста файла ---
    "PDF_XREF_RECONSTRUCTED": _r(30, Severity.MEDIUM),
    "PDF_XREF_BROKEN": _r(35, Severity.MEDIUM),
    "PDF_DAMAGED": _r(30, Severity.MEDIUM),
    # Несколько ревизий — норма для подписанных документов, поэтому вес низкий.
    "PDF_INCREMENTAL_UPDATES": _r(10, Severity.LOW),
    # А вот данные после %%EOF — это приклеенный хвост, признак polyglot.
    "PDF_TRAILING_DATA": _r(45, Severity.HIGH),
    # --- объём и вложенность ---
    "PDF_TOO_MANY_OBJECTS": _r(35, Severity.MEDIUM),
    "PDF_DEEP_NESTING": _r(40, Severity.HIGH),
    # --- аннотации ---
    "PDF_ANNOT_ACTION": _r(35, Severity.MEDIUM),
    "PDF_ANNOT_AUTO_ACTION": _r(40, Severity.HIGH),
    # Невидимая аннотация с действием не бывает случайной.
    "PDF_ANNOT_HIDDEN_ACTION": _r(70, Severity.HIGH),
    # --- шрифты: исторически богатый источник CVE в парсерах ---
    "PDF_FONT_EMBEDDED": _r(0, Severity.INFO),
    "PDF_FONT_OVERSIZED": _r(35, Severity.MEDIUM),
    "PDF_TOO_MANY_FONTS": _r(25, Severity.MEDIUM),
    # --- потоки ---
    "PDF_UNUSUAL_FILTER": _r(40, Severity.HIGH),
    "PDF_FILTER_CHAIN": _r(30, Severity.MEDIUM),
    # Слабый структурный сигнал: генераторы PDF регулярно ошибаются в длине.
    # На 40 баллах любой такой документ становился подозрительным.
    "PDF_STREAM_LENGTH_MISMATCH": _r(20, Severity.MEDIUM),
    "PDF_STREAM_BOMB": _r(70, Severity.HIGH),
    # Исполняемый файл внутри документа легитимным не бывает.
    "PDF_EMBEDDED_EXECUTABLE": _r(95, Severity.CRITICAL),
    # --- изображения ---
    "IMG_PIXEL_BOMB": _r(70, Severity.HIGH),
    "IMG_DECOMPRESSION_BOMB": _r(65, Severity.HIGH),
    "IMG_TOO_MANY_FRAMES": _r(30, Severity.MEDIUM),
    "IMG_MALFORMED": _r(35, Severity.MEDIUM),
    "IMG_HAS_EXIF": _r(0, Severity.INFO),
    # --- антивирус ---
    "AV_SIGNATURE_MATCH": _r(100, Severity.CRITICAL),
    "AV_ERROR": _r(10, Severity.LOW),
    # --- YARA: ключ по тегу правила, код формируется из его имени ---
    "YARA:critical": _r(95, Severity.CRITICAL),
    "YARA:high": _r(60, Severity.HIGH),
    "YARA:medium": _r(35, Severity.MEDIUM),
    "YARA:low": _r(15, Severity.LOW),
    # --- сбои обработки ---
    # Вердикт при сбое определяет полнота покрытия и режим отказа тенанта,
    # а не эти баллы: подкрутка веса здесь ничего не «починит».
    "STAGE_FAILED": _r(10, Severity.LOW),
    "STAGE_TIMEOUT": _r(10, Severity.LOW),
    "CDR_FAILED": _r(0, Severity.MEDIUM),
}

CODE_FAMILIES: dict[str, str] = {
    # Битая структура: три проверки видят один и тот же факт с разных сторон.
    "PDF_DAMAGED": "pdf_broken",
    "PDF_MALFORMED": "pdf_broken",
    "PDF_XREF_BROKEN": "pdf_broken",
    "PDF_XREF_RECONSTRUCTED": "pdf_broken",
    "PDF_STREAM_LENGTH_MISMATCH": "pdf_broken",
    # JavaScript находится и по длинному, и по короткому маркеру.
    "PDF_JAVASCRIPT": "pdf_js",
    "PDF_JS": "pdf_js",
    # Автозапуск: /OpenAction и /AA — один механизм.
    "PDF_OPENACTION": "pdf_autorun",
    "PDF_AUTO_ACTION": "pdf_autorun",
    # Вложение видно и в маркере, и в дереве имён.
    "PDF_EMBEDDED_FILE": "pdf_embedded",
    "PDF_EMBEDDED_NAMES": "pdf_embedded",
    # Скрытая аннотация с действием — частный случай аннотации с действием.
    "PDF_ANNOT_ACTION": "pdf_annot",
    "PDF_ANNOT_HIDDEN_ACTION": "pdf_annot",
    # Расширение и заявленный MIME врут об одном и том же.
    "MIME_MISMATCH": "type_lie",
    "EXT_MISMATCH": "type_lie",
    # Тип не распознан или не поддержан — одно наблюдение.
    "TYPE_UNKNOWN": "type_unsupported",
    "TYPE_UNSUPPORTED": "type_unsupported",
}
"""Коррелированные признаки.

Внутри семейства в балл идёт только сильнейший. Иначе битый PDF набирает сотню
из трёх взглядов на одну поломку, и легитимный скан с кривого сканера получает
вердикт `malicious`. Складывать так можно только независимые наблюдения.
"""


def family_of(code: str) -> str:
    """Семейство признака. По умолчанию — сам код: признак независим."""
    return CODE_FAMILIES.get(code, code)


FALLBACK = Rule(score=25, severity=Severity.MEDIUM)
"""Вес для кода, которого нет в таблице.

Не ноль: забытый в таблице код должен быть заметен в вердикте, а не исчезать.
"""


class WeightTable:
    def __init__(self, rules: dict[str, Rule] | None = None, degraded: bool = False) -> None:
        self._rules = {**DEFAULT_WEIGHTS, **(rules or {})}
        self.unknown_codes: set[str] = set()
        self.degraded = degraded
        """Файл весов задан, но не прочитан. Работаем на встроенных."""

    def __len__(self) -> int:
        """Сколько кодов знает таблица. Ноль означал бы пустую конфигурацию."""
        return len(self._rules)

    def rule_for(self, key: str) -> Rule:
        rule = self._rules.get(key)
        if rule is None:
            if key not in self.unknown_codes:
                logger.warning("код без веса, применён запасной", extra={"code": key})
                self.unknown_codes.add(key)
            return FALLBACK
        return rule

    def score_for(self, key: str) -> int:
        return self.rule_for(key).score

    def with_overrides(self, overrides: dict[str, int]) -> WeightTable:
        """Переопределения тенанта: только баллы, severity остаётся общей."""
        if not overrides:
            return self
        merged = {
            code: Rule(score=score, severity=self.rule_for(code).severity)
            for code, score in overrides.items()
        }
        table = WeightTable({**self._rules, **merged})
        table.unknown_codes = self.unknown_codes
        return table

    def fingerprint(self) -> str:
        """Отпечаток таблицы: входит в ключ структурного кэша.

        Правка веса обязана обесценить сохранённые признаки — они хранятся
        с уже посчитанными баллами.
        """
        payload = json.dumps(
            {
                "rules": {
                    code: (rule.score, rule.severity.value)
                    for code, rule in sorted(self._rules.items())
                },
                # Семейства входят сюда же: перегруппировка меняет балл при тех
                # же весах — внутри семейства в счёт идёт только сильнейший.
                # Без этого старая запись пережила бы правку и отдала бы балл,
                # посчитанный по прежней группировке.
                "families": {name: sorted(codes) for name, codes in sorted(CODE_FAMILIES.items())},
            },
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    @classmethod
    def load(cls, path: str | None) -> WeightTable:
        """Файл переопределяет и дополняет встроенные значения."""
        if not path:
            return cls()

        file = Path(path)
        if not file.is_file():
            logger.warning(
                "файл весов не найден, работаем на встроенных",
                extra={"path": path, "is_dir": file.is_dir()},
            )
            return cls()

        try:
            raw = json.loads(file.read_text())
            rules: dict[str, Rule] = {}
            for code, payload in raw.items():
                if code.startswith("_"):
                    continue  # комментарии в JSON
                default = DEFAULT_WEIGHTS.get(code, FALLBACK)
                rules[code] = Rule(
                    score=int(payload.get("score", default.score)),
                    severity=Severity(payload.get("severity", default.severity.value)),
                )
        except Exception:
            # Падать из-за конфигурации нельзя: встроенных весов достаточно,
            # чтобы сервис работал, а проблема видна в логе и в /readyz.
            logger.exception("файл весов не читается, работаем на встроенных")
            return cls(degraded=True)

        logger.info("веса загружены из файла", extra={"count": len(rules)})
        return cls(rules)
