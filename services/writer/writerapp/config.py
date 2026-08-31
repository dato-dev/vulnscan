from __future__ import annotations

from vscommon.config import CommonSettings


class WriterSettings(CommonSettings):
    service_name: str = "writer"
    consumer_name: str = "writer-1"

    postgres_dsn: str = "postgresql://vulnscan:vulnscan@postgres:5432/vulnscan"
    """Строка подключения. Владеет БД только этот сервис."""

    results_stream: str = "scan.results"
    results_group: str = "writers"

    batch_size: int = 32
    """Сколько результатов писать одной транзакцией."""

    flush_interval_s: float = 2.0
    """Как часто сбрасывать накопленное, даже если пачка не заполнилась.

    Без этого история ждала бы 32 скана: при небольшом потоке она оставалась бы
    невидимой часами, а ради неё сервис и существует.
    """

    history_retention_days: int = 90
    """Срок хранения истории. Ноль — не удалять (нужно решать осознанно)."""


settings = WriterSettings()
