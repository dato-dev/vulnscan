from __future__ import annotations

from vscommon.config import CommonSettings


class NotifierSettings(CommonSettings):
    service_name: str = "notifier"
    consumer_name: str = "notifier-1"

    callbacks_stream: str = "scan.callbacks"
    callbacks_group: str = "notifiers"

    keys_file: str | None = None
    """Реестр ключей: коллбэк подписывается ключом тенанта.

    Этот сервис недоверенный контент не разбирает, поэтому секреты здесь
    допустимы — в отличие от воркера.
    """

    callback_timeout_s: float = 10.0

    max_attempts: int = 10
    """Десять попыток с растущей паузой покрывают около получаса.

    Три попытки за несколько секунд хватало соседнему контейнеру и не хватало
    разрыву между площадками. Цифра подобрана так, чтобы пережить перезапуск
    приёмника и короткую сетевую аварию, но не удерживать задание сутки.
    """

    base_backoff_s: float = 2.0
    max_backoff_s: float = 600.0

    retry_poll_interval_s: float = 5.0


settings = NotifierSettings()
