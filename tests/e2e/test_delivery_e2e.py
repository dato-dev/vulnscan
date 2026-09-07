"""M13.0: доставка обезвреженной копии — от приёма файла до чужого бакета.

Каждая проверка здесь соответствует утверждению, которое до сих пор держалось
только на заглушке. Заглушка возвращает то, что мы считаем поведением S3;
здесь отвечает настоящее хранилище, и учётная запись сервиса имеет права
**только на запись** — то есть проверяется заодно и M14.4, который иначе
проверить нечем: права выдаёт хранилище, а не наш код.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from stand import (
    EXTERNAL,
    SERVICE_KEY,
    SERVICE_SECRET,
    SINK_BUCKET,
    SINK_ENDPOINT,
    SINK_PREFIX,
    SINK_REGION,
    upload,
    wait_for,
)

SAMPLES = Path(__file__).parent.parent.parent / "samples" / "generated"

pytestmark = pytest.mark.e2e


def _sample(name: str) -> bytes:
    path = SAMPLES / name
    if not path.exists():
        pytest.skip(f"нет сэмпла {name} — сначала `make samples`")
    return path.read_bytes()


def _body(sink: Any, key: str) -> bytes:
    return sink.get_object(Bucket=SINK_BUCKET, Key=key)["Body"].read()


def test_clean_file_arrives_with_its_manifest(sink: Any) -> None:
    """Основной путь целиком: приём, проверка, пересборка, выгрузка.

    Это то самое утверждение, которое неделю держалось на подделанном `boto3`.
    """
    result = upload(_sample("benign.pdf"), "Договор аренды.pdf")
    assert result["verdict"] == "clean", result

    keys = wait_for(sink, lambda found: any(k.endswith(".pdf") for k in found))
    files = [k for k in keys if k.endswith(".pdf")]

    assert files, f"копия не появилась в приёмнике: {keys}"
    assert f"{files[0]}.vulnscan.json" in keys, "файл есть, манифеста рядом нет"


def test_the_name_is_built_from_the_template(sink: Any) -> None:
    """Имя собирается по `key_template`, включая исходное имя файла.

    Проверяется на настоящем хранилище: ключ с кириллицей и пробелом — то
    место, где подделка сказала бы «сохранил», а S3 мог бы отказать.
    """
    upload(_sample("benign.pdf"), "Договор аренды.pdf")

    keys = wait_for(sink, lambda found: any("Договор аренды-Проверено-clean" in k for k in found))

    assert any("Договор аренды-Проверено-clean" in key for key in keys), keys


def test_a_blocked_file_is_rebuilt_into_its_own_directory(sink: Any) -> None:
    """Красная зона: файл заблокирован, но пересобран и отдан отдельно.

    Отдельный каталог — не косметика: скрипт на стороне клиента обрабатывает
    каталог целиком и манифест у каждого файла не читает.
    """
    result = upload(_sample("pdf_launch.pdf"), "Опасный.pdf")
    assert result["verdict"] == "malicious", result

    keys = wait_for(sink, lambda found: any("_rebuilt/" in k for k in found))
    rebuilt = [k for k in keys if "_rebuilt/" in k]

    assert rebuilt, f"пересобранной копии нет: {keys}"
    manifest_key = next(k for k in rebuilt if k.endswith(".vulnscan.json"))
    manifest = json.loads(_body(sink, manifest_key))

    assert manifest["rebuilt_from_blocked"] is True
    assert manifest["verdict"] == "malicious", "пересборка не смягчает вердикт"
    assert manifest["delivered"] is True


def test_the_manifest_explains_a_refusal(sink: Any) -> None:
    """Отказ виден в самом ящике, а не только в наших логах.

    Пустой приёмник означает одновременно «заблокирован», «ещё в работе» и
    «сервис сломался». Манифест — единственное, что их различает.
    """
    upload(_sample("pdf_launch.pdf"), "Опасный.pdf")

    keys = wait_for(sink, lambda found: any(k.endswith(".vulnscan.json") for k in found))
    manifests = [json.loads(_body(sink, k)) for k in keys if k.endswith(".vulnscan.json")]
    blocked = [m for m in manifests if m["verdict"] == "malicious"]

    assert blocked, "решение о заблокированном файле в приёмник не попало"
    assert any(m["findings"] for m in blocked), "манифест не объясняет, что нашли"


def test_write_only_credentials_are_enough(sink: Any) -> None:
    """Учётке сервиса хватает права на запись — и только его.

    Единственный способ это проверить: права выдаёт хранилище, а не наш код.
    Тест со списком запрещённых вызовов доказывает лишь то, что мы их не
    пишем, — а не то, что без них всё работает.

    Обратная сторона: этой же учёткой нельзя прочитать записанное. Если
    получится — политика в стенде разошлась с той, что описана в
    `docs/policies.md`, и M14.4 держится на честном слове.
    """
    boto3 = pytest.importorskip("boto3")

    service = boto3.client(
        "s3",
        endpoint_url=SINK_ENDPOINT,
        aws_access_key_id=SERVICE_KEY,
        aws_secret_access_key=SERVICE_SECRET,
        region_name=SINK_REGION,
    )

    upload(_sample("benign.pdf"), "Договор.pdf")
    keys = wait_for(sink, lambda found: any(k.endswith(".pdf") for k in found))
    assert keys, "выгрузка не прошла — значит прав на запись не хватило"

    with pytest.raises(Exception, match=r"(?i)denied|forbidden"):
        service.get_object(Bucket=SINK_BUCKET, Key=keys[0])

    with pytest.raises(Exception, match=r"(?i)denied|forbidden"):
        service.list_objects_v2(Bucket=SINK_BUCKET, Prefix=SINK_PREFIX)


def test_nothing_lands_outside_the_tenant_prefix(sink: Any) -> None:
    """Всё, что уехало, лежит под префиксом тенанта.

    Префикс — единственное, что ограничивает ущерб при утечке учётки. Объект
    мимо него означал бы, что ограничение существует только на бумаге.
    """
    upload(_sample("benign.pdf"), "Договор.pdf")
    wait_for(sink, lambda found: bool(found))

    if EXTERNAL:
        # В общем бакете лежат объекты прошлых прогонов под своими префиксами:
        # учётка сервиса умеет только писать и за собой не убирает. Считать их
        # «мимо префикса» значило бы падать на исправной работе.
        pytest.skip("на внешнем бакете проверяется владельцем: правилом на префикс")

    everything = sink.list_objects_v2(Bucket=SINK_BUCKET)
    stray = [
        item["Key"]
        for item in everything.get("Contents", [])
        if not item["Key"].startswith(SINK_PREFIX)
    ]

    assert not stray, f"объекты мимо префикса тенанта: {stray}"


# --- антивирус в цепочке ---------------------------------------------------


def test_eicar_is_caught_by_the_real_antivirus(sink: Any) -> None:
    """Канонический вредоносный образец ловится настоящим clamd.

    Без этого стенд подтверждал бы работу конвейера, которого в бою нет:
    `clamav` входит в `ESSENTIAL_STAGES`, и с выключенным антивирусом вердикт
    `clean` выдавался бы, ни разу не пройдя через сигнатурный детект.

    EICAR — не PDF, поэтому вердикт приходит не от YARA и не от разбора
    структуры: отвечает именно антивирус.
    """
    result = upload(_sample("eicar.com"), "eicar.com")

    assert result["verdict"] == "malicious", result
    engines = result.get("engines", {})
    assert engines.get("clamav", {}).get("status") not in (None, "disabled"), (
        f"антивирус не участвовал в проверке: {engines}"
    )


def test_a_clean_verdict_required_the_antivirus_to_run(sink: Any) -> None:
    """`clean` выдаётся только когда обязательные стадии отработали.

    Главное правило сервиса (M1.7): недоступный clamd когда-то молча выдавал
    `clean` на всё подряд. Проверка стоит здесь, а не на заглушке, потому что
    заглушке нечего сообщать о том, работал ли демон.
    """
    result = upload(_sample("benign.pdf"), "Договор.pdf")

    assert result["verdict"] == "clean", result
    assert result["engines"]["clamav"]["status"] == "OK", result["engines"]
