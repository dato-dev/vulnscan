"""Объектное хранилище. S3/MinIO в проде, локальный каталог в тестах."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import BinaryIO, Protocol

from vscommon.config import CommonSettings
from vscommon.models import ObjectRef

logger = logging.getLogger(__name__)


def _stream_size(fileobj: BinaryIO) -> int:
    """Длина потока с возвратом курсора в начало."""
    fileobj.seek(0, os.SEEK_END)
    size = fileobj.tell()
    fileobj.seek(0)
    return size


class ObjectStore(Protocol):
    def put(self, bucket: str, key: str, fileobj: BinaryIO, content_type: str) -> ObjectRef: ...

    def get_to_path(self, ref: ObjectRef, dest: Path) -> Path: ...

    def exists(self, ref: ObjectRef) -> bool: ...

    def presign(self, ref: ObjectRef, ttl_s: int) -> str | None: ...


class S3Store:
    """MinIO / S3. Клиент создаётся один раз на процесс."""

    def __init__(self, settings: CommonSettings) -> None:
        import boto3  # локальный импорт: тестам boto3 не нужен

        self._client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name=settings.s3_region,
        )

    def ensure_buckets(self, *buckets: str) -> None:
        for bucket in buckets:
            try:
                self._client.head_bucket(Bucket=bucket)
            except Exception:
                logger.info("создаю бакет", extra={"bucket": bucket})
                self._client.create_bucket(Bucket=bucket)

    def apply_retention(self, bucket: str, days: int) -> bool:
        """Срок хранения объектов бакета. Возвращает, удалось ли применить.

        Здесь лежат сканы паспортов и договоров. Хранилище, которое ничего не
        удаляет, со временем превращается в архив чужих документов — и это
        риск сам по себе, независимо от того, вредоносны файлы или нет.

        Срок выставляется правилом на стороне хранилища, а не уборщиком в
        коде: процесс, который «должен» подчищать, однажды не запустится, а
        правило в бакете переживёт и рестарт, и переезд.
        """
        if days <= 0:
            logger.warning(
                "срок хранения не задан, объекты будут накапливаться",
                extra={"bucket": bucket},
            )
            return False
        try:
            self._client.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={
                    "Rules": [
                        {
                            "ID": "vulnscan-retention",
                            "Status": "Enabled",
                            "Filter": {"Prefix": ""},
                            "Expiration": {"Days": days},
                        }
                    ]
                },
            )
        except Exception:
            # Не все реализации S3 поддерживают lifecycle. Это повод сказать
            # вслух, а не падать: сервис должен работать, но администратор
            # обязан узнать, что уборка не настроена.
            logger.exception(
                "не удалось выставить срок хранения, уборка не настроена",
                extra={"bucket": bucket, "days": days},
            )
            return False
        logger.info("срок хранения выставлен", extra={"bucket": bucket, "days": days})
        return True

    def put(self, bucket: str, key: str, fileobj: BinaryIO, content_type: str) -> ObjectRef:
        # Размер снимается ДО заливки: boto3 дочитывает поток и закрывает его,
        # поэтому tell() после upload_fileobj падает на закрытом файле.
        size = _stream_size(fileobj)
        self._client.upload_fileobj(fileobj, bucket, key, ExtraArgs={"ContentType": content_type})
        return ObjectRef(backend="s3", bucket=bucket, key=key, size=size, content_type=content_type)

    def get_to_path(self, ref: ObjectRef, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        self._client.download_file(ref.bucket, ref.key, str(dest))
        return dest

    def exists(self, ref: ObjectRef) -> bool:
        try:
            self._client.head_object(Bucket=ref.bucket, Key=ref.key)
        except Exception:
            return False
        return True

    def presign(self, ref: ObjectRef, ttl_s: int) -> str | None:
        return self._client.generate_presigned_url(
            "get_object", Params={"Bucket": ref.bucket, "Key": ref.key}, ExpiresIn=ttl_s
        )


class LocalStore:
    """Файловая система. Для тестов и одноузловой разработки."""

    def __init__(self, root: str) -> None:
        self._root = Path(root)

    def _path(self, bucket: str, key: str) -> Path:
        return self._root / bucket / key

    def put(self, bucket: str, key: str, fileobj: BinaryIO, content_type: str) -> ObjectRef:
        target = self._path(bucket, key)
        target.parent.mkdir(parents=True, exist_ok=True)
        fileobj.seek(0)
        with target.open("wb") as out:
            shutil.copyfileobj(fileobj, out)
        return ObjectRef(
            backend="local",
            bucket=bucket,
            key=key,
            size=target.stat().st_size,
            content_type=content_type,
        )

    def get_to_path(self, ref: ObjectRef, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self._path(ref.bucket, ref.key), dest)
        return dest

    def exists(self, ref: ObjectRef) -> bool:
        return self._path(ref.bucket, ref.key).exists()

    def presign(self, ref: ObjectRef, ttl_s: int) -> str | None:
        return None


def build_store(settings: CommonSettings) -> ObjectStore:
    if settings.storage_backend == "local":
        os.makedirs(settings.local_storage_dir, exist_ok=True)
        logger.info("хранилище: local", extra={"dir": settings.local_storage_dir})
        return LocalStore(settings.local_storage_dir)
    logger.info("хранилище: s3", extra={"endpoint": settings.s3_endpoint})
    return S3Store(settings)
