"""Потоковое хэширование: sha256 считается во время приёма, а не после."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Iterator


class StreamHasher:
    """Накапливает sha256 и размер по мере прохождения чанков."""

    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self.size = 0

    def update(self, chunk: bytes) -> None:
        self._digest.update(chunk)
        self.size += len(chunk)

    @property
    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short(sha256: str) -> str:
    """Усечённый хэш для логов — полный в общие логи не пишем."""
    return sha256[:12]


async def ahash_stream(chunks: AsyncIterator[bytes], sink: object | None = None) -> StreamHasher:
    hasher = StreamHasher()
    write = getattr(sink, "write", None)
    async for chunk in chunks:
        hasher.update(chunk)
        if write is not None:
            write(chunk)
    return hasher


def hash_stream(chunks: Iterator[bytes], sink: object | None = None) -> StreamHasher:
    hasher = StreamHasher()
    write = getattr(sink, "write", None)
    for chunk in chunks:
        hasher.update(chunk)
        if write is not None:
            write(chunk)
    return hasher
