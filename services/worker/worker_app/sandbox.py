"""Единственный разрешённый способ запускать внешние утилиты над файлом.

Прямой subprocess.run в стадиях запрещён (см. CLAUDE.md): здесь собраны
таймаут, rlimits и закрытие дескрипторов.
"""

from __future__ import annotations

import logging
import resource
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CPU_S = 30
DEFAULT_AS_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_FSIZE_BYTES = 512 * 1024 * 1024


@dataclass(slots=True)
class SandboxResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _apply_limits(cpu_s: int, address_space: int, file_size: int) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_sandboxed(
    argv: list[str],
    *,
    timeout_s: float,
    cwd: Path | None = None,
    cpu_s: int = DEFAULT_CPU_S,
    address_space: int = DEFAULT_AS_BYTES,
    file_size: int = DEFAULT_FSIZE_BYTES,
) -> SandboxResult:
    """Блокирующий вызов — вызывать только через asyncio.to_thread."""
    try:
        completed = subprocess.run(  # noqa: S603 - argv собирается кодом, не пользователем
            argv,
            capture_output=True,
            timeout=timeout_s,
            cwd=cwd,
            close_fds=True,
            check=False,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"},
            preexec_fn=lambda: _apply_limits(cpu_s, address_space, file_size),
        )
    except subprocess.TimeoutExpired:
        logger.warning("внешняя утилита не уложилась в таймаут", extra={"tool": argv[0]})
        return SandboxResult(returncode=-1, stdout=b"", stderr=b"timeout", timed_out=True)
    except FileNotFoundError:
        logger.warning("утилита не установлена", extra={"tool": argv[0]})
        return SandboxResult(returncode=-2, stdout=b"", stderr=b"not found")

    return SandboxResult(
        returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr
    )
