"""Único punto del automatizador que lanza procesos externos.

Garantías (lo que el runner promete y lo que NO promete):
- stdout y stderr se escriben a archivos con tope de bytes; no se cargan en memoria.
  Al pasar el tope se descarta el resto y se marca `truncated`.
- Timeout: se mata el grupo de procesos (POSIX) para no dejar hijos huérfanos.
- No es un sandbox del sistema operativo. El aislamiento (Docker, usuario sin
  privilegios, red deshabilitada) lo debe aportar quien ejecuta este runner.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path


class CommandNotFoundError(Exception):
    """El ejecutable de argv[0] no existe o no se pudo lanzar (ENOENT/EACCES/etc.).

    Separado de los fallos que `rea` (u otra herramienta) reporta por sí misma:
    aquí el proceso nunca llegó a arrancar.
    """

    def __init__(self, argv: tuple[str, ...], original: OSError):
        self.argv = argv
        self.original = original
        super().__init__(f"no se pudo ejecutar {argv[0]!r}: {original}")


@dataclass(frozen=True)
class RawRun:
    argv: tuple[str, ...]
    returncode: int | None  # None si hubo timeout
    timed_out: bool
    stdout_path: Path
    stderr_path: Path
    stdout_truncated: bool
    stderr_truncated: bool
    duration_s: float


def _pump(stream, dest: Path, limit: int, flag: list[bool]) -> None:
    """Copia el stream al archivo hasta `limit` bytes; luego drena y descarta."""
    written = 0
    with open(dest, "wb") as out:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if written < limit:
                take = chunk[: limit - written]
                out.write(take)
                written += len(take)
                if len(take) < len(chunk):
                    flag[0] = True
            else:
                flag[0] = True
    stream.close()


def run_bounded(
    argv: tuple[str, ...] | list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    timeout_s: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> RawRun:
    argv = tuple(argv)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True

    start = time.monotonic()
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv lo construye el adaptador, sin shell
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **kwargs,
        )
    except OSError as exc:
        # El comando no existe, no es ejecutable, o el SO no pudo lanzarlo.
        # Esto NO es un fallo reportado por la herramienta externa: nunca arrancó.
        raise CommandNotFoundError(argv, exc) from exc
    out_flag = [False]
    err_flag = [False]
    t_out = threading.Thread(target=_pump, args=(proc.stdout, stdout_path, max_stdout_bytes, out_flag))
    t_err = threading.Thread(target=_pump, args=(proc.stderr, stderr_path, max_stderr_bytes, err_flag))
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill(proc)
        proc.wait()
    t_out.join()
    t_err.join()

    return RawRun(
        argv=argv,
        returncode=None if timed_out else proc.returncode,
        timed_out=timed_out,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_truncated=out_flag[0],
        stderr_truncated=err_flag[0],
        duration_s=round(time.monotonic() - start, 3),
    )


def _kill(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass
