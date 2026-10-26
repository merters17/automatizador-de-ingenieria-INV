"""Orquesta la descompilación MASIVA: rutea -> ejecuta la herramienta de volcado
completo correspondiente -> empaqueta todo el resultado en un .zip.

Esto es deliberadamente distinto de `analyzer.analyze_target`:
- `analyze_target` invoca `rea` y guarda evidencia dirigida (JSON) de lo que
  `rea` decidió investigar.
- `decompile_target` invoca la herramienta subyacente (jadx, ilspycmd, asar,
  Ghidra headless) en su modo de volcado COMPLETO y entrega un .zip con todo
  el árbol de código fuente resultante.

No es un sustituto del automatizador original: es un segundo modo, para cuando
lo que se necesita es "paso un archivo, me devuelve todo descompilado en un zip".
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import fcntl  # POSIX. En Windows no existe: ahí la limpieza queda desactivada.
except ImportError:  # pragma: no cover - depende de la plataforma
    fcntl = None  # type: ignore[assignment]

from .adapters.bulk_native import build_ghidra_headless_argv
from .adapters.bulk_tools import KIND_COPY_DIR, KIND_SUBPROCESS, build_bulk_plan
from .config import Settings
from .routing import FAMILY_ANDROID, FAMILY_NATIVE, Route, RoutingError, route
from .runner import CommandNotFoundError, run_bounded

DECOMPILE_STATUSES = (
    "ok",                # la herramienta terminó y se generó el zip
    "partial",           # la herramienta terminó con código distinto de 0 pero sí escribió salida
    "empty_output",      # la herramienta terminó "bien" pero no escribió ningún archivo
    "timeout",
    "command_not_found",
    "routing_error",
    "not_found",
    "unsupported_family",
)


@dataclass
class DecompileResult:
    target: str
    status: str
    family: str | None = None
    argv: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_s: float | None = None
    file_count: int = 0
    zip_path: str | None = None
    out_dir: str | None = None
    run_dir: str | None = None
    error: Any = None
    unknowns: list[str] = field(default_factory=list)
    # v2: datos medidos de la ejecución (hoy solo `details["jadx"]` para la familia Android).
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# Códigos de salida de `jadx` según JadxCLI.java de la versión 1.5.6 (jadx-cli):
#   0 -> `LOG.info("done")`
#   1 -> argumentos inválidos (JadxArgsValidateException) o excepción no controlada
#   2 -> `checkForErrors` devolvió true: con --no-res y sin clases que descompilar ("Load failed!")
#   3 -> terminó de guardar y `errorsCount != 0` ("finished with errors, count: N")
JADX_EXIT_MEANINGS = {
    0: "terminó sin errores",
    1: "argumentos inválidos o error de proceso",
    2: "no se cargó ninguna clase que descompilar (no guarda nada)",
    3: "terminó y guardó el código, pero con errores en algunas clases o métodos",
}
_JADX_ERRORS_RE = re.compile(r"finished with errors, count:\s*(\d+)")


def _tail_text(path: Path, limit: int = 64 * 1024) -> str:
    """Últimos `limit` bytes de un log como texto (el resumen de JADX está al final)."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - limit))
            return handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def summarize_jadx_run(returncode: int | None, run_dir: Path, src_dir: Path) -> dict:
    """Interpreta lo que JADX dejó: código de salida, nº de errores que informó y `.java` en disco."""
    errors: int | None = None
    for name in ("stdout.log", "stderr.log"):
        match = _JADX_ERRORS_RE.search(_tail_text(run_dir / name))
        if match:
            errors = int(match.group(1))
            break
    if returncode is None:
        meaning = "interrumpido por timeout"
    else:
        meaning = JADX_EXIT_MEANINGS.get(returncode, "código no documentado en JadxCLI 1.5.6")
    return {
        "exit_code": returncode,
        "exit_meaning": meaning,
        "errors": errors,
        "java_files": sum(1 for _ in src_dir.rglob("*.java")),
    }


def _slug(path: Path) -> str:
    digest = hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()[:10]
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", path.name)[:80] or "target"
    return f"{safe}-{digest}"


RUN_LOCK_NAME = ".lock"
# Una ejecución solo puede borrarse si lleva más de este tiempo sin actividad Y
# ningún proceso tiene su bloqueo. El tiempo protege la ventana entre mkdtemp y
# la toma del bloqueo; el bloqueo protege a las ejecuciones activas.
STALE_RUN_AGE_S = 24 * 3600


def _lock_run_dir(run_dir: Path):
    """Crea `.lock` en la carpeta de ejecución y toma un bloqueo exclusivo.

    El bloqueo dura mientras el handle esté abierto (o hasta que el proceso
    termine). Un proceso que intente limpiar esta carpeta no podrá tomarlo.
    """
    handle = open(run_dir / RUN_LOCK_NAME, "w")
    if fcntl is not None:
        fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


def cleanup_stale_runs(out_dir: Path, *, max_age_s: float = STALE_RUN_AGE_S) -> int:
    """Borra ejecuciones antiguas que ya no están en uso. Devuelve cuántas borró.

    Reglas, todas necesarias para borrar una carpeta:
    - Es un directorio real (no un enlace) y contiene `.lock`: si no tiene ese
      archivo no la creó este módulo, así que no se toca nunca.
    - Su última modificación es anterior a `max_age_s`.
    - Se puede tomar su bloqueo sin esperar. Si otro proceso la tiene en uso,
      el intento falla con BlockingIOError y se deja intacta.

    Sin `fcntl` (Windows) no hay forma de saber si una ejecución está activa,
    así que no se borra nada.
    """
    if fcntl is None or not out_dir.is_dir():
        return 0
    cutoff = time.time() - max_age_s
    removed = 0
    for candidate in out_dir.iterdir():
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        lock_path = candidate / RUN_LOCK_NAME
        if not lock_path.is_file():
            continue
        try:
            if candidate.stat().st_mtime > cutoff:
                continue
            handle = open(lock_path, "r+")
        except OSError:
            continue
        try:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue  # en uso por otro proceso: no tocar
            shutil.rmtree(candidate, ignore_errors=True)
            removed += 1
        finally:
            handle.close()
    return removed


def _create_run_dir(out_dir: Path, target_path: Path):
    """Crea un directorio NUEVO y exclusivo para esta ejecución y lo bloquea.

    Devuelve (run_dir, handle_del_bloqueo). Quien llame debe cerrar el handle
    al terminar. La limpieza no toca nada que no haya creado este módulo, ni
    ejecuciones activas, así que dos ejecuciones sobre el mismo objetivo ya no
    pueden borrarse mutuamente.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cleanup_stale_runs(out_dir)
    prefix = f"{_slug(target_path)}-"
    run_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=out_dir))
    return run_dir, _lock_run_dir(run_dir)


def _read_ghidra_index(src_dir: Path) -> tuple[int, int, int] | None:
    """Lee `_index.tsv` (escrito por ghidra_decompile_all.py) y cuenta cuántas
    funciones terminaron "ok" contra el total. Devuelve (ok, fallidas, total),
    o None si el índice no existe o no se puede interpretar: en ese caso no
    hay forma de confirmar éxito y el llamador debe tratarlo con cautela, no
    como un "ok" implícito.

    No se confía en el código de salida del subproceso de Ghidra para esto:
    el script puede terminar con código 0 (el host --analyzeHeadless-- no se
    cayó) aun cuando varias o todas las funciones individuales fallaron.
    """
    index_path = src_dir / "_index.tsv"
    if not index_path.is_file():
        return None
    try:
        lines = index_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    rows = lines[1:]  # saltar encabezado "address\tname\tstatus\tfile"
    ok_count = 0
    fail_count = 0
    for row in rows:
        if not row.strip():
            continue
        fields = row.split("\t")
        if len(fields) < 3:
            continue
        status = fields[2]
        if status == "ok":
            ok_count += 1
        else:  # "failed" o "exception"
            fail_count += 1
    return ok_count, fail_count, ok_count + fail_count


def _copy_tree_no_symlinks(src: Path, dst: Path) -> tuple[int, int]:
    """Copia `src` a `dst` sin seguir enlaces simbólicos.

    `shutil.copytree` sigue symlinks por defecto, así que un enlace dentro de la
    carpeta podía meter en el zip de salida contenido de fuera de ella. Aquí los
    enlaces (a archivo o a directorio) se omiten, igual que en el pipeline.
    Devuelve (archivos copiados, enlaces omitidos).
    """
    copied = 0
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel_dir = Path(dirpath).relative_to(src)
        (dst / rel_dir).mkdir(parents=True, exist_ok=True)
        skipped += sum(1 for d in dirnames if (Path(dirpath) / d).is_symlink())
        for name in filenames:
            origin = Path(dirpath) / name
            if origin.is_symlink():
                skipped += 1
                continue
            shutil.copy2(origin, dst / rel_dir / name)
            copied += 1
    return copied, skipped


def _zip_dir(src_dir: Path, zip_path: Path) -> int:
    """Comprime src_dir completo en zip_path. Devuelve cuántos archivos entraron."""
    count = 0
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(src_dir.rglob("*")):
            if file_path.is_file():
                zf.write(file_path, file_path.relative_to(src_dir))
                count += 1
    return count


def decompile_target(
    target: str | Path,
    settings: Settings,
    *,
    family: str | None = None,
) -> DecompileResult:
    target_path = Path(target)

    if not target_path.exists():
        result = DecompileResult(target=str(target_path), status="not_found")
        result.unknowns.append("target_missing")
        return result

    run_dir, lock = _create_run_dir(settings.out_dir, target_path)
    try:
        return _decompile_in_run_dir(target_path, settings, run_dir, family)
    finally:
        lock.close()


def _decompile_in_run_dir(
    target_path: Path,
    settings: Settings,
    run_dir: Path,
    family: str | None,
) -> DecompileResult:
    result = DecompileResult(target=str(target_path), status="failed")

    # Directorio de trabajo único para ESTA ejecución (creado y bloqueado por
    # _create_run_dir): nunca existió antes, así que no puede traer contenido
    # de una corrida anterior.
    result.run_dir = str(run_dir)
    src_dir = run_dir / "decompiled"
    zip_path = run_dir / "decompiled.zip"

    # Con un run_dir recién creado (nombre aleatorio) esto ya no puede pasar en
    # la práctica, pero se mantiene como resguardo barato: si el target fuera
    # el propio run_dir o algo dentro de él, el copy_dir de más abajo podría
    # entrar en recursión sobre su propio destino.
    resolved_target = target_path.resolve()
    resolved_run_dir = run_dir.resolve()
    try:
        resolved_target.relative_to(resolved_run_dir)
    except ValueError:
        pass
    else:
        result.status = "failed"
        result.error = {
            "code": "output_target_collision",
            "message": "el objetivo está dentro del directorio de salida de esta ejecución",
        }
        result.unknowns.append("output_target_collision")
        return result

    if family is None:
        try:
            chosen = route(target_path)
        except RoutingError as err:
            result.status = "routing_error"
            result.error = {"code": err.code, "message": err.message}
            result.unknowns.append(f"routing:{err.code}")
            return result
        family = chosen.family
    result.family = family

    src_dir.mkdir(parents=True, exist_ok=True)

    if family == FAMILY_NATIVE:
        project_dir = run_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)
        argv = build_ghidra_headless_argv(
            settings, target_path, src_dir, project_dir=project_dir
        )
    else:
        plan = build_bulk_plan(settings, family, target_path, src_dir)
        if plan.kind == KIND_COPY_DIR:
            _, links_skipped = _copy_tree_no_symlinks(target_path, src_dir)
            if links_skipped:
                result.unknowns.append(f"symlinks_excluded:{links_skipped}")
            file_count = _zip_dir(src_dir, zip_path)
            result.status = "ok" if file_count > 0 else "empty_output"
            result.file_count = file_count
            result.zip_path = str(zip_path) if file_count else None
            result.out_dir = str(src_dir)
            return result
        argv = plan.argv

    result.argv = list(argv)

    try:
        raw = run_bounded(
            argv,
            stdout_path=run_dir / "stdout.log",
            stderr_path=run_dir / "stderr.log",
            timeout_s=settings.timeout_s,
            max_stdout_bytes=settings.max_stdout_bytes,
            max_stderr_bytes=settings.max_stderr_bytes,
        )
    except CommandNotFoundError as exc:
        result.status = "command_not_found"
        result.error = {"argv0": argv[0], "message": str(exc.original)}
        if family == FAMILY_ANDROID:
            result.error["hint"] = "JADX no está preparado en esa ruta. Ejecuta: python -m rea_automator setup-jadx"
        result.unknowns.append("command_not_found")
        return result

    result.exit_code = raw.returncode
    result.duration_s = raw.duration_s

    if family == FAMILY_ANDROID:
        # Lo medido de esta ejecución de JADX (no se deduce: sale del código de salida, del
        # log y de los archivos que quedaron en disco). Si JADX informó errores, queda
        # también como "desconocido" para que el estado `partial` tenga una razón visible.
        result.details["jadx"] = summarize_jadx_run(raw.returncode, run_dir, src_dir)
        if result.details["jadx"]["errors"] is not None:
            result.unknowns.append(f"jadx_errors:{result.details['jadx']['errors']}")

    if raw.timed_out:
        result.status = "timeout"
        result.unknowns.append("timeout_killed")
        # Empaquetar lo que se alcanzó a descompilar antes del timeout, si algo hay.
        file_count = _zip_dir(src_dir, zip_path)
        if file_count:
            result.file_count = file_count
            result.zip_path = str(zip_path)
            result.out_dir = str(src_dir)
        return result

    file_count = _zip_dir(src_dir, zip_path)
    result.file_count = file_count
    result.out_dir = str(src_dir)

    if file_count == 0:
        result.status = "empty_output"
        result.unknowns.append("no_files_written")
        return result

    result.zip_path = str(zip_path)
    result.status = "ok" if raw.returncode == 0 else "partial"
    if raw.returncode != 0:
        result.unknowns.append(f"tool_exit_code:{raw.returncode}")

    if family == FAMILY_NATIVE:
        # Ghidra puede terminar con código 0 aunque varias (o todas) las
        # funciones individuales hayan fallado al descompilar: la presencia
        # de archivos .c (uno por función, incluso las fallidas, con un
        # comentario de error adentro) no es evidencia de éxito. Se analiza
        # _index.tsv -- el resultado real por función -- para corregir el
        # estado en vez de confiar solo en el código de salida del proceso.
        index = _read_ghidra_index(src_dir)
        if index is None:
            # No se pudo confirmar nada: no declarar "ok" a ciegas.
            if result.status == "ok":
                result.status = "partial"
            result.unknowns.append("ghidra_index_missing")
        else:
            ok_count, fail_count, total = index
            if fail_count > 0:
                result.unknowns.append(f"ghidra_function_failures:{fail_count}/{total}")
                if ok_count == 0:
                    result.status = "failed"
                elif result.status == "ok":
                    result.status = "partial"
    return result
