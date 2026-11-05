"""Flujo completo para un usuario: entrega un .zip -> recibe UN .zip descompilado.

Pasos:
1. Extrae el .zip de entrada de forma segura (sin rutas que escapen de la carpeta,
   con tope de archivos y de bytes totales).
2. Recorre cada archivo extraído y lo enruta por forma (`routing.route`).
   - Lo que es binario reconocible (ELF, PE, Mach-O, .asar, .apk) se descompila
     con `decompile.decompile_target`.
   - Lo que no tiene firma reconocida (texto, imágenes, JSON...) se copia tal cual
     a `otros_archivos/`, para que el zip final conserve el contenido original.
3. Empaqueta todo en `<nombre>-decompilado.zip`:
     decompilado/<ruta-original-del-binario>/...   código fuente generado
     otros_archivos/...                            archivos no binarios
     report.json                                   estado por cada archivo

No ejecuta el binario objetivo: jadx, ilspycmd, asar y Ghidra headless analizan
el contenido, pero aun así conviene correr esto en un contenedor o VM aislada
cuando el zip no es de confianza (ver límites en README).
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .config import Settings, validate_positive_int
from .decompile import DecompileResult, decompile_target
from .routing import RoutingError, byte_kind, route

DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB descomprimidos

# Cuántos niveles de zip anidados se descomprimen (un zip dentro de un zip, etc.).
MAX_NESTED_ZIP_DEPTH = 2


class PipelineError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class FileEntry:
    path: str                      # ruta relativa dentro del zip de entrada
    action: str                    # "decompiled" | "partial" | "copied" | "skipped" | "ambiguous" | "failed"
    family: str | None = None
    decompile_status: str | None = None
    file_count: int = 0
    unknowns: list[str] = field(default_factory=list)
    error: Any = None
    # v2: datos medidos por la herramienta (para Android: código de salida de JADX, errores, .java).
    details: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    input: str
    status: str                    # "ok" | "partial" | "failed" | "skipped"
    output_zip: str | None = None
    decompiled_targets: int = 0
    copied_files: int = 0
    skipped_files: int = 0
    partial_targets: int = 0
    failed_targets: int = 0
    entries: list[FileEntry] = field(default_factory=list)
    error: Any = None

    def to_dict(self) -> dict:
        return asdict(self)


# ── 1. Extracción segura ─────────────────────────────────────────────────────

@dataclass
class _Budget:
    """Presupuesto acumulado de archivos/bytes para TODO el flujo (no por nivel).

    Cada extracción (zip raíz, zip anidado, o directorio de entrada) debe
    descontar de este mismo objeto compartido. Así, aunque haya muchos niveles
    de anidamiento, la suma total nunca puede superar lo que el usuario pidió.
    """
    remaining_files: int
    remaining_bytes: int

    def check_and_consume(self, n_files: int, n_bytes: int, what: str) -> None:
        if n_files > self.remaining_files:
            raise PipelineError(
                "too_many_files",
                f"{what}: {n_files} archivos superan el presupuesto restante ({self.remaining_files})",
            )
        if n_bytes > self.remaining_bytes:
            raise PipelineError(
                "too_large",
                f"{what}: {n_bytes} bytes superan el presupuesto restante ({self.remaining_bytes})",
            )
        self.remaining_files -= n_files
        self.remaining_bytes -= n_bytes


def _safe_extract(zip_path: Path, dest: Path, *, budget: _Budget) -> None:
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        total = sum(i.file_size for i in infos)
        budget.check_and_consume(len(infos), total, f"zip {zip_path.name}")
        for info in infos:
            target = (dest / info.filename).resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise PipelineError("unsafe_path", f"ruta que escapa del directorio: {info.filename}")
        zf.extractall(dest)
        # info.file_size es metadata declarada por el propio zip; no es imposible
        # que el contenido real descomprimido no coincida. Verificamos contra lo
        # que de verdad quedó en disco para no confiar ciegamente en el header.
        real_total = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
        if real_total > total:
            raise PipelineError(
                "too_large",
                f"el contenido real descomprimido ({real_total} bytes) excede lo declarado ({total})",
            )


def _is_nested_zip_candidate(p: Path) -> bool:
    """Un archivo cuya extensión es .zip en cualquier capitalización (no .apk)."""
    return p.is_file() and not p.is_symlink() and p.suffix.lower() == ".zip"


def _extract_nested_zips(root: Path, budget: _Budget, depth: int = 0) -> list[FileEntry]:
    """Descomprime zips anidados que NO sean .apk (los .apk se descompilan como tales).

    Reglas, aplicadas a cada archivo con extensión .zip (sin distinguir mayúsculas):
    - Si no es un zip válido -> acción "failed", código "nested_zip_invalid".
      Un zip corrupto es un fallo real, no un archivo más.
    - Si ya se alcanzó MAX_NESTED_ZIP_DEPTH -> acción "skipped", código
      "nested_zip_depth_limit". El límite se conserva; lo que queda sin expandir
      se registra para que el informe no declare éxito.
    - Si el destino de extracción ya existe -> "skipped", "nested_zip_destination_exists".
    - Si supera el presupuesto o tiene rutas inseguras -> "skipped" con el código
      del PipelineError (política, no error técnico).
    - Si el zip se abre pero falla al extraer -> "failed", "nested_zip_extract_error".

    Todo zip que no se expande queda como FileEntry; `_process_files` lo excluye
    de un segundo enrutamiento (ver skip_paths) y `_assemble` conserva el original
    en otros_archivos/ si corresponde.
    """
    problems: list[FileEntry] = []
    found = False
    for p in sorted(root.rglob("*")):
        if not _is_nested_zip_candidate(p):
            continue
        rel = _relpath(p, root)

        if not zipfile.is_zipfile(p):
            problems.append(FileEntry(
                path=rel, action="failed",
                error={
                    "code": "nested_zip_invalid",
                    "message": f"{p.name} tiene extensión .zip pero su contenido no es un zip válido",
                },
            ))
            continue

        if depth >= MAX_NESTED_ZIP_DEPTH:
            problems.append(FileEntry(
                path=rel, action="skipped",
                error={
                    "code": "nested_zip_depth_limit",
                    "message": f"zip anidado más allá de {MAX_NESTED_ZIP_DEPTH} niveles; no se extrajo",
                },
            ))
            continue

        dest = p.with_suffix("")
        if dest.exists():
            # No se pisa contenido existente, pero el zip tampoco se analiza:
            # que quede registrado, no silenciado.
            problems.append(FileEntry(
                path=rel, action="skipped",
                error={
                    "code": "nested_zip_destination_exists",
                    "message": f"ya existe {dest.name}/ junto a {p.name}; el zip anidado no se analizó",
                },
            ))
            continue
        try:
            _safe_extract(p, dest, budget=budget)
        except PipelineError as err:
            shutil.rmtree(dest, ignore_errors=True)
            problems.append(FileEntry(
                path=rel, action="skipped",
                error={"code": err.code, "message": err.message},
            ))
            continue
        except (zipfile.BadZipFile, OSError) as exc:
            shutil.rmtree(dest, ignore_errors=True)
            problems.append(FileEntry(
                path=rel, action="failed",
                error={"code": "nested_zip_extract_error", "message": str(exc)},
            ))
            continue
        p.unlink()
        found = True
    if found:
        problems.extend(_extract_nested_zips(root, budget, depth + 1))
    return problems


def _walk_no_symlinks(root: Path) -> tuple[list[Path], list[Path]]:
    """Recorre `root` SIN seguir enlaces simbólicos.

    A diferencia de `Path.rglob`/`shutil.copytree` (que siguen symlinks por
    defecto), aquí cualquier entrada que sea un enlace simbólico -- apunte a
    un archivo o a un directorio -- se excluye antes de decidir si es
    "archivo" o de descender en ella. Así un symlink dentro del directorio de
    entrada no puede traer contenido de fuera de ese directorio.

    El propio `root` también se valida: si la raíz que se nos pide recorrer
    es, ella misma, un enlace simbólico, se rechaza por completo en vez de
    seguirla -- no hay "contenido interno" que recorrer de forma segura si
    la raíz entera es un symlink a otro lado.
    """
    if root.is_symlink():
        raise PipelineError(
            "symlink_rejected",
            f"la entrada es un enlace simbólico, no un directorio real: {root}",
        )
    files: list[Path] = []
    skipped: list[Path] = []
    stack = [root]
    while stack:
        d = stack.pop()
        for entry in sorted(d.iterdir()):
            if entry.is_symlink():
                skipped.append(entry)
                continue
            if entry.is_dir():
                stack.append(entry)
            elif entry.is_file():
                files.append(entry)
    return files, skipped


def _safe_copy_tree(src: Path, dest: Path, budget: _Budget) -> list[Path]:
    """Copia un directorio de entrada validando contra el mismo presupuesto
    acumulado que usan las rutas de zip, en vez de copiar sin ningún chequeo.

    Política explícita para enlaces simbólicos: se excluyen de la entrada,
    nunca se siguen -- incluida la propia raíz (ver `_walk_no_symlinks`).
    Devuelve las rutas (relativas a `src`) de los symlinks internos
    excluidos, para que el llamador los deje registrados en el reporte.
    """
    files, skipped = _walk_no_symlinks(src)
    total = sum(f.stat().st_size for f in files)
    budget.check_and_consume(len(files), total, f"directorio {src.name}")
    for f in files:
        rel = f.relative_to(src)
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, out)
    return [p.relative_to(src) for p in skipped]


# ── 2. Enrutado y descompilación por archivo ─────────────────────────────────

def _relpath(p: Path, root: Path) -> str:
    return p.relative_to(root).as_posix()


def _is_zip_by_content(p: Path) -> bool:
    """True si los bytes de `p` son una cabecera de zip, sin mirar el nombre."""
    try:
        return byte_kind(p) == "zip"
    except OSError:
        return False


def _process_files(extracted: Path, work: Path, settings: Settings, entries: list[FileEntry],
                   decompiled_results: list[tuple[str, DecompileResult]],
                   failed_runs: list[tuple[str, Path]],
                   skip_paths: frozenset[str] = frozenset()) -> None:
    file_settings = dataclasses.replace(settings, out_dir=work / "runs")
    for p in sorted(extracted.rglob("*")):
        if not p.is_file():
            continue
        rel = _relpath(p, extracted)
        if rel in skip_paths:
            # Ya tiene una FileEntry propia (p. ej. un zip anidado que no se
            # pudo expandir): no volver a enrutarlo/clasificarlo acá, o
            # terminaríamos con dos entradas distintas para la misma ruta.
            continue
        try:
            chosen = route(p)
        except RoutingError as err:
            if err.code == "ambiguous":
                entries.append(FileEntry(rel, "ambiguous", error={"code": err.code, "message": err.message}))
            elif err.code == "unknown_format" and _is_zip_by_content(p):
                # Es un zip aunque no tenga extensión .zip (p. ej. datos.bin). No se
                # expande: las extensiones deciden qué es un contenedor. Pero su
                # contenido no se analizó, así que queda registrado como skipped
                # y el estado global no puede ser "ok".
                entries.append(FileEntry(
                    rel, "skipped",
                    error={
                        "code": "zip_by_content_not_expanded",
                        "message": f"{p.name} es un zip sin extensión .zip; no se expandió",
                    },
                ))
            else:
                # Texto, imágenes, datos, etc.: no es binario reconocible, se copia tal cual.
                entries.append(FileEntry(rel, "copied", error={"code": err.code}))
            continue

        res = decompile_target(p, file_settings, family=chosen.family)
        has_artifacts = bool(
            res.out_dir
            and res.file_count > 0
            and Path(res.out_dir).is_dir()
        )
        if res.status == "ok" and has_artifacts:
            action = "decompiled"
        elif has_artifacts and res.status in ("partial", "timeout"):
            # Un resultado incompleto sigue siendo útil, pero nunca debe reportarse
            # como un éxito completo.
            action = "partial"
        else:
            action = "failed"

        entry = FileEntry(
            path=rel,
            action=action,
            family=res.family,
            decompile_status=res.status,
            file_count=res.file_count,
            unknowns=list(res.unknowns),
            error=res.error,
            details=dict(res.details),
        )
        entries.append(entry)
        if has_artifacts and res.out_dir:
            decompiled_results.append((rel, res))
        if action in ("partial", "failed") and res.status != "not_found" and res.run_dir:
            # Usamos el run_dir que decompile.py realmente creó (no uno
            # reconstruido adivinando su esquema de nombres): ahora es un
            # directorio único por ejecución, no una ruta determinista.
            failed_runs.append((rel, Path(res.run_dir)))


# ── 3. Empaquetado final ─────────────────────────────────────────────────────

def _copy_tree(src: Path, dst: Path) -> int:
    count = 0
    for f in src.rglob("*"):
        if f.is_file():
            out = dst / f.relative_to(src)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, out)
            count += 1
    return count


def _assemble(extracted: Path, staging: Path, entries: list[FileEntry],
              decompiled_results: list[tuple[str, DecompileResult]],
              failed_runs: list[tuple[str, Path]], keep_originals: bool) -> None:
    for rel, res in decompiled_results:
        _copy_tree(Path(res.out_dir), staging / "decompilado" / rel)

    # Logs de las herramientas que fallaron: sin ellos no se puede diagnosticar.
    for rel, run_dir in failed_runs:
        for name in ("stdout.log", "stderr.log"):
            log = run_dir / name
            if log.is_file() and log.stat().st_size > 0:
                dst = staging / "logs" / rel / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(log, dst)

    if keep_originals:
        for e in entries:
            # "failed" con decompile_status=None identifica específicamente un
            # zip anidado que no se pudo expandir por un error real (zip
            # corrupto/E-S) -- ver _extract_nested_zips. A diferencia de un
            # target que sí se intentó descompilar y falló (que siempre trae
            # decompile_status seteado), acá nunca hubo intento de descompilar
            # nada: conservar el zip crudo es lo único útil para diagnosticar.
            is_failed_nested_zip = e.action == "failed" and e.decompile_status is None
            if e.action in ("copied", "ambiguous", "skipped") or is_failed_nested_zip:
                src = extracted / e.path
                if not src.is_file():
                    continue
                dst = staging / "otros_archivos" / e.path
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)


def _summarize_entries(entries: list[FileEntry]) -> dict[str, int | str]:
    """Calcula un estado global conservador y conteos reproducibles.

    `ok` solo significa que todos los archivos terminaron sin ambigüedad,
    fallo ni resultado parcial. Los desconocidos copiados son un resultado válido.
    `skipped` significa que no hubo ningún trabajo exitoso ni fallido, por ejemplo
    una entrada vacía o archivos que el enrutador no pudo resolver.
    """
    counts = {
        "decompiled_targets": sum(e.action == "decompiled" for e in entries),
        "partial_targets": sum(
            e.action == "partial" or e.decompile_status == "partial" for e in entries
        ),
        "copied_files": sum(e.action == "copied" for e in entries),
        "skipped_files": sum(e.action in ("skipped", "ambiguous") for e in entries),
        "failed_targets": sum(e.action == "failed" for e in entries),
    }

    successful = counts["decompiled_targets"] + counts["partial_targets"] + counts["copied_files"]
    had_issues = (
        counts["partial_targets"] > 0
        or counts["skipped_files"] > 0
        or counts["failed_targets"] > 0
    )
    if not entries or (successful == 0 and counts["failed_targets"] == 0):
        status = "skipped"
    elif counts["failed_targets"] > 0 and successful == 0:
        status = "failed"
    elif had_issues:
        status = "partial"
    else:
        status = "ok"

    return {"status": status, **counts}


def _write_zip(src_dir: Path, zip_path: Path) -> int:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(src_dir.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(src_dir))
                count += 1
    return count


def run_pipeline(
    input_path: str | Path,
    settings: Settings,
    *,
    out_dir: str | Path | None = None,
    keep_originals: bool = True,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> PipelineResult:
    # Se validan antes de tocar el disco: un tope inválido no debe producir
    # un directorio temporal ni un zip a medias.
    max_files = validate_positive_int(max_files, "max_files")
    max_bytes = validate_positive_int(max_bytes, "max_bytes")

    src = Path(input_path)
    out_root = Path(out_dir) if out_dir else settings.out_dir
    result = PipelineResult(input=str(src), status="failed")

    if not src.exists():
        result.error = {"code": "not_found", "message": f"no existe: {src}"}
        return result

    work = Path(tempfile.mkdtemp(prefix="automator-"))
    try:
        extracted = work / "extracted"
        extracted.mkdir()

        # Presupuesto único y compartido para TODO el flujo: entrada inicial
        # (zip o directorio) + cada zip anidado descuentan del mismo contador,
        # así que no hay forma de superar max_files/max_bytes acumulando niveles.
        budget = _Budget(remaining_files=max_files, remaining_bytes=max_bytes)
        rejected_symlinks: list[Path] = []

        # Misma política para todo tipo de entrada: nunca seguir un symlink
        # como si fuera el objeto real. Para un directorio, esto ya lo valida
        # `_walk_no_symlinks`, pero para un ZIP o un archivo suelto no hay
        # recorrido interno que haga ese chequeo -- se valida acá, una sola
        # vez, para las tres ramas por igual.
        if src.is_symlink():
            result.error = {
                "code": "symlink_rejected",
                "message": f"la entrada es un enlace simbólico, no se sigue: {src}",
            }
            return result

        try:
            if src.is_dir():
                rejected_symlinks = _safe_copy_tree(src, extracted, budget)
            elif src.suffix.lower() == ".apk" and zipfile.is_zipfile(src):
                # Un .apk ES un zip, pero es un objetivo Android, no un contenedor
                # de archivos. Si se extrajera como zip, jadx nunca se ejecutaría y
                # el pipeline reportaría "ok" con todo copiado sin descompilar.
                # Se trata como archivo único para que decompile lo enrute a Android.
                size = src.stat().st_size
                budget.check_and_consume(1, size, f"archivo {src.name}")
                shutil.copy2(src, extracted / src.name)
            elif zipfile.is_zipfile(src):
                _safe_extract(src, extracted, budget=budget)
            elif src.suffix.lower() == ".zip":
                # La extensión dice .zip pero el contenido no lo es (cabecera
                # inválida, archivo truncado, texto plano renombrado, etc.).
                # No se trata como "archivo suelto" -- eso silenciaría el
                # problema real tratándolo como éxito parcial. Se detiene acá
                # con un error explícito.
                raise PipelineError(
                    "bad_zip",
                    f"la extensión es .zip pero el contenido no es un zip válido: {src.name}",
                )
            else:
                # Un archivo suelto (no zip): se procesa como único elemento.
                size = src.stat().st_size
                budget.check_and_consume(1, size, f"archivo {src.name}")
                shutil.copy2(src, extracted / src.name)
        except PipelineError as err:
            result.error = {"code": err.code, "message": err.message}
            return result
        except zipfile.BadZipFile as exc:
            result.error = {"code": "bad_zip", "message": str(exc)}
            return result

        nested_zip_problems = _extract_nested_zips(extracted, budget)

        entries: list[FileEntry] = []
        for rel in rejected_symlinks:
            entries.append(FileEntry(
                rel.as_posix(), "skipped",
                error={"code": "symlink_rejected", "message": "enlace simbólico excluido de la entrada"},
            ))
        entries.extend(nested_zip_problems)
        skip_paths = frozenset(e.path for e in nested_zip_problems)
        decompiled_results: list[tuple[str, DecompileResult]] = []
        failed_runs: list[tuple[str, Path]] = []
        _process_files(extracted, work, settings, entries, decompiled_results, failed_runs, skip_paths)

        staging = work / "staging"
        staging.mkdir()
        _assemble(extracted, staging, entries, decompiled_results, failed_runs, keep_originals)

        summary = _summarize_entries(entries)
        report = {
            "schema_version": 1,
            "input": str(src),
            "status": summary["status"],
            "summary": {k: v for k, v in summary.items() if k != "status"},
            "entries": [asdict(e) for e in entries],
        }
        (staging / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

        stem = src.stem if src.suffix else src.name
        output_zip = out_root / f"{stem}-decompilado.zip"
        _write_zip(staging, output_zip)

        result.entries = entries
        result.output_zip = str(output_zip)
        result.status = str(summary["status"])
        result.decompiled_targets = int(summary["decompiled_targets"])
        result.partial_targets = int(summary["partial_targets"])
        result.copied_files = int(summary["copied_files"])
        result.skipped_files = int(summary["skipped_files"])
        result.failed_targets = int(summary["failed_targets"])
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
