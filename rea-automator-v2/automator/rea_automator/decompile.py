"""Orquesta la descompilación MASIVA con soporte para artefactos por función,
manifiesto estructurado, caché opcional de Ghidra y reanudación (resume)."""
from __future__ import annotations

import hashlib
import json
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
    import fcntl
except ImportError:
    fcntl = None

from .adapters.bulk_native import build_ghidra_headless_argv
from .adapters.bulk_tools import KIND_COPY_DIR, KIND_SUBPROCESS, build_bulk_plan
from .config import Settings
from .ghidra_cache import (
    PROJECT_DIRNAME,
    CacheOutcome,
    default_cache_root,
    discard_project,
    entry_lock,
    evaluate_entry,
    mark_complete,
    mark_incomplete,
    resolved_versions,
)
from .routing import FAMILY_ANDROID, FAMILY_NATIVE, Route, RoutingError, route
from .runner import CommandNotFoundError, run_bounded

DECOMPILE_STATUSES = (
    "ok",
    "partial",
    "empty_output",
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
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def ok_ish(self) -> bool:
        return self.status in ("ok", "partial") and self.file_count > 0


JADX_EXIT_MEANINGS = {
    0: "terminó sin errores",
    1: "argumentos inválidos o error de proceso",
    2: "no se cargó ninguna clase que descompilar (no guarda nada)",
    3: "terminó y guardó el código, pero con errores en algunas clases o métodos",
}

_JADX_ERRORS_RE = re.compile(r"finished with errors, count:\s*(\d+)")


def _tail_text(path: Path, limit: int = 64 * 1024) -> str:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - limit))
            return handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def summarize_jadx_run(returncode: int | None, run_dir: Path, src_dir: Path) -> dict:
    errors: int | None = None
    for name in ("stdout.log", "stderr.log"):
        match = _JADX_ERRORS_RE.search(_tail_text(run_dir / name))
        if match:
            errors = int(match.group(1))
            break
    if returncode is None:
        meaning = "interrumpido por timeout"
    else:
        meaning = JADX_EXIT_MEANINGS.get(returncode, "código no documentado")
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
STALE_RUN_AGE_S = 24 * 3600


def _lock_run_dir(run_dir: Path):
    handle = open(run_dir / RUN_LOCK_NAME, "w")
    if fcntl is not None:
        fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


def cleanup_stale_runs(out_dir: Path, *, max_age_s: float = STALE_RUN_AGE_S) -> int:
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
                continue
            shutil.rmtree(candidate, ignore_errors=True)
            removed += 1
        finally:
            handle.close()
    return removed


def _create_run_dir(out_dir: Path, target_path: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    cleanup_stale_runs(out_dir)
    prefix = f"{_slug(target_path)}-"
    run_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=out_dir))
    return run_dir, _lock_run_dir(run_dir)


def _read_ghidra_index(src_dir: Path) -> tuple[int, int, int] | None:
    index_path = src_dir / "_index.tsv"
    if not index_path.is_file():
        return None
    try:
        lines = index_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    rows = lines[1:]
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
        else:
            fail_count += 1
    return ok_count, fail_count, ok_count + fail_count


def _read_ghidra_manifest(src_dir: Path) -> dict | None:
    manifest_path = src_dir / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _copy_tree_no_symlinks(src: Path, dst: Path) -> tuple[int, int]:
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
    count = 0
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(src_dir.rglob("*")):
            if file_path.is_file():
                zf.write(file_path, file_path.relative_to(src_dir))
                count += 1
    return count


# ============================ RESUME HELPERS ============================

def _find_previous_run(out_dir: Path, slug: str) -> Path | None:
    """Busca el directorio de ejecución previa más reciente para un target."""
    if not out_dir.is_dir():
        return None
    candidates = []
    for child in out_dir.iterdir():
        if not child.is_dir() or child.is_symlink():
            continue
        if not child.name.startswith(f"{slug}-"):
            continue
        manifest = child / "manifest.json"
        if manifest.is_file():
            candidates.append(child)
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _artifact_hashes_match(previous_dir: Path, record: dict) -> bool:
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, dict):
        return False
    for path_key, hash_key in (
        ("pseudocode", "pseudocode_sha256"),
        ("assembly", "assembly_sha256"),
        ("sidecar", "sidecar_sha256"),
    ):
        relative = artifacts.get(path_key)
        expected = artifacts.get(hash_key)
        if not isinstance(relative, str) or not isinstance(expected, str):
            return False
        path = previous_dir / relative
        if not path.resolve().is_relative_to(previous_dir.resolve()):
            return False
        if not path.is_file():
            return False
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return False
        if actual != expected:
            return False
    return True


def load_resume_index(
    previous_dir: Path,
    filters: dict | None = None,
) -> dict[str, dict]:
    """Devuelve stem -> record para funciones reutilizables de una corrida previa."""
    try:
        manifest = json.loads((previous_dir / "manifest.json").read_text(encoding="utf-8"))
        records = manifest.get("functions", [])
    except (OSError, json.JSONDecodeError, ValueError):
        return {}

    if not isinstance(manifest, dict) or manifest.get("status") != "complete":
        return {}
    if not isinstance(records, list):
        return {}

    include = filters.get("include") or ()
    exclude = filters.get("exclude") or ()
    if include or exclude:
        include_re = [re.compile(p) for p in include]
        exclude_re = [re.compile(p) for p in exclude]

        def name_ok(name: str) -> bool:
            if include_re and not any(p.search(name) for p in include_re):
                return False
            return not any(p.search(name) for p in exclude_re)

        records = [r for r in records if name_ok(r.get("name", ""))]

    reusable: dict[str, dict] = {}
    for record in records:
        if not isinstance(record, dict) or "address" not in record:
            continue
        if record.get("decompilation", {}).get("status") not in ("ok", "success"):
            continue
        if not _artifact_hashes_match(previous_dir, record):
            continue
        stem = record.get("artifacts", {}).get("pseudocode")
        if not stem:
            address = record.get("address", "")
            name = record.get("name", "")
            stem = _artifact_stem(address, name)
        reusable[stem] = record

    return reusable


def _artifact_stem(address: str, name: str, max_length: int = 120) -> str:
    digest = hashlib.sha256(f"{address}\0{name}".encode()).hexdigest()[:24]
    safe_address = re.sub(r"[^A-Za-z0-9._-]", "_", address)[:40] or "_"
    name_limit = max(1, max_length - len(safe_address) - len(digest) - 2)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:name_limit] or "_"
    return f"{safe_address}_{digest}_{safe_name}"


def _copy_reusable_artifacts(
    previous_dir: Path,
    new_dir: Path,
    reusable: dict[str, dict],
) -> list[str]:
    """Copia .c / .s / .json de funciones reutilizadas al nuevo directorio."""
    copied = []
    for stem, record in reusable.items():
        artifacts = record.get("artifacts", {})
        for key in ("pseudocode", "assembly", "sidecar"):
            rel = artifacts.get(key)
            if not rel:
                continue
            src = previous_dir / rel
            dst = new_dir / rel
            if src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                copied.append(stem)
                break
    return copied


# ============================ MAIN ENTRY ============================

def decompile_target(
    target: str | Path,
    settings: Settings,
    *,
    family: str | None = None,
    timeout_per_func: int = 60,
    combined: bool = False,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    resume: bool = False,
    force_export: bool = False,
    cache_enabled: bool = True,
    cache_dir: str | Path | None = None,
) -> DecompileResult:
    target_path = Path(target)
    if not target_path.exists():
        result = DecompileResult(target=str(target_path), status="not_found")
        result.unknowns.append("target_missing")
        return result

    run_dir, lock = _create_run_dir(settings.out_dir, target_path)
    try:
        return _decompile_in_run_dir(
            target_path,
            settings,
            run_dir,
            family,
            timeout_per_func=timeout_per_func,
            combined=combined,
            include=include,
            exclude=exclude,
            resume=resume,
            force_export=force_export,
            cache_enabled=cache_enabled,
            cache_dir=cache_dir,
        )
    finally:
        lock.close()


def _decompile_in_run_dir(
    target_path: Path,
    settings: Settings,
    run_dir: Path,
    family: str | None,
    *,
    timeout_per_func: int,
    combined: bool,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    resume: bool,
    force_export: bool,
    cache_enabled: bool,
    cache_dir: str | Path | None,
) -> DecompileResult:
    result = DecompileResult(target=str(target_path), status="failed")
    result.run_dir = str(run_dir)
    src_dir = run_dir / "decompiled"
    zip_path = run_dir / "decompiled.zip"
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

    # ============================ RESUME LOGIC ============================
    reusable_stems: list[str] = []
    resume_info: dict[str, Any] = {"enabled": resume, "reused": 0, "pending": 0}

    if family == FAMILY_NATIVE and resume and not force_export:
        prev_dir = _find_previous_run(settings.out_dir, _slug(target_path))
        if prev_dir is not None:
            filters = {"include": list(include), "exclude": list(exclude)}
            reusable = load_resume_index(prev_dir, filters=filters)
            if reusable:
                reusable_stems = _copy_reusable_artifacts(prev_dir, src_dir, reusable)
                resume_info["reused"] = len(reusable_stems)

    pending_exclude = tuple(exclude) + tuple(reusable_stems)

    if family == FAMILY_NATIVE:
        project_dir = run_dir / "ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)

        cache_outcome: CacheOutcome | None = None
        project_location = project_dir

        if cache_enabled:
            root = (Path(cache_dir) if cache_dir else default_cache_root()).expanduser().resolve()
            fingerprint = {
                "schema_version": 1,
                "input": {
                    "path": str(resolved_target),
                    "sha256": hashlib.sha256(resolved_target.read_bytes()).hexdigest(),
                    "size": resolved_target.stat().st_size,
                },
                "analysis": {
                    "timeout_per_func": timeout_per_func,
                    "combined": combined,
                    "include": list(include),
                    "exclude": list(exclude),
                },
            }
            key = fingerprint["sha256"] if "sha256" in fingerprint else None
            if key is None:
                from .ghidra_cache import cache_key as _cache_key
                key = _cache_key(fingerprint, fingerprint["analysis"])
            entry = root / key
            versions = resolved_versions(
                ghidra_version="unknown",
                pyghidra_version="unknown",
                exporter_version="0.2.1",
            )
            with entry_lock(entry):
                hit, reason = evaluate_entry(entry, fingerprint, versions)
                if force_export:
                    discard_project(root, entry)
                    hit, reason = False, "reanalysis forced"
                if not hit:
                    mark_incomplete(entry, fingerprint)
                cache_outcome = CacheOutcome(True, hit, entry, reason)
            if hit:
                project_location = entry / PROJECT_DIRNAME

        argv = build_ghidra_headless_argv(
            settings,
            target_path,
            src_dir,
            project_dir=project_location,
            timeout_per_func=timeout_per_func,
            combined=combined,
            include=include,
            exclude=pending_exclude,
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
            result.details["resume"] = resume_info
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
        result.details["resume"] = resume_info
        return result

    result.exit_code = raw.returncode
    result.duration_s = raw.duration_s

    if family == FAMILY_ANDROID:
        result.details["jadx"] = summarize_jadx_run(raw.returncode, run_dir, src_dir)
        if result.details["jadx"]["errors"] is not None:
            result.unknowns.append(f"jadx_errors:{result.details['jadx']['errors']}")

    if raw.timed_out:
        result.status = "timeout"
        result.unknowns.append("timeout_killed")
        file_count = _zip_dir(src_dir, zip_path)
        if file_count:
            result.file_count = file_count
            result.zip_path = str(zip_path)
            result.out_dir = str(src_dir)
        result.details["resume"] = resume_info
        return result

    file_count = _zip_dir(src_dir, zip_path)
    result.file_count = file_count
    result.out_dir = str(src_dir)

    if file_count == 0:
        result.status = "empty_output"
        result.unknowns.append("no_files_written")
        result.details["resume"] = resume_info
        return result

    result.zip_path = str(zip_path)
    result.status = "ok" if raw.returncode == 0 else "partial"
    if raw.returncode != 0:
        result.unknowns.append(f"tool_exit_code:{raw.returncode}")

    if (
        family == FAMILY_NATIVE
        and cache_enabled
        and cache_outcome is not None
        and cache_outcome.path is not None
        and not cache_outcome.hit
    ):
        analysis_summary = {
            "status": result.status,
            "file_count": file_count,
            "reused": resume_info["reused"],
        }
        mark_complete(
            cache_outcome.path,
            {
                "schema_version": 1,
                "input": {
                    "path": str(resolved_target),
                    "sha256": hashlib.sha256(resolved_target.read_bytes()).hexdigest(),
                    "size": resolved_target.stat().st_size,
                },
                "analysis": {
                    "timeout_per_func": timeout_per_func,
                    "combined": combined,
                    "include": list(include),
                    "exclude": list(exclude),
                },
            },
            resolved_versions(
                ghidra_version="unknown",
                pyghidra_version="unknown",
                exporter_version="0.2.1",
            ),
            analysis_summary,
        )

    if family == FAMILY_NATIVE:
        index = _read_ghidra_index(src_dir)
        manifest = _read_ghidra_manifest(src_dir)
        if manifest is not None:
            counts = manifest.get("counts", {})
            result.details["ghidra_manifest"] = {
                "language_id": manifest.get("language_id"),
                "compiler_id": manifest.get("compiler_id"),
                "image_base": manifest.get("image_base"),
                "counts": counts,
            }
            if isinstance(counts, dict):
                manifest_file_count = (
                    counts.get("successful", 0)
                    + counts.get("fallback", 0)
                    + counts.get("failed", 0)
                )
                if manifest_file_count:
                    result.file_count = manifest_file_count
        if index is None and manifest is None:
            if result.status == "ok":
                result.status = "partial"
            result.unknowns.append("ghidra_index_missing")
        else:
            if index is not None:
                ok_count, fail_count, total = index
                if fail_count > 0:
                    result.unknowns.append(f"ghidra_function_failures:{fail_count}/{total}")
                    if ok_count == 0:
                        result.status = "failed"
                    elif result.status == "ok":
                        result.status = "partial"

    result.details["resume"] = resume_info
    return result