"""Caché de análisis Ghidra indexado por huella dactilar del binario y solicitud.
Adaptado de ghidra-decomp-main/src/ghidra_decomp/cache.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .ghidra_artifacts import (
    atomic_write_json,
    ensure_directory,
    file_lock,
    fsync_directory,
    sha256_file,
)

CACHE_STATE_FILE = "cache-state.json"
CACHE_LOCK_FILE = ".lock"
PROJECT_DIRNAME = "project"
PROJECT_NAME = "project"

REASON_HIT = "reused cached analysis"
REASON_DISABLED = "caching disabled"
REASON_FORCED = "reanalysis forced"
REASON_ABSENT = "no cached analysis for this fingerprint"
REASON_UNREADABLE = "cached analysis state is unreadable"
REASON_INCOMPLETE = "cached analysis did not finish"
REASON_PROJECT_MISSING = "cached project directory is missing"
REASON_BUSY = "cached analysis is in use by another run"


@dataclass(frozen=True)
class CacheOutcome:
    enabled: bool
    hit: bool
    path: Path | None
    reason: str

    def as_manifest_block(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "hit": self.hit,
            "path": str(self.path) if self.path is not None else None,
            "reason": self.reason,
        }


def default_cache_root() -> Path:
    configured = os.environ.get("XDG_CACHE_HOME")
    if configured:
        return Path(configured).expanduser() / "rea-automator" / "ghidra-cache"
    return Path.home() / ".cache" / "rea-automator" / "ghidra-cache"


def cache_key_from(fingerprint: dict[str, Any]) -> str:
    return fingerprint["sha256"]


def cache_key(input_identity: Any, requested_analysis: dict[str, Any]) -> str:
    if isinstance(input_identity, Path):
        input_data = {
            "path": str(input_identity.resolve()),
            "sha256": sha256_file(input_identity),
            "size": input_identity.stat().st_size,
        }
    else:
        input_data = dict(input_identity)

    fingerprint: dict[str, Any] = {
        "schema_version": 1,
        "input": input_data,
        "analysis": requested_analysis,
    }

    hash_input = {k: v for k, v in input_data.items() if k != "path"}
    canonical = json.dumps(
        {**fingerprint, "input": hash_input},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fingerprint["sha256"] = hashlib.sha256(canonical).hexdigest()
    return fingerprint["sha256"]


def entry_path(root: Path, key: str) -> Path:
    return root / key


def resolved_versions(
    *,
    ghidra_version: str,
    pyghidra_version: str,
    exporter_version: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ghidra_version": ghidra_version,
        "pyghidra_version": pyghidra_version,
        "exporter_version": exporter_version,
    }


def read_state(entry: Path) -> dict[str, Any] | None:
    try:
        state = json.loads((entry / CACHE_STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return state if isinstance(state, dict) else None


def evaluate_entry(
    entry: Path, request_fingerprint: dict[str, Any], versions: dict[str, Any]
) -> tuple[bool, str]:
    state = read_state(entry)
    if state is None:
        return False, REASON_UNREADABLE
    if state.get("status") != "complete":
        return False, REASON_INCOMPLETE
    if state.get("fingerprint", {}).get("sha256") != request_fingerprint["sha256"]:
        return False, REASON_ABSENT
    for key, value in versions.items():
        if state.get("versions", {}).get(key) != value:
            return False, f"cached analysis was built with a different {key}"
    if not (entry / PROJECT_DIRNAME).is_dir():
        return False, REASON_PROJECT_MISSING
    return True, REASON_HIT


@contextmanager
def entry_lock(entry: Path, *, blocking: bool = False):
    """Bloqueo exclusivo sobre la entrada de caché para la vida del run."""
    ensure_directory(entry)
    with file_lock(entry / CACHE_LOCK_FILE, blocking=blocking) as acquired:
        yield acquired


def mark_incomplete(entry: Path, request_fingerprint: dict[str, Any]) -> None:
    """Marca la entrada como incompleta antes de comenzar el análisis."""
    atomic_write_json(
        entry / CACHE_STATE_FILE,
        {
            "schema_version": 1,
            "status": "incomplete",
            "fingerprint": request_fingerprint,
        },
    )


def mark_complete(
    entry: Path,
    request_fingerprint: dict[str, Any],
    versions: dict[str, Any],
    analysis: dict[str, Any],
) -> None:
    """Publica la entrada como reutilizable una vez el proyecto es durable."""
    fsync_directory(entry)
    atomic_write_json(
        entry / CACHE_STATE_FILE,
        {
            "schema_version": 1,
            "status": "complete",
            "fingerprint": request_fingerprint,
            "versions": versions,
            "analysis": analysis,
        },
    )


def discard_project(root: Path, entry: Path) -> None:
    """Elimina solo el proyecto Ghidra, rechazando rutas fuera del root del caché."""
    root = root.resolve()
    project = (entry / PROJECT_DIRNAME).resolve()
    if project == root or root not in project.parents:
        raise ValueError(f"Refusing to remove a path outside the cache root: {project}")
    shutil.rmtree(project, ignore_errors=True)