"""Escritura atómica, publicación segura y recuperación de directorios de salida de Ghidra.
Adaptado de ghidra-decomp-main/src/ghidra_decomp/artifacts.py.
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import importlib
import json
import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import fcntl
except ImportError:
    fcntl = None

CORPUS_OWNER = "rea-automator"
OWNED_SCHEMA_VERSIONS = frozenset({1, 2, 3, 4, 5})


@dataclass(frozen=True)
class DestinationState:
    exists: bool
    device: int | None = None
    inode: int | None = None
    mode: int | None = None
    group: int | None = None


def sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if os.name == "nt" or error.errno in {
            getattr(os, "EACCES", 0),
            getattr(os, "EINVAL", 0),
            getattr(os, "ENOTSUP", 0),
            getattr(os, "EOPNOTSUPP", 0),
        }:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno not in {
                getattr(os, "EINVAL", 0),
                getattr(os, "ENOTSUP", 0),
                getattr(os, "EOPNOTSUPP", 0),
            }:
                raise
    finally:
        os.close(descriptor)


def fsync_tree(root: Path) -> None:
    directories = [Path(p) for p, _, _ in os.walk(root)]
    for directory in reversed(directories):
        fsync_directory(directory)


def ensure_directory(path: Path) -> None:
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    for directory in reversed(missing):
        fsync_directory(directory.parent)


def atomic_write_chunks(path: Path, chunks: Iterable[str]) -> None:
    ensure_directory(path.parent)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temp_path = Path(stream.name)
            for chunk in chunks:
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        temp_path.replace(path)
        fsync_directory(path.parent)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def atomic_write_text(path: Path, content: str) -> None:
    atomic_write_chunks(path, (content,))


def atomic_write_json(path: Path, data: Any) -> None:
    atomic_write_text(
        path, json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    )


def _acquire_lock(descriptor: int, *, blocking: bool) -> bool:
    if os.name == "nt":
        msvcrt = importlib.import_module("msvcrt")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        try:
            msvcrt.locking(descriptor, mode, 1)
        except OSError:
            if blocking:
                raise
            return False
        return True
    import fcntl as _fcntl
    flags = _fcntl.LOCK_EX if blocking else _fcntl.LOCK_EX | _fcntl.LOCK_NB
    try:
        _fcntl.flock(descriptor, flags)
    except OSError:
        if blocking:
            raise
        return False
    return True


def _release_lock(descriptor: int) -> None:
    if os.name == "nt":
        msvcrt = importlib.import_module("msvcrt")
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl as _fcntl
        _fcntl.flock(descriptor, _fcntl.LOCK_UN)


@contextmanager
def file_lock(lock_path: Path, *, blocking: bool = True):
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        acquired = _acquire_lock(descriptor, blocking=blocking)
        yield acquired
    finally:
        if acquired:
            _release_lock(descriptor)
        os.close(descriptor)


def _owned_complete_manifest(output: Path) -> bool:
    manifest_path = output / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(manifest, dict)
        and manifest.get("schema_version") in OWNED_SCHEMA_VERSIONS
        and manifest.get("status") == "complete"
        and isinstance(manifest.get("tool"), dict)
        and manifest["tool"].get("name") == CORPUS_OWNER
        and not (output / ".run-state.json").exists()
    )


def validate_destination(output: Path) -> DestinationState:
    if not output.exists():
        return DestinationState(exists=False)
    if not output.is_dir():
        raise ValueError(f"Output path is not a directory: {output}")
    entries = {path.name for path in output.iterdir()}
    if entries and not _owned_complete_manifest(output):
        raise ValueError(
            f"Refusing to replace incomplete or unowned output directory: {output}"
        )
    stat = output.stat()
    return DestinationState(
        exists=True,
        device=stat.st_dev,
        inode=stat.st_ino,
        mode=stat.st_mode & 0o7777,
        group=stat.st_gid,
    )


def _backup_directories(output: Path) -> list[Path]:
    prefix = f".{output.name}.backup-"
    return [
        path
        for path in output.parent.iterdir()
        if path.name.startswith(prefix)
        and path.is_dir()
        and _owned_complete_manifest(path)
    ]


def _backup_generation(output: Path, backup: Path) -> int:
    prefix = f".{output.name}.backup-"
    generation = backup.name[len(prefix):].split("-", 1)[0]
    try:
        return int(generation)
    except ValueError:
        return -1


def staging_prefix(output: Path) -> str:
    return f".{output.name}.staging-"


def _staging_lock_path(staging: Path) -> Path:
    return staging.parent / f"{staging.name}.lock"


def _staging_directories(output: Path) -> list[Path]:
    prefix = staging_prefix(output)
    return [
        path
        for path in output.parent.iterdir()
        if path.name.startswith(prefix) and path.is_dir()
    ]


@contextmanager
def staging_lock(staging: Path):
    lock_path = _staging_lock_path(staging)
    try:
        with file_lock(lock_path, blocking=False) as acquired:
            if not acquired:
                raise ValueError(f"Staging directory is already owned: {staging}")
            yield
    finally:
        lock_path.unlink(missing_ok=True)


def sweep_orphan_staging(output: Path) -> list[Path]:
    """Elimina carpetas de staging huérfanas dejadas por un proceso muerto."""
    removed = []
    for staging in _staging_directories(output):
        lock_path = _staging_lock_path(staging)
        with file_lock(lock_path, blocking=False) as acquired:
            if not acquired:
                continue
            shutil.rmtree(staging, ignore_errors=True)
            if not staging.exists():
                removed.append(staging)
        if not staging.exists():
            lock_path.unlink(missing_ok=True)
    if removed:
        fsync_directory(output.parent)
    return removed


def recover_destination(output: Path) -> bool:
    """Restaura el backup más reciente si una publicación anterior fue interrumpida."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(output.parent / f".{output.name}.lock"):
        sweep_orphan_staging(output)
        if output.exists():
            return False
        backups = _backup_directories(output)
        if not backups:
            return False
        newest = max(backups, key=lambda path: _backup_generation(output, path))
        os.replace(newest, output)
        fsync_directory(output.parent)
        for stale in backups:
            if stale != newest:
                shutil.rmtree(stale, ignore_errors=True)
        fsync_directory(output.parent)
        return True


@contextmanager
def destination_lock(output: Path):
    """Serializa publicación y recuperación para un mismo destino."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(output.parent / f".{output.name}.lock"):
        yield


def publish_directory(
    staging: Path, output: Path, expected: DestinationState
) -> Path | None:
    """Publica `staging` sobre `output` de forma atómica con rollback.

    `expected` es el `DestinationState` capturado antes de comenzar la exportación;
    si el destino cambió entre medio, se lanza `ValueError`.
    """
    with destination_lock(output):
        if not staging.is_dir() or not _owned_complete_manifest(staging):
            raise ValueError(
                f"Refusing to publish incomplete staging directory: {staging}"
            )
        current = validate_destination(output)
        if current != expected:
            raise ValueError(f"Output directory changed during export: {output}")

        staging.chmod(expected.mode if expected.mode is not None else 0o755)
        if expected.group is not None and hasattr(os, "chown"):
            try:
                os.chown(staging, -1, expected.group)
            except PermissionError:
                pass

        backup: Path | None = None
        if current.exists:
            backup = Path(
                tempfile.mkdtemp(
                    prefix=f".{output.name}.backup-{time.time_ns()}-",
                    dir=output.parent,
                )
            )
            backup.rmdir()

        old_moved = False
        new_moved = False
        try:
            if backup is not None:
                os.replace(output, backup)
                old_moved = True
                fsync_directory(output.parent)
            os.replace(staging, output)
            new_moved = True
            fsync_directory(output.parent)
        except BaseException as publication_error:
            rollback_errors: list[str] = []
            if new_moved:
                try:
                    os.replace(output, staging)
                    fsync_directory(output.parent)
                    new_moved = False
                except BaseException as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
            if old_moved and backup is not None and not output.exists():
                try:
                    os.replace(backup, output)
                    fsync_directory(output.parent)
                    old_moved = False
                except BaseException as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
            if rollback_errors:
                publication_error.add_note(
                    "Rollback también falló: " + "; ".join(rollback_errors)
                )
            raise
        if backup is not None:
            try:
                shutil.rmtree(backup)
                fsync_directory(output.parent)
            except OSError:
                return backup
        return None