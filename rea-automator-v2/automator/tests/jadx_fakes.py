"""Constructores de un JADX simulado: carpeta ya instalada y zip de "release" (para install_jadx)."""

import hashlib
import shlex
import stat
import sys
import zipfile
from pathlib import Path

FAKE_JADX_PY = Path(__file__).parent / "fake_jadx.py"
VERSION = "9.9.9"


def launcher_text() -> str:
    """bin/jadx simulado: delega en fake_jadx.py con el mismo intérprete que corre las pruebas."""
    return f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(FAKE_JADX_PY))} "$@"\n'


BROKEN_LAUNCHER = "#!/bin/sh\necho 'jadx roto' >&2\nexit 1\n"


def make_install(tool_dir: Path, version: str = VERSION, *, launcher: str | None = None, executable: bool = True) -> Path:
    """Crea <tool_dir>/jadx/{bin/jadx,lib/jadx-<v>-all.jar}; devuelve la carpeta jadx."""
    jadx_dir = tool_dir / "jadx"
    (jadx_dir / "bin").mkdir(parents=True)
    (jadx_dir / "lib").mkdir(parents=True)
    script = jadx_dir / "bin" / "jadx"
    script.write_text(launcher if launcher is not None else launcher_text())
    script.chmod(0o755 if executable else 0o644)
    (jadx_dir / "lib" / f"jadx-{version}-all.jar").write_bytes(b"PK\x03\x04 jar simulado")
    return jadx_dir


def make_zip(
    zip_path: Path,
    version: str = VERSION,
    *,
    launcher: str | None = None,
    omit: tuple[str, ...] = (),
    extra: dict[str, bytes] | None = None,
    symlink: str | None = None,
) -> str:
    """Escribe un zip con la estructura de una release de JADX (sin bits de ejecución, como
    hace Python) y devuelve su SHA-256."""
    entries = {
        "LICENSE": b"Apache-2.0 (simulado)",
        "README.md": b"# jadx simulado",
        "bin/jadx": (launcher if launcher is not None else launcher_text()).encode(),
        "bin/jadx-gui": b"#!/bin/sh\nexit 0\n",
        "bin/jadx.bat": b"@echo off\r\n",
        f"lib/jadx-{version}-all.jar": b"PK\x03\x04 jar simulado",
    }
    for name in omit:
        entries.pop(name)
    entries.update(extra or {})
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return hashlib.sha256(zip_path.read_bytes()).hexdigest()
