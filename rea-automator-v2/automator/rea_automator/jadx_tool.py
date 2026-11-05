"""Preparación y comprobación de JADX dentro del propio proyecto (`tool/jadx/`).

Por qué existe (v2)
-------------------
La v1 daba por hecho que `tool/jadx/bin/jadx` ya estaba ahí. Lo instalaba un paso de
`scripts/setup_tools.sh` que:

  (a) averiguaba la versión con `curl -sI https://github.com/skylot/jadx/releases/latest`
      (con una política de salida de red esa consulta puede devolver 403 y el script
      seguía con una versión vacía),
  (b) solo corría después de `apt-get`, y
  (c) nunca comprobaba que el JADX instalado arrancara (a diferencia de ilspycmd).

Este módulo lo sustituye:

- **Versión y SHA-256 fijados.** No se consulta "latest". El zip se verifica antes de
  extraerse y, si no coincide, no se instala nada.
- **Extracción segura** a una carpeta temporal; solo se pasa a `tool/jadx/` cuando el zip
  está verificado y tiene la estructura esperada.
- **Comprobación desde esa ruta.** Se ejecuta `tool/jadx/bin/jadx` por su ruta absoluta
  (nunca por `PATH`): primero `--version` y después una descompilación real de una clase
  de prueba (`smoke/Hello.class`), comprobando que el Java recuperado contiene lo esperado.

Todo proceso externo pasa por `runner.run_bounded`, como en el resto del proyecto.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import os
import re
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterator

try:
    import fcntl  # POSIX. En Windows no existe: ahí no se bloquea la instalación.
except ImportError:  # pragma: no cover - depende de la plataforma
    fcntl = None  # type: ignore[assignment]

from . import __version__
from .config import PROJECT_JADX_DIR, PROJECT_TOOL_DIR
from .runner import CommandNotFoundError, run_bounded

JADX_VERSION = "1.5.6"
JADX_RELEASE_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
# SHA-256 del asset oficial jadx-1.5.6.zip (72 646 741 bytes), calculado al descargarlo el
# 2026-10-17 desde la URL de arriba. No se pudo contrastar con una fuente independiente
# (la API y la página de releases de GitHub no eran accesibles desde el entorno donde se
# preparó esta versión), así que es un valor "fijado en el primer uso": si el asset cambia,
# la instalación falla (comportamiento deseado) en vez de ejecutar algo distinto.
JADX_ZIP_SHA256 = "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"

# README de JADX: "ensure you have installed Java 11 or later 64-bit version".
MIN_JAVA_MAJOR = 11

MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_EXTRACT_FILES = 1000
MAX_EXTRACT_BYTES = 1024 * 1024 * 1024  # el zip real descomprime ~78 MB
DEFAULT_CHECK_TIMEOUT_S = 300.0

SMOKE_CLASS = Path(__file__).resolve().parent / "smoke" / "Hello.class"

SETUP_COMMAND = "python -m rea_automator setup-jadx"


class JadxInstallError(Exception):
    """Fallo al preparar JADX. `code` es estable para consumidores; `hint` dice qué hacer."""

    def __init__(self, code: str, message: str, *, hint: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "hint": self.hint}


# ── utilidades ───────────────────────────────────────────────────────────────

def sha256_file(path: str | Path, *, chunk: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


@dataclass(frozen=True)
class Captured:
    returncode: int | None
    timed_out: bool
    stdout: str
    stderr: str
    duration_s: float
    launch_error: str | None = None  # el proceso nunca llegó a arrancar


def _run_capture(argv: list[str], *, timeout_s: float) -> Captured:
    """Ejecuta `argv` con el runner acotado del proyecto y devuelve su salida como texto."""
    with tempfile.TemporaryDirectory(prefix="rea-run-") as tmp:
        base = Path(tmp)
        try:
            raw = run_bounded(
                argv,
                stdout_path=base / "stdout.log",
                stderr_path=base / "stderr.log",
                timeout_s=timeout_s,
                max_stdout_bytes=1024 * 1024,
                max_stderr_bytes=1024 * 1024,
            )
        except CommandNotFoundError as exc:
            return Captured(None, False, "", "", 0.0, launch_error=str(exc.original))
        return Captured(
            raw.returncode,
            raw.timed_out,
            _read_text(base / "stdout.log"),
            _read_text(base / "stderr.log"),
            raw.duration_s,
        )


# ── Java ─────────────────────────────────────────────────────────────────────

_JAVA_VERSION_RE = re.compile(r'version\s+"([^"]+)"')


def parse_java_major(version_text: str) -> int | None:
    """'21.0.12.1' -> 21;  '1.8.0_292' -> 8;  '11' -> 11;  '17-ea' -> 17."""
    match = re.match(r"(\d+)(?:\.(\d+))?", version_text.strip())
    if not match:
        return None
    major = int(match.group(1))
    if major == 1 and match.group(2) is not None:  # esquema antiguo: 1.8.0_292 -> 8
        return int(match.group(2))
    return major


def java_command() -> str:
    """Mismo criterio que `bin/jadx`: $JAVA_HOME/bin/java si JAVA_HOME existe; si no, `java` del PATH."""
    home = os.environ.get("JAVA_HOME")
    return str(Path(home) / "bin" / "java") if home else "java"


def check_java(*, timeout_s: float = 60.0) -> dict:
    command = java_command()
    info: dict = {"command": command, "ok": False, "version": None, "major": None, "detail": ""}
    cap = _run_capture([command, "-version"], timeout_s=timeout_s)
    if cap.launch_error:
        info["detail"] = f"no se pudo ejecutar {command!r}: {cap.launch_error}"
        return info
    match = _JAVA_VERSION_RE.search(cap.stderr + "\n" + cap.stdout)  # `java -version` escribe en stderr
    if cap.returncode != 0 or not match:
        info["detail"] = f"`{command} -version` terminó con código {cap.returncode} y una salida no reconocible"
        return info
    info["version"] = match.group(1)
    info["major"] = parse_java_major(match.group(1))
    if info["major"] is None or info["major"] < MIN_JAVA_MAJOR:
        info["detail"] = f"Java {match.group(1)}: JADX necesita Java {MIN_JAVA_MAJOR} o superior"
        return info
    info["ok"] = True
    info["detail"] = f"Java {match.group(1)}"
    return info


# ── comprobación desde la ruta del proyecto ──────────────────────────────────

@dataclass
class CheckStep:
    name: str
    ok: bool
    detail: str = ""
    duration_s: float | None = None


@dataclass
class JadxCheck:
    ok: bool
    jadx_dir: str
    launcher: str
    expected_version: str
    version: str | None = None
    jar: str | None = None
    jar_sha256: str | None = None
    java: dict = field(default_factory=dict)
    steps: list[CheckStep] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    smoke: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


_VERSION_LINE_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?[-+.\w]*$")

# Lo que JADX debe haber reconstruido de smoke/Hello.class. Los nombres de los parámetros
# se perdieron a propósito al compilar (-g:none), así que no se comprueban.
_SMOKE_MARKERS = {
    "declaración `class Hello`": re.compile(r"\bclass\s+Hello\b"),
    'literal "hola-jadx-smoke:"': re.compile(r'"hola-jadx-smoke:"'),
    "llamada add(2, 3)": re.compile(r"\badd\(2,\s*3\)"),
}


def _smoke_decompile(launcher: Path, smoke_class: Path, timeout_s: float) -> tuple[bool, str, dict, float | None]:
    if not smoke_class.is_file():
        return False, f"falta la clase de prueba {smoke_class}", {}, None
    with tempfile.TemporaryDirectory(prefix="rea-jadx-smoke-") as tmp:
        out = Path(tmp) / "out"
        cap = _run_capture([str(launcher), "-d", str(out), "--no-res", str(smoke_class)], timeout_s=timeout_s)
        java_files = sorted(out.rglob("*.java")) if out.is_dir() else []
        text = "\n".join(_read_text(p) for p in java_files)
        markers = {name: bool(rx.search(text)) for name, rx in _SMOKE_MARKERS.items()}
        rel = [p.relative_to(out).as_posix() for p in java_files]
        data = {
            "input": str(smoke_class),
            "exit_code": cap.returncode,
            "java_files": rel,
            "markers": markers,
            "excerpt": text.splitlines()[:14],
        }
    if cap.launch_error:
        return False, f"no se pudo ejecutar {launcher}: {cap.launch_error}", data, cap.duration_s
    ok = cap.returncode == 0 and not cap.timed_out and bool(rel) and all(markers.values())
    if ok:
        detail = f"JADX recuperó {', '.join(rel)} con las {len(markers)} marcas esperadas"
    else:
        missing = [name for name, found in markers.items() if not found]
        detail = (
            f"código de salida {cap.returncode}{' (timeout)' if cap.timed_out else ''}; "
            f"archivos .java recuperados: {len(rel)}; marcas que faltan: {missing or 'ninguna'}"
        )
    return ok, detail, data, cap.duration_s


def check_jadx(
    jadx_dir: str | Path = PROJECT_JADX_DIR,
    *,
    expected_version: str = JADX_VERSION,
    smoke_class: str | Path = SMOKE_CLASS,
    fix_permissions: bool = True,
    timeout_s: float = DEFAULT_CHECK_TIMEOUT_S,
) -> JadxCheck:
    """Comprueba que el JADX de `jadx_dir` funciona EJECUTADO DESDE ESA RUTA.

    Pasos (cada uno queda en `steps`; el primero que falla corta la comprobación):
      1. `bin/jadx` existe        2. es ejecutable        3. existe `lib/jadx-*-all.jar`
      4. hay Java 11+             5. `bin/jadx --version` responde con una versión
      6. descompila `smoke/Hello.class` y el Java recuperado tiene lo esperado

    Nunca se consulta `PATH` para JADX: el lanzador se ejecuta por su ruta absoluta.
    `fix_permissions` restaura el bit de ejecución si un zip/copia lo perdió.
    """
    jadx_dir = Path(jadx_dir)
    launcher = jadx_dir / "bin" / "jadx"
    chk = JadxCheck(ok=False, jadx_dir=str(jadx_dir), launcher=str(launcher), expected_version=expected_version)

    def step(name: str, ok: bool, detail: str = "", duration_s: float | None = None) -> bool:
        chk.steps.append(CheckStep(name, ok, detail, duration_s))
        return ok

    present = launcher.is_file()
    if not step(
        "launcher_existe",
        present,
        str(launcher) if present else f"no existe {launcher} (prepáralo con: {SETUP_COMMAND})",
    ):
        return chk

    if not os.access(launcher, os.X_OK):
        if not fix_permissions:
            step("launcher_ejecutable", False, f"{launcher} no es ejecutable (chmod +x)")
            return chk
        try:
            launcher.chmod(launcher.stat().st_mode | 0o111)
        except OSError as exc:
            step("launcher_ejecutable", False, f"{launcher} no es ejecutable y no se pudo corregir: {exc}")
            return chk
        chk.warnings.append("bin/jadx no era ejecutable; se restauró el bit de ejecución")
    step("launcher_ejecutable", True, str(launcher))

    jars = sorted((jadx_dir / "lib").glob("jadx-*-all.jar"))
    if not step(
        "jar_existe",
        bool(jars),
        str(jars[0]) if jars else f"no hay lib/jadx-*-all.jar dentro de {jadx_dir}",
    ):
        return chk
    chk.jar = str(jars[0])
    try:
        chk.jar_sha256 = sha256_file(jars[0])
    except OSError as exc:
        chk.warnings.append(f"no se pudo calcular el SHA-256 del jar: {exc}")
    jar_version = re.fullmatch(r"jadx-(.+)-all\.jar", jars[0].name)

    chk.java = check_java()
    if not step("java_disponible", bool(chk.java["ok"]), chk.java["detail"]):
        return chk

    cap = _run_capture([str(launcher), "--version"], timeout_s=timeout_s)
    first_line = next((line.strip() for line in cap.stdout.splitlines() if line.strip()), "")
    version_ok = cap.returncode == 0 and not cap.timed_out and bool(_VERSION_LINE_RE.match(first_line))
    if cap.launch_error:
        detail = f"no se pudo ejecutar {launcher}: {cap.launch_error}"
    else:
        detail = f"`{launcher} --version` -> {first_line!r} (código {cap.returncode}{', timeout' if cap.timed_out else ''})"
    chk.version = first_line if version_ok else None
    if not step("version_desde_la_ruta_del_proyecto", version_ok, detail, cap.duration_s):
        return chk
    if chk.version != expected_version:
        chk.warnings.append(f"la versión instalada es {chk.version}, pero el proyecto fija {expected_version}")
    if jar_version and jar_version.group(1) != chk.version:
        chk.warnings.append(
            f"el jar se llama jadx-{jar_version.group(1)}-all.jar pero `--version` responde {chk.version}"
        )

    smoke_ok, detail, data, duration = _smoke_decompile(launcher, Path(smoke_class), timeout_s)
    chk.smoke = data
    step("descompila_clase_de_prueba", smoke_ok, detail, duration)

    chk.ok = all(s.ok for s in chk.steps)
    return chk


# ── instalación ──────────────────────────────────────────────────────────────

def _download(url: str, dest: Path, *, timeout_s: float, log: Callable[[str], None], hint: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": f"rea-automator/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as resp, open(dest, "wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            next_mark = 25
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                done += len(chunk)
                if done > MAX_DOWNLOAD_BYTES:
                    raise JadxInstallError("too_large", f"la descarga supera {MAX_DOWNLOAD_BYTES} bytes; se aborta")
                out.write(chunk)
                if total and done * 100 // total >= next_mark:
                    log(f"  descargado {done * 100 // total}% ({done // (1024 * 1024)} MiB)")
                    next_mark += 25
    except urllib.error.HTTPError as exc:
        raise JadxInstallError("download_failed", f"HTTP {exc.code} al descargar {url}", hint=hint) from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise JadxInstallError("download_failed", f"no se pudo descargar {url}: {exc}", hint=hint) from exc


def _safe_extract(zip_path: Path, dest: Path) -> None:
    """Extrae `zip_path` en `dest` (carpeta nueva) rechazando rutas que escapan, enlaces y tamaños excesivos."""
    try:
        zf = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise JadxInstallError("bad_zip", f"el archivo no es un zip válido: {exc}") from exc
    with zf:
        dest.mkdir(parents=True, exist_ok=False)
        dest_resolved = dest.resolve()
        infos = zf.infolist()
        if len(infos) > MAX_EXTRACT_FILES:
            raise JadxInstallError("too_many_files", f"el zip tiene {len(infos)} entradas (máximo {MAX_EXTRACT_FILES})")
        declared = 0
        for info in infos:
            if stat.S_ISLNK(info.external_attr >> 16):
                raise JadxInstallError("unsafe_entry", f"enlace simbólico dentro del zip: {info.filename}")
            target = (dest / info.filename).resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise JadxInstallError("unsafe_path", f"ruta que escapa del directorio: {info.filename}")
            declared += info.file_size
        if declared > MAX_EXTRACT_BYTES:
            raise JadxInstallError("too_large", f"el zip declara {declared} bytes descomprimidos (máximo {MAX_EXTRACT_BYTES})")
        written = 0
        try:
            for info in infos:
                target = dest / info.filename
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    while True:
                        block = src.read(1024 * 1024)
                        if not block:
                            break
                        written += len(block)
                        if written > MAX_EXTRACT_BYTES:  # el encabezado del zip mentía
                            raise JadxInstallError("too_large", "el contenido real supera el límite de extracción")
                        out.write(block)
        except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
            raise JadxInstallError("bad_zip", f"zip dañado durante la extracción: {exc}") from exc


def _validate_layout(root: Path, version: str) -> None:
    needed = [root / "bin" / "jadx", root / "lib" / f"jadx-{version}-all.jar"]
    missing = [str(p.relative_to(root)) for p in needed if not p.is_file()]
    if missing:
        raise JadxInstallError(
            "bad_layout",
            f"el zip no tiene la estructura esperada de JADX {version}; faltan: {', '.join(missing)}",
        )


def _make_executable(root: Path) -> None:
    for name in ("jadx", "jadx-gui"):
        launcher = root / "bin" / name
        if launcher.is_file():
            launcher.chmod(launcher.stat().st_mode | 0o111)


@contextlib.contextmanager
def _install_lock(tool_dir: Path) -> Iterator[None]:
    """Bloqueo exclusivo: dos instalaciones simultáneas no pueden pisarse."""
    tool_dir.mkdir(parents=True, exist_ok=True)
    handle = open(tool_dir / ".jadx-install.lock", "w")
    try:
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        handle.close()


@dataclass
class InstallResult:
    status: str  # already_installed | installed | reinstalled | rolled_back
    ok: bool
    jadx_dir: str
    version: str | None
    source: str | None  # "download" | "local-zip" | None (ya estaba instalado)
    zip_sha256: str | None
    previous_version: str | None
    restored_previous: bool
    check: JadxCheck

    def to_dict(self) -> dict:
        return asdict(self)


def install_jadx(
    *,
    tool_dir: str | Path = PROJECT_TOOL_DIR,
    zip_path: str | Path | None = None,
    force: bool = False,
    version: str = JADX_VERSION,
    sha256: str = JADX_ZIP_SHA256,
    url: str | None = None,
    download_timeout_s: float = 60.0,
    log: Callable[[str], None] | None = None,
) -> InstallResult:
    """Prepara JADX en `<tool_dir>/jadx/` y lo comprueba desde esa ruta.

    - Si ya hay un JADX de la versión fijada que pasa la comprobación completa, no toca nada
      (a menos que `force`).
    - Si no, obtiene el zip (`zip_path` local, o descarga de `url`), verifica su SHA-256,
      lo extrae en una carpeta temporal, valida la estructura y lo coloca en `tool/jadx/`.
    - Si había una instalación previa que funcionaba y la nueva no pasa la comprobación,
      se restaura la anterior (`status == "rolled_back"`).
    - Una instalación nueva que no pasa la comprobación (p. ej. no hay Java) se deja en su
      sitio para poder arreglar el entorno y volver a comprobar; `ok` es False.

    Lanza `JadxInstallError` si no se pudo obtener o validar el zip.
    """
    log = log or (lambda _msg: None)
    tool_dir = Path(tool_dir)
    jadx_dir = tool_dir / "jadx"
    url = url or f"https://github.com/skylot/jadx/releases/download/v{version}/jadx-{version}.zip"
    hint = f"Descarga {url} manualmente y ejecuta: {SETUP_COMMAND} --jadx-zip <ruta/a/jadx-{version}.zip>"

    with _install_lock(tool_dir):
        for leftover in tool_dir.glob(".jadx-staging-*"):  # restos de una instalación interrumpida
            shutil.rmtree(leftover, ignore_errors=True)

        previous_version: str | None = None
        previous_healthy = False
        if jadx_dir.exists():
            log(f"Comprobando la instalación existente en {jadx_dir} ...")
            pre = check_jadx(jadx_dir, expected_version=version)
            if pre.ok and pre.version == version and not force:
                log(f"JADX {version} ya está instalado y funciona desde esa ruta: no se toca nada.")
                return InstallResult("already_installed", True, str(jadx_dir), pre.version, None, None, None, False, pre)
            previous_version = pre.version
            previous_healthy = pre.ok

        staging_root = Path(tempfile.mkdtemp(prefix=".jadx-staging-", dir=tool_dir))
        try:
            if zip_path is not None:
                source_zip = Path(zip_path)
                if not source_zip.is_file():
                    raise JadxInstallError("zip_not_found", f"no existe el zip indicado: {source_zip}")
                source = "local-zip"
            else:
                source_zip = staging_root / f"jadx-{version}.zip"
                log(f"Descargando {url} ...")
                _download(url, source_zip, timeout_s=download_timeout_s, log=log, hint=hint)
                source = "download"

            actual = sha256_file(source_zip)
            if actual != sha256:
                raise JadxInstallError(
                    "checksum_mismatch",
                    f"SHA-256 inesperado para {source_zip.name}: {actual} (se esperaba {sha256})",
                    hint="No se instala nada que no coincida con el SHA-256 fijado en rea_automator/jadx_tool.py.",
                )
            log(f"SHA-256 verificado: {actual}")

            staging = staging_root / "jadx"
            _safe_extract(source_zip, staging)
            _validate_layout(staging, version)
            _make_executable(staging)

            backup: Path | None = None
            if jadx_dir.exists():
                backup = staging_root / "previous"
                os.replace(jadx_dir, backup)
            os.replace(staging, jadx_dir)

            log(f"Comprobando {jadx_dir / 'bin' / 'jadx'} ...")
            check = check_jadx(jadx_dir, expected_version=version)

            restored = False
            if not check.ok and backup is not None and previous_healthy:
                shutil.rmtree(jadx_dir, ignore_errors=True)
                os.replace(backup, jadx_dir)
                restored = True
                status = "rolled_back"
            else:
                status = "reinstalled" if backup is not None else "installed"
            return InstallResult(
                status=status,
                ok=check.ok and not restored,
                jadx_dir=str(jadx_dir),
                version=check.version,
                source=source,
                zip_sha256=actual,
                previous_version=previous_version,
                restored_previous=restored,
                check=check,
            )
        finally:
            shutil.rmtree(staging_root, ignore_errors=True)
