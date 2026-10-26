"""Configuración. Todo se puede sobrescribir por variable de entorno.

Cada valor numérico se valida al cargarlo y también al construir `Settings`
directamente, para que un valor inválido nunca llegue a los subprocesos ni a
los límites de lectura. Un valor inválido lanza `ConfigError` con el nombre de
la variable (o del campo) y el valor recibido.
"""

from __future__ import annotations

import math
import os
import shlex
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REA_CMD = "rea"
DEFAULT_TIMEOUT_S = 1800.0
DEFAULT_MAX_STDOUT = 256 * 1024 * 1024  # la evidencia JSON de apps grandes puede ser muy grande
DEFAULT_MAX_STDERR = 4 * 1024 * 1024
DEFAULT_NATIVE_PROVIDER = "ghidra"

# El directorio del proyecto se determina desde el código fuente, no desde el
# directorio actual del terminal. Así JADX no cae por defecto en el PATH del
# sistema: debe existir en ./tool/jadx/bin/jadx dentro de ESTE proyecto.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROJECT_TOOL_DIR = PROJECT_ROOT / "tool"
# v2: `PROJECT_JADX_DIR` (automator/tool/jadx/) es la carpeta que prepara
# `jadx_tool.install_jadx` y que comprueba `jadx_tool.check_jadx`.
PROJECT_JADX_DIR = PROJECT_TOOL_DIR / "jadx"
PROJECT_JADX_CMD = PROJECT_JADX_DIR / "bin" / "jadx"

# Herramientas de descompilación MASIVA (bulk): invocadas directo, sin pasar por `rea`.
# `rea` entrega evidencia dirigida clase-por-clase/método-por-método; estas herramientas
# vuelcan TODO el objetivo a una carpeta de código fuente de una sola vez.
DEFAULT_JADX_CMD = str(PROJECT_JADX_CMD)
DEFAULT_ILSPYCMD_CMD = "ilspycmd"
DEFAULT_ASAR_CMD = "npx asar"
# Ghidra 12 solo ejecuta scripts Python vía PyGhidra; `analyzeHeadless` a secas no sirve.
DEFAULT_GHIDRA_HEADLESS_CMD = "pyghidraRun -H"


class ConfigError(ValueError):
    """Valor de configuración inválido. El mensaje nombra la variable o el campo."""


def validate_timeout(value: object, name: str) -> float:
    """Timeout en segundos: número finito y mayor que 0. Rechaza NaN, ±inf, 0 y negativos."""
    if isinstance(value, bool):
        raise ConfigError(f"{name} debe ser un número, no {value!r}")
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ConfigError(f"{name} debe ser un número, no {value!r}") from None
    if not math.isfinite(number):
        raise ConfigError(f"{name} debe ser un número finito, no {value!r}")
    if number <= 0:
        raise ConfigError(f"{name} debe ser mayor que 0, no {value!r}")
    return number


def validate_positive_int(value: object, name: str) -> int:
    """Límite entero (bytes, cantidad de archivos): entero estricto y mayor que 0.

    Un 0 también se rechaza: con un tope de 0 ninguna salida cabe, así que el
    automatizador fallaría en silencio en cada corrida.
    """
    if isinstance(value, bool):
        raise ConfigError(f"{name} debe ser un entero, no {value!r}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str):
        text = value.strip()
        try:
            number = int(text, 10)
        except ValueError:
            raise ConfigError(f"{name} debe ser un entero, no {value!r}") from None
    else:
        raise ConfigError(f"{name} debe ser un entero, no {value!r}")
    if number <= 0:
        raise ConfigError(f"{name} debe ser mayor que 0, no {value!r}")
    return number


@dataclass(frozen=True)
class Settings:
    rea_argv: tuple[str, ...]
    native_provider: str
    timeout_s: float
    max_stdout_bytes: int
    max_stderr_bytes: int
    out_dir: Path
    jadx_argv: tuple[str, ...] = (DEFAULT_JADX_CMD,)
    ilspycmd_argv: tuple[str, ...] = (DEFAULT_ILSPYCMD_CMD,)
    asar_argv: tuple[str, ...] = (DEFAULT_ASAR_CMD,)
    ghidra_headless_argv: tuple[str, ...] = (DEFAULT_GHIDRA_HEADLESS_CMD,)

    def __post_init__(self) -> None:
        # Se valida sin reasignar: el dataclass es frozen y el valor ya es el correcto.
        validate_timeout(self.timeout_s, "timeout_s")
        validate_positive_int(self.max_stdout_bytes, "max_stdout_bytes")
        validate_positive_int(self.max_stderr_bytes, "max_stderr_bytes")


def _argv_from_env(env: dict, var: str, default_cmd: str) -> tuple[str, ...]:
    raw = env.get(var, default_cmd)
    argv = tuple(shlex.split(raw))
    if not argv:
        raise ConfigError(f"{var} está vacío")
    return argv


def load_settings(
    *,
    out_dir: str | Path = "automator-results",
    timeout_s: float | None = None,
    env: dict | None = None,
) -> Settings:
    env = os.environ if env is None else env

    if timeout_s is not None:
        timeout = validate_timeout(timeout_s, "--timeout")
    else:
        timeout = validate_timeout(
            env.get("REA_AUTOMATOR_TIMEOUT_S", DEFAULT_TIMEOUT_S), "REA_AUTOMATOR_TIMEOUT_S"
        )

    max_stdout = validate_positive_int(
        env.get("REA_AUTOMATOR_MAX_STDOUT", DEFAULT_MAX_STDOUT), "REA_AUTOMATOR_MAX_STDOUT"
    )
    max_stderr = validate_positive_int(
        env.get("REA_AUTOMATOR_MAX_STDERR", DEFAULT_MAX_STDERR), "REA_AUTOMATOR_MAX_STDERR"
    )

    return Settings(
        rea_argv=_argv_from_env(env, "REA_AUTOMATOR_REA_CMD", DEFAULT_REA_CMD),
        native_provider=env.get("REA_AUTOMATOR_NATIVE_PROVIDER", DEFAULT_NATIVE_PROVIDER),
        timeout_s=timeout,
        max_stdout_bytes=max_stdout,
        max_stderr_bytes=max_stderr,
        out_dir=Path(out_dir),
        # JADX es deliberadamente fijo al binario local del proyecto. No se consulta
        # PATH ni una variable de entorno que pueda redirigir a otra instalación.
        jadx_argv=(DEFAULT_JADX_CMD,),
        ilspycmd_argv=_argv_from_env(env, "REA_AUTOMATOR_ILSPYCMD_CMD", DEFAULT_ILSPYCMD_CMD),
        asar_argv=_argv_from_env(env, "REA_AUTOMATOR_ASAR_CMD", DEFAULT_ASAR_CMD),
        ghidra_headless_argv=_argv_from_env(
            env, "REA_AUTOMATOR_GHIDRA_HEADLESS_CMD", DEFAULT_GHIDRA_HEADLESS_CMD
        ),
    )
