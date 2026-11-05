"""Adaptador para binarios nativos: arma el comando `pyghidraRun -H` contra el objetivo.
Incluye soporte para opciones del script mejorado (tiempo por función, combinado, filtros).
Solo construye argv; no ejecuta nada.
"""
from __future__ import annotations
from pathlib import Path
from ..config import Settings

_SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
_SCRIPT_NAME = "ghidra_decompile_all.py"


def build_ghidra_headless_argv(
    settings: Settings,
    target: Path,
    out_dir: Path,
    *,
    project_dir: Path,
    project_name: str = "rea_automator_bulk",
    timeout_per_func: int = 60,
    combined: bool = False,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """pyghidraRun -H <project_dir> <project_name> -import <target> \
         -postScript ghidra_decompile_all.py <out_dir> [opciones] \
         -scriptPath <script_dir> -deleteProject
    """
    argv: list[str] = [
        *settings.ghidra_headless_argv,
        str(project_dir),
        project_name,
        "-import",
        str(target),
        "-postScript",
        _SCRIPT_NAME,
        str(out_dir),
        "--timeout-per-func",
        str(timeout_per_func),
        "-scriptPath",
        str(_SCRIPT_DIR),
        "-deleteProject",
    ]
    if combined:
        argv.append("--combined")
    for pattern in include:
        argv.extend(["--include", pattern])
    for pattern in exclude:
        argv.extend(["--exclude", pattern])
    return tuple(argv)