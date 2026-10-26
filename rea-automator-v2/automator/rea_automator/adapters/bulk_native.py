"""Adaptador para binarios nativos: arma el comando `pyghidraRun -H` (PyGhidra headless) que corre
`scripts/ghidra_decompile_all.py` contra el objetivo. Solo construye argv; no
ejecuta nada. Requiere una instalación de Ghidra real (no se distribuye aquí).
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
) -> tuple[str, ...]:
    """pyghidraRun -H <project_dir> <project_name> -import <target> \
         -postScript ghidra_decompile_all.py <out_dir> \
         -scriptPath <script_dir> -deleteProject
    """
    return (
        *settings.ghidra_headless_argv,
        str(project_dir),
        project_name,
        "-import",
        str(target),
        "-postScript",
        _SCRIPT_NAME,
        str(out_dir),
        "-scriptPath",
        str(_SCRIPT_DIR),
        "-deleteProject",
    )
