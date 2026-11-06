"""Adaptador: familia -> comando de volcado MASIVO a una carpeta de código fuente.

Diferencia clave con `adapters/rea_cli.py`: `rea` entrega evidencia dirigida
(una clase, un método, una función a la vez). Aquí se invoca la herramienta de
descompilación DIRECTO, en su modo de volcado completo, para obtener TODO el
código de una sola vez. Solo construye el plan; no ejecuta nada ni interpreta
resultados (igual que rea_cli.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..routing import FAMILY_ANDROID, FAMILY_JS, FAMILY_MANAGED, FAMILY_NATIVE

# kinds de plan: cómo analyzer/decompile.py debe ejecutar este plan.
KIND_SUBPROCESS = "subprocess"  # correr argv con run_bounded
KIND_COPY_DIR = "copy_dir"      # el objetivo ya es una carpeta de fuente (JS sin empaquetar)


@dataclass(frozen=True)
class BulkPlan:
    kind: str
    argv: tuple[str, ...] = ()
    note: str = ""


def build_bulk_plan(settings: Settings, family: str, target: Path, out_dir: Path) -> BulkPlan:
    """Arma el plan de descompilación masiva para `family`. No ejecuta nada."""
    if family == FAMILY_ANDROID:
        # jadx en modo normal (NO jadx-headless-mcp): vuelca TODAS las clases a .java.
        return BulkPlan(
            KIND_SUBPROCESS,
            (*settings.jadx_argv, "-d", str(out_dir), str(target), "--no-res"),
        )

    if family == FAMILY_MANAGED:
        # ilspycmd -p: proyecto completo (todas las clases), no una clase a la vez.
        return BulkPlan(
            KIND_SUBPROCESS,
            (*settings.ilspycmd_argv, "-p", "-o", str(out_dir), str(target)),
        )

    if family == FAMILY_JS:
        if target.is_dir():
            # Ya es una carpeta de fuente (no empaquetada): no hay nada que descompilar,
            # solo recolectar para el zip final.
            return BulkPlan(KIND_COPY_DIR, note="directorio ya es código fuente")
        # .asar: extraer el archivo empaquetado completo a una carpeta.
        return BulkPlan(
            KIND_SUBPROCESS,
            (*settings.asar_argv, "extract", str(target), str(out_dir)),
        )

    if family == FAMILY_NATIVE:
        raise NotImplementedError(
            "native-binary: requiere un proyecto Ghidra + script headless; "
            "ver rea_automator.adapters.bulk_native.build_ghidra_headless_argv"
        )

    raise ValueError(f"familia sin adaptador de volcado masivo: {family}")
