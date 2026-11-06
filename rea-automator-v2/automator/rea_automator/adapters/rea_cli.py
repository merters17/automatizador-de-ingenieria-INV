"""Adaptador: familia de análisis -> comando de la CLI de rea.

Solo construye argv. No ejecuta nada ni interpreta resultados.
Los nombres de comando y opciones están verificados contra `rea <cmd> --help`
de rea v6.5.0.
"""

from __future__ import annotations

from ..config import Settings
from ..routing import FAMILY_ANDROID, FAMILY_JS, FAMILY_MANAGED, FAMILY_NATIVE


def build_argv(settings: Settings, family: str, target: str) -> tuple[str, ...]:
    if family == FAMILY_JS:
        sub = ["analyze-javascript-application", target]
    elif family == FAMILY_ANDROID:
        sub = ["inspect-android-package", target]
    elif family == FAMILY_MANAGED:
        sub = ["inspect-managed-artifact", target]
    elif family == FAMILY_NATIVE:
        sub = ["analyze", target, "--provider", settings.native_provider]
    else:
        raise ValueError(f"familia sin adaptador: {family}")
    # --format json: la salida por defecto es TOON, no JSON.
    return (*settings.rea_argv, *sub, "--format", "json")
