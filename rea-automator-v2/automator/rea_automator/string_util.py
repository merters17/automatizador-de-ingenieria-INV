"""Extracción de strings de binarios usando el comando `strings` del sistema (adaptado de GhidraAutomation-main)."""
from __future__ import annotations
import subprocess
from pathlib import Path


def extract_strings(binary_path: str | Path) -> list[str]:
    """Extrae strings imprimibles de un binario y las devuelve como lista de líneas."""
    try:
        result = subprocess.run(
            ["strings", str(binary_path)],
            capture_output=True,
            check=True,
            text=True,
        )
        return result.stdout.splitlines()
    except Exception as exc:  # noqa: BLE001 - se informa al llamador mediante lista vacía
        print(f"Error extrayendo strings de {binary_path}: {exc}")
        return []