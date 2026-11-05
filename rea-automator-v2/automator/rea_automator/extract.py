"""Extractor simple de código fuente (optimizado para velocidad).

Uso:
    python -m rea_automator extract <archivo_o_carpeta> --out <carpeta> --jobs 4 --no-zip
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from .adapters.bulk_tools import KIND_COPY_DIR, KIND_SUBPROCESS, build_bulk_plan
from .config import load_settings
from .decompile import DecompileResult, decompile_target
from .routing import (
    FAMILY_ANDROID,
    FAMILY_JS,
    FAMILY_MANAGED,
    FAMILY_NATIVE,
    RoutingError,
    route,
)
from .runner import CommandNotFoundError


def _file_hash(path: Path) -> str:
    """Hash rápido (sha1, primeros 16 MB) para cachear resultados."""
    h = hashlib.sha1()
    with open(path, "rb") as f:
        h.update(f.read(16 * 1024 * 1024))
    return h.hexdigest()[:16]


def _detect_family(target: Path) -> Optional[str]:
    try:
        chosen = route(target)
        return chosen.family
    except RoutingError:
        return None


def _hint_for_family(family: str) -> str:
    hints = {
        FAMILY_ANDROID: "Instala JADX: python -m rea_automator setup-jadx",
        FAMILY_MANAGED: "Instala ilspycmd: dotnet tool install -g ilspycmd",
        FAMILY_JS: "Instala asar: npm install -g @electron/asar",
        FAMILY_NATIVE: "Instala Ghidra y PyGhidra (ver scripts/setup_tools.sh)",
    }
    return hints.get(family, "")


def _extract_one(args: tuple) -> dict:
    """Worker para ProcessPoolExecutor."""
    target_str, out_dir, family_override, no_zip, skip_if_exists = args
    target_path = Path(target_str)
    out_path = Path(out_dir)

    # Skip si ya existe y tiene contenido
    marker = out_path / f"{target_path.stem}.done"
    if skip_if_exists and marker.exists():
        return {"target": str(target_path), "ok": True, "cached": True}

    settings = load_settings(out_dir=out_path)
    family = family_override or _detect_family(target_path)

    if family is None:
        return {"target": str(target_path), "ok": False, "error": "tipo no reconocido"}

    try:
        result: DecompileResult = decompile_target(
            target_path, settings, family=family, no_zip=no_zip
        )
    except CommandNotFoundError as exc:
        return {
            "target": str(target_path),
            "ok": False,
            "error": f"herramienta no encontrada: {exc.argv0}",
            "hint": _hint_for_family(family),
        }
    except Exception as exc:  # noqa: BLE001
        return {"target": str(target_path), "ok": False, "error": str(exc)}

    if not result.ok_ish():
        return {
            "target": str(target_path),
            "ok": False,
            "status": result.status,
            "error": result.error,
            "hint": _hint_for_family(family),
        }

    # Copiar ZIP si se generó y se pidió
    final_zip = None
    if not no_zip and result.zip_path:
        src_zip = Path(result.zip_path)
        final_zip = out_path / f"{target_path.stem}-codigo.zip"
        shutil.copy2(src_zip, final_zip)

    final_dir = None
    if result.out_dir:
        src_dir = Path(result.out_dir)
        final_dir = out_path / f"{target_path.stem}-fuente"
        if final_dir.exists():
            shutil.rmtree(final_dir)
        shutil.copytree(src_dir, final_dir, symlinks=False)

    # Marcar como hecho para cache
    marker.write_text(json.dumps({"ok": True, "family": family}), encoding="utf-8")

    return {
        "target": str(target_path),
        "ok": True,
        "family": family,
        "zip": str(final_zip) if final_zip else None,
        "directorio": str(final_dir) if final_dir else None,
        "archivos": result.file_count,
        "estado": result.status,
    }


def extract(
    target: str | Path,
    out_dir: str | Path = "extraccion",
    *,
    family: Optional[str] = None,
    jobs: int = 1,
    no_zip: bool = False,
    skip_if_exists: bool = False,
) -> dict:
    target_path = Path(target)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Si es carpeta, procesar hijos en paralelo
    if target_path.is_dir():
        files = [p for p in sorted(target_path.iterdir()) if p.is_file()]
        if not files:
            return {"ok": False, "error": "la carpeta está vacía"}

        if jobs == 1:
            results = [_extract_one((str(f), str(out_path), family, no_zip, skip_if_exists)) for f in files]
        else:
            args = [(str(f), str(out_path), family, no_zip, skip_if_exists) for f in files]
            results = []
            with ProcessPoolExecutor(max_workers=jobs) as ex:
                futs = [ex.submit(_extract_one, a) for a in args]
                for fut in as_completed(futs):
                    results.append(fut.result())

        ok = sum(1 for r in results if r["ok"])
        fail = len(results) - ok
        return {
            "ok": fail == 0,
            "batch": True,
            "total": len(results),
            "ok": ok,
            "failed": fail,
            "results": results,
        }

    # Un solo archivo
    return _extract_one((str(target_path), str(out_path), family, no_zip, skip_if_exists))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea_automator extract",
        description="Extrae código fuente de APK y aplicaciones de PC.",
    )
    p.add_argument("target", help="Archivo o carpeta a descompilar.")
    p.add_argument("--out", default="extraccion", help="Carpeta de destino.")
    p.add_argument("--family", help="Forzar familia (android, managed, js, native).")
    p.add_argument("--jobs", type=int, default=1, help="Procesos en paralelo (para carpetas).")
    p.add_argument("--no-zip", action="store_true", help="No crear ZIP, solo carpeta fuente.")
    p.add_argument("--skip-if-exists", action="store_true", help="Saltar si ya hay salida previa.")
    args = p.parse_args(argv)

    res = extract(
        args.target,
        args.out,
        family=args.family,
        jobs=args.jobs,
        no_zip=args.no_zip,
        skip_if_exists=args.skip_if_exists,
    )

    if res.get("batch"):
        print(f"Procesados: {res['ok']} OK / {res['failed']} falló de {res['total']}")
        for r in res["results"]:
            if not r["ok"]:
                print(f"  ERROR {r['target']}: {r.get('error')}", file=sys.stderr)
        return 0 if res["failed"] == 0 else 1

    if not res["ok"]:
        print(f"ERROR: {res['error']}", file=sys.stderr)
        if res.get("hint"):
            print(f"Pista: {res['hint']}", file=sys.stderr)
        return 1

    print(f"OK — familia: {res['family']}")
    print(f"Estado: {res['estado']}")
    print(f"Archivos: {res['archivos']}")
    if res["directorio"]:
        print(f"Código: {res['directorio']}")
    if res["zip"]:
        print(f"ZIP: {res['zip']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())