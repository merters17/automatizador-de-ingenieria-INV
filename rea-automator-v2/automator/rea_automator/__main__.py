"""CLI del automatizador: `python -m rea_automator {route,analyze,batch,decompile,pipeline,
setup-jadx,check-jadx,verify-jadx,extract} ...`."""
from __future__ import annotations
import argparse
import json
import sys
from .analyzer import analyze_target
from .batch import run_batch
from .config import ConfigError, load_settings
from .decompile import decompile_target
from .jadx_tool import JadxInstallError, check_jadx, install_jadx
from .pipeline import run_pipeline
from .routing import FAMILIES, RoutingError, route
from .verify import verify_apk


def _log(message: str) -> None:
    """Mensajes de progreso a stderr, para no mezclarlos con el JSON."""
    print(message, file=sys.stderr, flush=True)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rea_automator", description="Automatiza la CLI de rea (sin MCP).")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("route", help="Muestra la familia elegida, sin ejecutar nada.")
    r.add_argument("target")

    a = sub.add_parser("analyze", help="Analiza un objetivo con la CLI de rea.")
    a.add_argument("target")
    a.add_argument("--family", choices=FAMILIES, help="Fuerza la familia y omite el enrutamiento.")
    a.add_argument("--out", default="automator-results")
    a.add_argument("--timeout", type=float, default=None)

    b = sub.add_parser("batch", help="Analiza cada hijo de un directorio.")
    b.add_argument("input_dir")
    b.add_argument("--out", default="automator-results")
    b.add_argument("--timeout", type=float, default=None)

    d = sub.add_parser(
        "decompile",
        help="Descompilación MASIVA: vuelca TODO el objetivo a un .zip (jadx/ilspycmd/asar/ghidra, sin pasar por rea).",
    )
    d.add_argument("target")
    d.add_argument("--family", choices=FAMILIES, help="Fuerza la familia y omite el enrutamiento.")
    d.add_argument("--out", default="automator-results")
    d.add_argument("--timeout", type=float, default=None)
    d.add_argument("--timeout-per-func", type=int, default=60, help="Timeout de decompilación por función (Ghidra).")
    d.add_argument("--combined", action="store_true", help="Genera all_functions.c con todo el código (Ghidra).")
    d.add_argument("--include", action="append", default=[], help="Solo exporta funciones cuyo nombre coincida con esta regex (Ghidra).")
    d.add_argument("--exclude", action="append", default=[], help="Omite funciones cuyo nombre coincida con esta regex (Ghidra).")
    d.add_argument("--resume", action="store_true", help="Reutiliza artefactos de una corrida previa si son válidos.")
    d.add_argument("--force-export", action="store_true", help="Ignora cualquier salida previa y reconstruye todo.")
    d.add_argument("--no-cache", action="store_true", help="No usa ni escribe caché de análisis Ghidra.")
    d.add_argument("--cache-dir", default=None, help="Directorio personalizado para el caché de proyectos Ghidra.")

    pl = sub.add_parser(
        "pipeline",
        help="Flujo completo: entrega un .zip y obtiene UN .zip con todo descompilado + report.json.",
    )
    pl.add_argument("input", help="Archivo .zip (o carpeta) a descompilar.")
    pl.add_argument("--out", default="automator-results", help="Carpeta donde se escribe el zip final.")
    pl.add_argument("--timeout", type=float, default=None, help="Timeout por cada archivo binario.")
    pl.add_argument(
        "--sin-originales",
        action="store_true",
        help="No incluir en el zip final los archivos no binarios (solo código descompilado + report.json).",
    )

    sj = sub.add_parser(
        "setup-jadx",
        help="Prepara JADX en tool/jadx/ (versión y SHA-256 fijados) y comprueba que funciona desde esa ruta.",
    )
    sj.add_argument("--force", action="store_true", help="Reinstala aunque ya haya un JADX que funcione.")
    sj.add_argument(
        "--jadx-zip",
        help="Instala desde un jadx-<versión>.zip ya descargado (sin red). Su SHA-256 se verifica igual.",
    )

    sub.add_parser(
        "check-jadx",
        help="Comprueba, sin instalar nada, que tool/jadx/bin/jadx funciona desde esa ruta.",
    )

    vj = sub.add_parser(
        "verify-jadx",
        help="Prueba de aceptación: prepara JADX, lo comprueba, ejecuta el APK con el pipeline y escribe el informe.",
    )
    vj.add_argument("apk", help="Archivo .apk a descompilar.")
    vj.add_argument("--out", default="automator-results", help="Carpeta de resultados (zip + informe .json/.md).")
    vj.add_argument("--timeout", type=float, default=None, help="Timeout de JADX sobre el APK.")
    vj.add_argument(
        "--no-install",
        action="store_true",
        help="No descarga ni instala JADX: solo comprueba lo que haya en tool/jadx/.",
    )
    vj.add_argument("--jadx-zip", help="jadx-<versión>.zip local para instalar sin red (se verifica su SHA-256).")

    ex = sub.add_parser(
        "extract",
        help="Extrae código fuente de un archivo (APK, .NET, Electron, nativo).",
    )
    ex.add_argument("target", help="Archivo a descompilar (APK, .exe/.dll, .asar, binario nativo).")
    ex.add_argument("--out", default="extraccion", help="Carpeta de destino.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "route":
        try:
            chosen = route(args.target)
        except RoutingError as err:
            print(json.dumps({"code": err.code, "message": err.message, "candidates": list(err.candidates)}, ensure_ascii=False, indent=2))
            return 1
        print(json.dumps(chosen.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "setup-jadx":
        try:
            installed = install_jadx(zip_path=args.jadx_zip, force=args.force, log=_log)
        except JadxInstallError as err:
            print(json.dumps({"ok": False, "error": err.to_dict()}, ensure_ascii=False, indent=2))
            return 1
        print(json.dumps(installed.to_dict(), ensure_ascii=False, indent=2))
        return 0 if installed.ok else 1

    if args.cmd == "check-jadx":
        checked = check_jadx()
        print(json.dumps(checked.to_dict(), ensure_ascii=False, indent=2))
        return 0 if checked.ok else 1

    if args.cmd == "extract":
        from .extract import main as extract_main
        return extract_main([args.target, "--out", args.out])

    try:
        settings = load_settings(out_dir=args.out, timeout_s=args.timeout)
    except ConfigError as err:
        print(f"error de configuración: {err}", file=sys.stderr)
        return 2

    if args.cmd == "analyze":
        res = analyze_target(args.target, settings, family=args.family)
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return 0 if res.status == "ok" else 1

    if args.cmd == "decompile":
        res = decompile_target(
            args.target,
            settings,
            family=args.family,
            timeout_per_func=args.timeout_per_func,
            combined=args.combined,
            include=tuple(args.include),
            exclude=tuple(args.exclude),
            resume=args.resume,
            force_export=args.force_export,
            cache_enabled=not args.no_cache,
            cache_dir=args.cache_dir,
        )
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return 0 if res.status in ("ok", "partial") else 1

    if args.cmd == "pipeline":
        res = run_pipeline(args.input, settings, keep_originals=not args.sin_originales)
        print(json.dumps(res.to_dict(), ensure_ascii=False, indent=2))
        return 0 if res.status == "ok" else 1

    if args.cmd == "verify-jadx":
        report = verify_apk(
            args.apk,
            settings,
            install=not args.no_install,
            jadx_zip=args.jadx_zip,
            log=_log,
        )
        print(report.markdown)
        return 0 if report.passed else 1

    summary = run_batch(args.input_dir, settings)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if set(summary["by_status"]) <= {"ok"} else 1


def _entry() -> int:
    try:
        return main()
    except BrokenPipeError:
        sys.stdout = open(__import__("os").devnull, "w")
        return 1


if __name__ == "__main__":
    sys.exit(_entry())