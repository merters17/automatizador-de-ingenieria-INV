"""Prueba de aceptación de la v2: prepara JADX, lo comprueba desde su ruta, ejecuta un APK con
el propio pipeline del proyecto y escribe un informe que confirma (o no) la descompilación.

Qué significa APROBADO
----------------------
El veredicto es APROBADO solo si se cumplen TODOS los criterios de `CRITERIA`. Ninguno se da
por bueno por defecto: un criterio que no se pudo evaluar cuenta como no cumplido.

  1. El APK es un APK de verdad (extensión .apk, zip, con classes*.dex legibles).
  2. JADX está en `tool/jadx/` y funciona desde esa ruta: `--version` y una descompilación
     real de una clase de prueba (ver `jadx_tool.check_jadx`).
  3. El pipeline del proyecto (`pipeline.run_pipeline`, el mismo código que `python -m
     rea_automator pipeline`) procesó el APK con ESE JADX y JADX terminó con código 0
     (limpio) o 3 (guardó el código con errores). Los códigos 1 y 2 no guardan resultado útil.
  4. El zip de resultado contiene archivos `.java` con declaraciones de tipo reales
     (comentarios descartados), y al menos la mitad de las clases del APK tiene un `.java`
     propio (umbral mínimo de cordura; el dato exacto va en el informe).
  5. Los números que informa el pipeline coinciden con lo que de verdad hay en el zip.

Un resultado con errores de JADX (código 3) sigue siendo `partial` para el pipeline —es la
regla de v1— pero se aprueba si cumple lo anterior, y los errores quedan en las advertencias.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .config import PROJECT_JADX_DIR, Settings
from .dexinfo import DexScan, compare_with_java_files, scan_apk
from .jadx_tool import MIN_JAVA_MAJOR, JadxCheck, JadxInstallError, check_jadx, install_jadx, sha256_file
from .pipeline import run_pipeline
from .routing import FAMILY_ANDROID

VERDICT_PASS = "APROBADO"
VERDICT_FAIL = "NO APROBADO"

MIN_COVERAGE = 0.5
VALID_JADX_EXIT_CODES = (0, 3)
MAX_JAVA_FILE_BYTES = 64 * 1024 * 1024

CRITERIA = {
    "apk_valido": "El archivo es un APK (.apk, zip) con al menos un classes*.dex legible",
    "launcher_existe": "JADX está en la ruta del proyecto (tool/jadx/bin/jadx)",
    "launcher_ejecutable": "El lanzador de JADX es ejecutable",
    "jar_existe": "Existe el jar de JADX en tool/jadx/lib/",
    "java_disponible": f"Hay un Java {MIN_JAVA_MAJOR} o superior",
    "version_desde_la_ruta_del_proyecto": "`jadx --version` funciona ejecutado desde esa ruta",
    "descompila_clase_de_prueba": "JADX descompila una clase de prueba y recupera su código Java",
    "pipeline_usa_el_jadx_del_proyecto": "El pipeline ejecutó exactamente ese JADX (no otro del PATH)",
    "pipeline_proceso_el_apk": "El pipeline del proyecto procesó el APK como paquete Android (ok o partial)",
    "jadx_codigo_de_salida_valido": "JADX terminó con código 0 (limpio) o 3 (guardó el código con errores)",
    "codigo_java_recuperado": "El zip de resultado contiene archivos .java con declaraciones de clase",
    "cobertura_de_clases_del_apk": f"Al menos el {int(MIN_COVERAGE * 100)} % de las clases del APK tiene un .java propio",
    "informe_del_pipeline_coincide_con_el_zip": "Los números del informe del pipeline coinciden con lo que hay en el zip",
}


@dataclass
class Criterion:
    id: str
    title: str
    ok: bool
    detail: str
    evaluated: bool = True


# ── análisis del zip de resultado ────────────────────────────────────────────

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_TYPE_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:public|protected|private|abstract|final|static|strictfp|sealed|non-sealed)[ \t]+)*"
    r"(?:class|interface|enum|@interface|record)[ \t]+[A-Za-z_$][\w$]*"
)


_FLOW_RE = re.compile(r"\b(?:if|for|while|switch|return)\b")


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", text))


def has_type_declaration(text: str) -> bool:
    """True si, quitando comentarios, hay una declaración `class|interface|enum|record X`."""
    return bool(_TYPE_DECL_RE.search(_strip_comments(text)))


@dataclass
class ZipAnalysis:
    prefix: str
    files_total: int = 0
    java_files: int = 0
    java_with_declaration: int = 0
    java_too_large_to_read: int = 0
    files_with_jadx_error_marker: int = 0
    files_with_jadx_warn_marker: int = 0
    java_paths: set[str] = field(default_factory=set)  # relativas a sources/
    sample: dict | None = None
    report: dict | None = None
    error: str | None = None


def analyze_output_zip(zip_path: str | Path, apk_rel: str) -> ZipAnalysis:
    """Lee el zip del pipeline y cuenta, archivo por archivo, lo que hay de verdad bajo
    `decompilado/<apk>/`. No usa ningún número del pipeline: es la comprobación independiente."""
    prefix = f"decompilado/{apk_rel}/"
    sources_prefix = prefix + "sources/"
    an = ZipAnalysis(prefix=prefix)
    with zipfile.ZipFile(zip_path) as zf:
        try:
            an.report = json.loads(zf.read("report.json"))
        except (KeyError, ValueError) as exc:
            an.error = f"report.json del zip ilegible: {exc}"

        java_names: list[str] = []
        for info in zf.infolist():
            if info.is_dir() or not info.filename.startswith(prefix):
                continue
            an.files_total += 1
            if info.filename.endswith(".java"):
                java_names.append(info.filename)
        an.java_files = len(java_names)

        per_dir = Counter(name.rpartition("/")[0] for name in java_names)
        # directorio -> (puntuación, nombre, primeras líneas, total de líneas)
        candidates: dict[str, tuple[int, str, list[str], int]] = {}
        for name in sorted(java_names):
            relative = name[len(sources_prefix):] if name.startswith(sources_prefix) else name[len(prefix):]
            an.java_paths.add(relative)
            if zf.getinfo(name).file_size > MAX_JAVA_FILE_BYTES:
                an.java_too_large_to_read += 1
                continue
            text = zf.read(name).decode("utf-8", errors="replace")
            if "JADX ERROR" in text:
                an.files_with_jadx_error_marker += 1
            if "JADX WARN" in text:
                an.files_with_jadx_warn_marker += 1
            stripped = _strip_comments(text)
            if not _TYPE_DECL_RE.search(stripped):
                continue
            an.java_with_declaration += 1
            lines = text.splitlines()
            if 30 <= len(lines) <= 120 and "{" in stripped:
                directory = name.rpartition("/")[0]
                score = len(_FLOW_RE.findall(stripped))
                # Estrictamente mayor: en un empate se queda el primero en orden alfabético.
                if score > candidates.get(directory, (-1,))[0]:
                    candidates[directory] = (score, name, lines[:40], len(lines))

        # Muestra determinista: del paquete con más clases recuperadas, el archivo legible
        # (30-120 líneas) con más lógica de control de flujo (if/for/while/switch/return).
        for directory, _count in sorted(per_dir.items(), key=lambda kv: (-kv[1], kv[0])):
            if directory in candidates:
                _score, name, lines, total = candidates[directory]
                an.sample = {"file": name[len(prefix):], "shown_lines": len(lines), "total_lines": total, "lines": lines}
                break
    return an


# ── informe ──────────────────────────────────────────────────────────────────

@dataclass
class VerificationReport:
    verdict: str
    data: dict
    markdown: str
    json_path: Path | None = None
    md_path: Path | None = None

    @property
    def passed(self) -> bool:
        return self.verdict == VERDICT_PASS


def _fmt_int(value: int | None) -> str:
    return "—" if value is None else f"{value:,}".replace(",", ".")


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(data: dict) -> str:
    """Renderiza el informe a partir de `data` (el mismo dict que se guarda como JSON)."""
    apk = data["apk"]
    jadx = data.get("jadx") or {}
    pipe = data.get("pipeline") or {}
    dec = data.get("decompilation") or {}
    dex = dec.get("dex") or {}
    passed = data["verdict"] == VERDICT_PASS

    out: list[str] = []
    out.append(f"# Informe de descompilación — {apk['name']}")
    out.append("")
    out.append(f"**Veredicto: {data['verdict']}**")
    out.append("")
    if passed:
        out.append(
            "JADX funciona desde `tool/jadx/`, el pipeline del proyecto descompiló el APK y el resultado "
            "contiene código Java recuperado."
        )
    else:
        failed = [c["id"] for c in data["criteria"] if not c["ok"]]
        out.append(f"No se cumplieron estos criterios: {', '.join(f'`{c}`' for c in failed)}.")
    out.append("")
    out.append(f"Generado: {data['generated_at']} · rea-automator {data['rea_automator_version']}")
    out.append("")
    out.append("## Resumen")
    out.append("")
    out.append("| Dato | Valor |")
    out.append("|---|---|")
    out.append(f"| APK | `{_cell(apk['name'])}` · {_fmt_int(apk.get('size_bytes'))} bytes · SHA-256 `{apk.get('sha256', '—')}` |")
    out.append(f"| JADX | versión {_cell(jadx.get('version') or '—')} · `{_cell(jadx.get('launcher', '—'))}` |")
    out.append(f"| Jar de JADX (SHA-256) | `{jadx.get('jar_sha256') or '—'}` |")
    out.append(f"| Java | {_cell((jadx.get('java') or {}).get('detail') or '—')} |")
    out.append(f"| Estado del pipeline | `{pipe.get('status', '—')}` |")
    out.append(
        f"| Código de salida de JADX | {dec.get('jadx_exit_code', '—')} — {_cell(dec.get('jadx_exit_meaning', '—'))} |"
    )
    out.append(f"| Errores que informó JADX | {_fmt_int(dec.get('jadx_errors'))} |")
    out.append(
        f"| Archivos `.java` recuperados | {_fmt_int(dec.get('java_files'))} "
        f"(con declaración de tipo: {_fmt_int(dec.get('java_files_with_type_declaration'))}) |"
    )
    if dex:
        out.append(
            f"| Clases del APK (DEX) | {_fmt_int(dex.get('classes_in_apk'))} · con `.java` propio: "
            f"{_fmt_int(dex.get('with_own_java_file'))} ({dex.get('coverage_pct')} %) |"
        )
    out.append(f"| Zip de resultado | `{_cell(pipe.get('output_zip') or '—')}` |")
    out.append("")
    out.append("## Criterios de aprobación")
    out.append("")
    out.append("| # | Criterio | Resultado | Detalle |")
    out.append("|---|---|---|---|")
    for index, crit in enumerate(data["criteria"], start=1):
        mark = "✅ cumple" if crit["ok"] else ("❌ no cumple" if crit["evaluated"] else "⏭ no evaluado")
        out.append(f"| {index} | {_cell(crit['title'])} | {mark} | {_cell(crit['detail'])} |")
    out.append("")
    if data["warnings"]:
        out.append("## Advertencias")
        out.append("")
        for warning in data["warnings"]:
            out.append(f"- {warning}")
        out.append("")
    sample = dec.get("sample")
    if sample:
        out.append("## Muestra de código Java recuperado")
        out.append("")
        out.append(
            f"Archivo `{sample['file']}` (primeras {sample['shown_lines']} de {sample['total_lines']} líneas), "
            "tal como está en el zip de resultado:"
        )
        out.append("")
        out.append("```java")
        out.extend(sample["lines"])
        out.append("```")
        out.append("")
    out.append("## Cómo reproducirlo")
    out.append("")
    out.append("```bash")
    out.append(f"python -m rea_automator verify-jadx {apk['name']} --out <carpeta-de-resultados>")
    out.append("```")
    out.append("")
    return "\n".join(out)


# ── la prueba ────────────────────────────────────────────────────────────────

def verify_apk(
    apk_path: str | Path,
    settings: Settings,
    *,
    out_dir: str | Path | None = None,
    jadx_dir: str | Path = PROJECT_JADX_DIR,
    install: bool = True,
    jadx_zip: str | Path | None = None,
    log: Callable[[str], None] | None = None,
) -> VerificationReport:
    """Ejecuta la prueba de aceptación sobre `apk_path` y escribe `<apk>-informe.json|md` en `out_dir`.

    `install=True` prepara JADX en `jadx_dir` si falta o no es la versión fijada (descarga con
    SHA-256 verificado, o `jadx_zip` local). `install=False` solo comprueba lo que haya.
    `jadx_dir` debe ser `<tool_dir>/jadx`. Un fallo de la prueba (JADX ausente, APK inválido,
    resultado vacío...) no lanza: queda como criterio no cumplido en el informe. Un error de
    programación sí debe verse como excepción.
    """
    log = log or (lambda _msg: None)
    apk = Path(apk_path)
    out_root = Path(out_dir) if out_dir is not None else settings.out_dir
    jadx_dir = Path(jadx_dir)
    launcher = jadx_dir / "bin" / "jadx"
    if install and jadx_dir.name != "jadx":
        raise ValueError(f"jadx_dir debe terminar en 'jadx' para poder instalarse; recibido: {jadx_dir}")

    criteria = {cid: Criterion(cid, title, False, "no evaluado", evaluated=False) for cid, title in CRITERIA.items()}
    warnings: list[str] = []

    def mark(cid: str, ok: bool, detail: str) -> None:
        crit = criteria[cid]
        crit.ok, crit.detail, crit.evaluated = bool(ok), detail, True

    # 1. El APK ----------------------------------------------------------------
    apk_info: dict = {"name": apk.name, "path": str(apk.resolve()) if apk.exists() else str(apk)}
    scan = DexScan()
    if not apk.is_file():
        mark("apk_valido", False, f"no existe el archivo {apk}")
    else:
        apk_info["size_bytes"] = apk.stat().st_size
        apk_info["sha256"] = sha256_file(apk)
        is_zip = zipfile.is_zipfile(apk)
        if is_zip:
            scan = scan_apk(apk)
        apk_info["dex_files"] = dict(scan.dex_files)
        apk_info["dex_classes_total"] = len(scan.classes)
        if scan.errors:
            warnings.extend(f"DEX: {e}" for e in scan.errors)
        problems = []
        if apk.suffix.lower() != ".apk":
            problems.append("el nombre debe terminar en .apk (el enrutamiento decide por extensión y bytes)")
        if not is_zip:
            problems.append("no es un zip")
        elif not scan.dex_files:
            problems.append("no se pudo leer ningún classes*.dex")
        mark(
            "apk_valido",
            not problems,
            "; ".join(problems)
            or f"{len(scan.dex_files)} archivo(s) DEX con {len(scan.classes)} clases en total ("
            + ", ".join(f"{name}: {count}" for name, count in scan.dex_files.items())
            + ")",
        )

    # 2. JADX: preparar (opcional) y comprobar desde su ruta -----------------------
    install_data: dict | None = None
    check: JadxCheck | None = None
    if install:
        try:
            result = install_jadx(tool_dir=jadx_dir.parent, zip_path=jadx_zip, log=log)
            install_data = result.to_dict()
            check = result.check
            if result.status == "rolled_back":
                warnings.append("La instalación nueva no pasó la comprobación y se restauró la anterior.")
        except JadxInstallError as err:
            install_data = {"ok": False, "error": err.to_dict()}
            warnings.append(f"No se pudo preparar JADX ({err.code}): {err.message}")
            if err.hint:
                warnings.append(err.hint)
    if check is None:
        log(f"Comprobando JADX en {launcher} ...")
        check = check_jadx(jadx_dir)
    for step in check.steps:
        if step.name in criteria:
            mark(step.name, step.ok, step.detail)
    warnings.extend(check.warnings)

    # 3. Pipeline del proyecto sobre el APK ----------------------------------------
    pipeline_data: dict | None = None
    decompilation: dict | None = None
    can_run = check.ok and criteria["apk_valido"].ok
    if not can_run:
        log("No se ejecuta el pipeline: la comprobación de JADX o del APK falló.")
    else:
        used = Path(settings.jadx_argv[0]).resolve() if settings.jadx_argv else None
        same = used is not None and used == launcher.resolve()
        mark(
            "pipeline_usa_el_jadx_del_proyecto",
            same,
            f"el pipeline usa {settings.jadx_argv[0] if settings.jadx_argv else '—'}"
            + ("" if same else f", que no es {launcher}"),
        )
        log(f"Ejecutando el pipeline del proyecto sobre {apk.name} ...")
        result_pl = run_pipeline(apk, settings, out_dir=out_root)
        entry = next((e for e in result_pl.entries if e.path == apk.name), None)
        pipeline_data = {
            "status": result_pl.status,
            "cli_exit_code": 0 if result_pl.status == "ok" else 1,
            "output_zip": result_pl.output_zip,
            "decompiled_targets": result_pl.decompiled_targets,
            "partial_targets": result_pl.partial_targets,
            "failed_targets": result_pl.failed_targets,
            "skipped_files": result_pl.skipped_files,
            "copied_files": result_pl.copied_files,
            "error": result_pl.error,
            "entry": asdict(entry) if entry else None,
        }
        processed = bool(
            entry
            and entry.family == FAMILY_ANDROID
            and entry.decompile_status in ("ok", "partial")
            and entry.file_count > 0
            and result_pl.output_zip
        )
        if entry is None:
            mark("pipeline_proceso_el_apk", False, f"el pipeline no registró una entrada para {apk.name}: {result_pl.error}")
        else:
            mark(
                "pipeline_proceso_el_apk",
                processed,
                f"entrada {entry.path}: familia {entry.family}, estado {entry.decompile_status}, "
                f"{entry.file_count} archivos escritos, estado global {result_pl.status}",
            )

        jx = ((entry.details or {}).get("jadx") if entry else None) or {}
        exit_code = jx.get("exit_code")
        if exit_code is None:
            mark("jadx_codigo_de_salida_valido", False, "el resultado del pipeline no trae el código de salida de JADX")
        else:
            mark(
                "jadx_codigo_de_salida_valido",
                exit_code in VALID_JADX_EXIT_CODES,
                f"código {exit_code}: {jx.get('exit_meaning')}",
            )

        # 4. Análisis independiente del zip de resultado ---------------------------
        an: ZipAnalysis | None = None
        if processed and result_pl.output_zip:
            try:
                an = analyze_output_zip(result_pl.output_zip, apk.name)
            except (zipfile.BadZipFile, OSError) as exc:
                mark("codigo_java_recuperado", False, f"no se pudo leer el zip de resultado: {exc}")
        if an is not None:
            mark(
                "codigo_java_recuperado",
                an.java_with_declaration >= 1,
                f"{an.java_with_declaration} de {an.java_files} archivos .java contienen una declaración de "
                "clase, interfaz o enum (comentarios descartados)",
            )
            coverage = None
            if scan.classes:
                coverage = compare_with_java_files(scan.classes, an.java_paths)
                pct = round(100 * coverage.ratio, 1)
                mark(
                    "cobertura_de_clases_del_apk",
                    coverage.ratio >= MIN_COVERAGE,
                    f"{coverage.with_own_file} de {coverage.total} clases del APK tienen .java propio ({pct} %); "
                    f"mínimo {int(MIN_COVERAGE * 100)} %",
                )
                if coverage.without_own_file:
                    warnings.append(
                        f"{coverage.without_own_file} de {coverage.total} clases del APK no tienen un .java con su "
                        f"nombre: {coverage.without_own_file_synthetic} son sintéticas (ACC_SYNTHETIC) y "
                        f"{coverage.without_own_file_not_synthetic} no lo son (JADX renombra las de nombre reservado "
                        "como `do` o `if`)."
                    )
            else:
                mark("cobertura_de_clases_del_apk", False, "no se pudo leer ninguna clase del DEX del APK")

            problems = []
            if entry is not None:
                if entry.file_count != an.files_total:
                    problems.append(f"el pipeline dice {entry.file_count} archivos y el zip tiene {an.files_total}")
                if jx.get("java_files") is not None and jx["java_files"] != an.java_files:
                    problems.append(f"el pipeline dice {jx['java_files']} .java y el zip tiene {an.java_files}")
                rep_entry = next(
                    (e for e in (an.report or {}).get("entries", []) if e.get("path") == apk.name), None
                )
                if rep_entry is None:
                    problems.append("el report.json del zip no tiene la entrada del APK")
                else:
                    if rep_entry.get("file_count") != an.files_total:
                        problems.append(
                            f"el report.json del zip dice {rep_entry.get('file_count')} archivos y el zip tiene {an.files_total}"
                        )
                    if rep_entry.get("decompile_status") != entry.decompile_status:
                        problems.append("el estado del report.json del zip no coincide con el del pipeline")
            mark(
                "informe_del_pipeline_coincide_con_el_zip",
                not problems,
                "; ".join(problems)
                or f"{an.files_total} archivos y {an.java_files} .java: coinciden el pipeline, su report.json y el zip",
            )

            if an.java_too_large_to_read:
                warnings.append(f"{an.java_too_large_to_read} archivos .java superan {MAX_JAVA_FILE_BYTES} bytes y no se leyeron.")
            if entry is not None and entry.decompile_status == "partial":
                errors = jx.get("errors")
                warnings.append(
                    f"El estado del pipeline es «partial» porque JADX terminó con código {exit_code} "
                    f"({jx.get('exit_meaning')}) e informó {errors if errors is not None else 'un número no determinado de'} "
                    "errores: clases o métodos que no pudo reconstruir del todo y que quedan marcados en el propio "
                    "código con comentarios «JADX ERROR» / «JADX WARN». El resto del código sí se recuperó."
                )
            decompilation = {
                "jadx_exit_code": exit_code,
                "jadx_exit_meaning": jx.get("exit_meaning"),
                "jadx_errors": jx.get("errors"),
                "files_in_result": an.files_total,
                "java_files": an.java_files,
                "java_files_with_type_declaration": an.java_with_declaration,
                "files_with_jadx_error_marker": an.files_with_jadx_error_marker,
                "files_with_jadx_warn_marker": an.files_with_jadx_warn_marker,
                "dex": (
                    {**coverage.to_dict(), "dex_files": dict(scan.dex_files), "errors": list(scan.errors)}
                    if coverage is not None
                    else None
                ),
                "sample": an.sample,
            }
        if decompilation is not None:
            decompilation["confirmed"] = all(
                criteria[cid].ok
                for cid in ("pipeline_proceso_el_apk", "jadx_codigo_de_salida_valido", "codigo_java_recuperado")
            )

    # 5. Veredicto e informe ---------------------------------------------------------
    passed = all(c.ok for c in criteria.values())
    verdict = VERDICT_PASS if passed else VERDICT_FAIL
    stem = apk.stem or "apk"
    json_path = out_root / f"{stem}-informe.json"
    md_path = out_root / f"{stem}-informe.md"
    data = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rea_automator_version": __version__,
        "verdict": verdict,
        "passed": passed,
        "criteria": [asdict(c) for c in criteria.values()],
        "warnings": warnings,
        "apk": apk_info,
        "jadx": check.to_dict(),
        "install": install_data,
        "pipeline": pipeline_data,
        "decompilation": decompilation,
        "files": {
            "report_json": str(json_path),
            "report_md": str(md_path),
            "output_zip": (pipeline_data or {}).get("output_zip"),
        },
    }
    markdown = render_markdown(data)
    out_root.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    return VerificationReport(verdict=verdict, data=data, markdown=markdown, json_path=json_path, md_path=md_path)
