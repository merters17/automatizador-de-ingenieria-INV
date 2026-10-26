"""Orquesta: enrutar -> construir argv -> ejecutar acotado -> interpretar resultado."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .adapters.rea_cli import build_argv
from .config import Settings
from .result import AnalysisResult
from .routing import FAMILIES, FAMILY_JS, FAMILY_MANAGED, Route, RoutingError, route
from .runner import CommandNotFoundError, run_bounded

_PROGRESS_PREFIX = '{"rea_progress"'


def _slug(path: Path) -> str:
    digest = hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()[:10]
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", path.name)[:80] or "target"
    return f"{safe}-{digest}"


def _progress(stderr_path: Path) -> tuple[int, str | None]:
    count, last = 0, None
    with open(stderr_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith(_PROGRESS_PREFIX):
                try:
                    msg = json.loads(line)["rea_progress"].get("message")
                except (ValueError, KeyError, AttributeError):
                    continue
                count += 1
                last = msg
    return count, last


def _domain_check(family: str, payload: dict, result: AnalysisResult) -> None:
    """Lee el veredicto de dominio que rea devuelve dentro de un resultado exitoso.

    rea puede terminar bien y aun así informar que el objetivo no es lo que se pidió
    (p. ej. PE nativo analizado como managed devuelve classification.status
    'not-managed'). Eso no es un `ok` para el automatizador.
    """
    if family == FAMILY_MANAGED:
        cls = (payload.get("normalized_result") or {}).get("classification") or {}
        verdict = cls.get("status")
        if verdict != "managed":
            result.status = "family_mismatch"
            result.unknowns.append(f"rea_reports:{verdict or 'missing'}")
    elif family == FAMILY_JS:
        stats = ((payload.get("summary") or {}).get("statistics") or {})
        if stats.get("relevant_files") == 0:
            result.unknowns.append("no_relevant_files")


def _load_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except (OSError, ValueError) as exc:
        return None, str(exc)


def analyze_target(
    target: str | Path,
    settings: Settings,
    *,
    family: str | None = None,
) -> AnalysisResult:
    """Analiza un objetivo y escribe `result.json` en su carpeta de salida."""
    result = _analyze(Path(target), settings, family)
    run_dir = settings.out_dir / _slug(Path(target))
    result.write(run_dir)
    return result


def _analyze(
    target_path: Path,
    settings: Settings,
    family: str | None,
) -> AnalysisResult:
    result = AnalysisResult(target=str(target_path), status="failed")

    if not target_path.exists():
        result.status = "not_found"
        result.unknowns.append("target_missing")
        return result

    if family is not None:
        if family not in FAMILIES:
            raise ValueError(f"familia desconocida: {family}")
        chosen = Route(family, ("override",))
    else:
        try:
            chosen = route(target_path)
        except RoutingError as err:
            result.status = "routing_error"
            result.error = {"code": err.code, "message": err.message, "candidates": list(err.candidates)}
            result.unknowns.append(f"routing:{err.code}")
            return result

    result.family = chosen.family
    result.route_reasons = list(chosen.reasons)

    run_dir = settings.out_dir / _slug(target_path)
    stdout_path = run_dir / "stdout.json"
    stderr_path = run_dir / "stderr.log"
    argv = build_argv(settings, chosen.family, str(target_path.resolve()))
    result.argv = list(argv)

    try:
        raw = run_bounded(
            argv,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_s=settings.timeout_s,
            max_stdout_bytes=settings.max_stdout_bytes,
            max_stderr_bytes=settings.max_stderr_bytes,
        )
    except CommandNotFoundError as exc:
        result.status = "command_not_found"
        result.error = {"argv0": argv[0], "message": str(exc.original)}
        result.unknowns.append("command_not_found")
        return result
    result.exit_code = raw.returncode
    result.duration_s = raw.duration_s
    result.stdout_path = str(stdout_path)
    result.stderr_path = str(stderr_path)
    result.progress_events, result.last_progress = _progress(stderr_path)
    if raw.stderr_truncated:
        result.unknowns.append("stderr_truncated")

    if raw.timed_out:
        result.status = "timeout"
        result.unknowns.append("timeout_killed")
        return result

    rc = raw.returncode
    payload, parse_err = _load_json(stdout_path)

    if rc == 0:
        if raw.stdout_truncated:
            result.status = "unparseable_output"
            result.unknowns.append("stdout_truncated")
        elif parse_err is not None:
            result.status = "unparseable_output"
            result.unknowns.append("stdout_not_json")
        elif isinstance(payload, dict) and "error" in payload:
            # Código 0 con envoltorio de error: no se confía en el código, se reporta como fallo.
            result.status = "failed"
            result.error = payload
            result.unknowns.append("exit0_with_error_envelope")
        else:
            result.status = "ok"
            result.evidence = payload
            _domain_check(chosen.family, payload, result)
        return result

    if rc is not None and (rc < 0 or rc > 128):
        result.status = "signaled"
        signum = -rc if rc < 0 else rc - 128
        result.error = {"signal": signum}
        return result

    # rc == 1 o código no documentado (2..128)
    result.status = "failed"
    if parse_err is None and isinstance(payload, dict) and "error" in payload:
        result.error = payload
    else:
        result.error = {"message": "sin envoltorio de error JSON"}
        result.unknowns.append("error_envelope_missing")
    if rc != 1:
        result.unknowns.append(f"exit_code_unexplained:{rc}")
    return result
