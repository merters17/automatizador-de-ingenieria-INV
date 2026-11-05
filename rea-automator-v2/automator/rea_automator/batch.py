"""Lote: analiza cada hijo de un directorio y escribe un resumen."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .analyzer import analyze_target
from .config import Settings


def run_batch(input_dir: str | Path, settings: Settings) -> dict:
    root = Path(input_dir)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    results = []
    for child in sorted(root.iterdir()):
        results.append(analyze_target(child, settings))
    summary = {
        "input": str(root),
        "total": len(results),
        "by_status": dict(Counter(r.status for r in results)),
        "targets": [{"target": r.target, "status": r.status, "family": r.family, "unknowns": r.unknowns} for r in results],
    }
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    (settings.out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary
