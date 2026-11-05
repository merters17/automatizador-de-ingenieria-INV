"""Resultado tipado de un análisis. Cada campo es observado o explícitamente desconocido."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

STATUSES = (
    "ok",                  # rea terminó con código 0 y JSON válido
    "failed",              # rea terminó con error reportado (código 1, envoltorio de error)
    "signaled",            # terminó por señal (código 128+N o negativo)
    "timeout",             # se mató por exceder el timeout
    "unparseable_output",  # código 0 pero stdout no es JSON válido (o está truncado)
    "family_mismatch",     # rea terminó bien pero el objetivo no es de la familia pedida
    "routing_error",       # no se pudo elegir familia
    "not_found",           # el objetivo no existe
    "command_not_found",   # argv[0] no existe / no es ejecutable (ENOENT, EACCES, etc.)
)


@dataclass
class AnalysisResult:
    target: str
    status: str
    family: str | None = None
    route_reasons: list[str] = field(default_factory=list)
    argv: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_s: float | None = None
    evidence: Any = None          # JSON de rea cuando status == ok
    error: Any = None             # envoltorio de error de rea o detalle del automatizador
    progress_events: int = 0
    last_progress: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    unknowns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"estado desconocido: {self.status}")

    def to_dict(self) -> dict:
        return asdict(self)

    def write(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "result.json"
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return path
