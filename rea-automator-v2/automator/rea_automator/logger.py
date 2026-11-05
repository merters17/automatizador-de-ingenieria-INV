"""Configuración de logging y rotación para rea-automator."""
from __future__ import annotations

import glob
import logging
import os
import shutil
from pathlib import Path


def setup_logger(name: str, log_file: str | Path, level: int = logging.INFO) -> logging.Logger:
    """Configura un logger que escribe en archivo con formato timestamp : nivel : mensaje."""
    formatter = logging.Formatter("%(asctime)s : %(levelname)s : %(message)s")
    file_handler = logging.FileHandler(str(log_file), mode="a", encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(file_handler)
    return logger


def logrotate(log_dir: str | Path = "logs", max_logs: int = 5) -> str:
    """Rota los archivos de log en `log_dir`.

    Renombra los existentes (log_0.txt -> log_1.txt, ...), crea un
    log_0.txt vacío y elimina los que superen `max_logs`.
    Devuelve la ruta del nuevo archivo de log.
    """
    log_dir = Path(log_dir)
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)

    log_files = sorted(glob.glob(str(log_dir / "log_*.txt")))
    for i, log_file in enumerate(reversed(log_files), start=1):
        new_name = log_dir / f"log_{i}.txt"
        shutil.move(log_file, new_name)

    new_log_file = log_dir / "log_0.txt"
    new_log_file.touch()

    log_files = sorted(glob.glob(str(log_dir / "log_*.txt")))
    for log_file in log_files[max_logs:]:
        os.remove(log_file)

    return str(new_log_file)