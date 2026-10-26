"""Regresión: dos ejecuciones sobre el mismo objetivo no deben borrarse entre sí.

Antes, `_run_dir_for()` borraba cualquier carpeta con el mismo prefijo antes de
crear la suya, así que una segunda llamada eliminaba una ejecución activa.
"""

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from rea_automator import decompile
from rea_automator.decompile import (
    STALE_RUN_AGE_S,
    _create_run_dir,
    cleanup_stale_runs,
)

needs_fcntl = pytest.mark.skipif(decompile.fcntl is None, reason="requiere fcntl (POSIX)")


def _envejecer(path: Path, age_s: float = 10 * STALE_RUN_AGE_S) -> None:
    viejo = time.time() - age_s
    os.utime(path, (viejo, viejo))


@pytest.fixture
def target(tmp_path):
    t = tmp_path / "app.apk"
    t.write_bytes(b"x")
    return t


@needs_fcntl
def test_segunda_ejecucion_no_borra_la_primera_activa(tmp_path, target):
    out = tmp_path / "out"
    primera, lock1 = _create_run_dir(out, target)
    marcador = primera / "EJECUCION_ACTIVA.marker"
    marcador.write_text("sigo corriendo")
    _envejecer(primera)  # solo el bloqueo debe protegerla

    segunda, lock2 = _create_run_dir(out, target)
    try:
        assert primera.exists()
        assert marcador.exists()
        assert segunda != primera
    finally:
        lock1.close()
        lock2.close()


@needs_fcntl
def test_ejecucion_bloqueada_por_otro_proceso_no_se_limpia(tmp_path, target):
    out = tmp_path / "out"
    run_dir, _ = _create_run_dir(out, target)  # bloqueo tomado por este proceso
    _envejecer(run_dir)
    # Un proceso hijo intenta limpiar: no debe poder tomar el bloqueo.
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
        from pathlib import Path
        from rea_automator.decompile import cleanup_stale_runs
        print(cleanup_stale_runs(Path({str(out)!r})))
    """)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "0"
    assert run_dir.exists()


@needs_fcntl
def test_ejecucion_vieja_y_libre_si_se_limpia(tmp_path, target):
    out = tmp_path / "out"
    run_dir, lock = _create_run_dir(out, target)
    lock.close()  # terminó: ya no hay proceso que la use
    _envejecer(run_dir)

    assert cleanup_stale_runs(out) == 1
    assert not run_dir.exists()


@needs_fcntl
def test_ejecucion_reciente_no_se_limpia_aunque_este_libre(tmp_path, target):
    out = tmp_path / "out"
    run_dir, lock = _create_run_dir(out, target)
    lock.close()
    # No envejecida: podría estar recién creada por otro proceso.
    assert cleanup_stale_runs(out) == 0
    assert run_dir.exists()


@needs_fcntl
def test_carpeta_sin_lock_nunca_se_borra(tmp_path):
    out = tmp_path / "out"
    datos_del_usuario = out / "mis_resultados"
    datos_del_usuario.mkdir(parents=True)
    (datos_del_usuario / "importante.txt").write_text("no es mío")
    _envejecer(datos_del_usuario)

    assert cleanup_stale_runs(out) == 0
    assert (datos_del_usuario / "importante.txt").exists()


@needs_fcntl
def test_archivos_sueltos_en_out_no_se_tocan(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    suelto = out / "summary.json"
    suelto.write_text("{}")
    _envejecer(suelto)
    assert cleanup_stale_runs(out) == 0
    assert suelto.exists()


def test_sin_fcntl_no_se_borra_nada(tmp_path, target, monkeypatch):
    # Simula Windows: sin fcntl no hay forma de saber si una ejecución está activa.
    out = tmp_path / "out"
    run_dir, lock = _create_run_dir(out, target)
    lock.close()
    _envejecer(run_dir)
    monkeypatch.setattr(decompile, "fcntl", None)
    assert cleanup_stale_runs(out) == 0
    assert run_dir.exists()
