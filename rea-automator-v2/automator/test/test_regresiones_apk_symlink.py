"""Regresiones de dos defectos reales encontrados en la revisión del código:

1. Un .apk pasado directamente al pipeline se extraía como zip en vez de
   descompilarse con jadx; el pipeline reportaba `ok` sin haber descompilado nada.
2. `decompile` sobre una carpeta seguía enlaces simbólicos (shutil.copytree),
   así que contenido de fuera de la carpeta terminaba dentro del zip de salida.
"""

import sys
import zipfile
from pathlib import Path
from dataclasses import replace

import pytest

from rea_automator.config import load_settings
from rea_automator.decompile import decompile_target
from rea_automator.pipeline import run_pipeline

from .test_pipeline import FAKE_TOOL, _names


@pytest.fixture
def settings(tmp_path, monkeypatch):
    cmd = f"{sys.executable} {FAKE_TOOL}"
    monkeypatch.setenv("REA_AUTOMATOR_ILSPYCMD_CMD", cmd)
    monkeypatch.setenv("REA_AUTOMATOR_GHIDRA_HEADLESS_CMD", cmd)
    settings = load_settings(out_dir=tmp_path / "out", timeout_s=20)
    return replace(settings, jadx_argv=(sys.executable, FAKE_TOOL))


def _make_apk(path: Path) -> Path:
    # Un APK real es un zip con AndroidManifest.xml y classes.dex.
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "manifest")
        zf.writestr("classes.dex", "dex")
    return path


def test_apk_input_is_decompiled_not_extracted_as_zip(settings, tmp_path):
    apk = _make_apk(tmp_path / "app.apk")

    res = run_pipeline(apk, settings)

    # Antes: status "ok" con AndroidManifest.xml y classes.dex en `copied`.
    actions = {e.path: e.action for e in res.entries}
    assert res.decompiled_targets == 1, res.to_dict()
    assert actions == {"app.apk": "decompiled"}
    assert res.copied_files == 0
    names = _names(Path(res.output_zip))
    assert "decompilado/app.apk/a.java" in names


def test_apk_input_with_missing_jadx_is_not_reported_ok(settings, tmp_path, monkeypatch):
    # Hermética: con un comando que no existe, y no con el JADX real de tool/jadx/ (que en v2
    # puede estar instalado y funcionar).
    settings = replace(
        load_settings(out_dir=tmp_path / "out2", timeout_s=20),
        jadx_argv=("comando-jadx-que-no-existe",),
    )
    apk = _make_apk(tmp_path / "app.apk")

    res = run_pipeline(apk, settings)

    assert res.status != "ok", res.to_dict()


def test_decompile_dir_does_not_leak_symlink_target(settings, tmp_path):
    secreto = tmp_path / "secreto.txt"
    secreto.write_text("CONTENIDO_FUERA_DEL_DIRECTORIO")
    carpeta = tmp_path / "proyecto_js"
    carpeta.mkdir()
    (carpeta / "app.js").write_text("console.log(1)")
    (carpeta / "enlace.txt").symlink_to(secreto)

    res = decompile_target(carpeta, settings)

    assert res.status == "ok", res.to_dict()
    assert res.zip_path is not None
    with zipfile.ZipFile(res.zip_path) as zf:
        names = zf.namelist()
        assert "app.js" in names
        assert "enlace.txt" not in names
        for n in names:
            assert b"CONTENIDO_FUERA" not in zf.read(n)
    assert "symlinks_excluded:1" in res.unknowns
