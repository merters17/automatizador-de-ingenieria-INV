import sys
import zipfile
from pathlib import Path
from dataclasses import replace

import pytest

from rea_automator.config import load_settings
from rea_automator.decompile import decompile_target

from . import fakes

FAKE_TOOL = str(Path(__file__).parent / "fake_bulk_tool.py")


@pytest.fixture
def settings(tmp_path, monkeypatch):
    # El "jadx" e "ilspycmd" simulados escriben N archivos de texto en el out_dir
    # que reciben como argumento, para probar el empaquetado en zip sin herramientas reales.
    monkeypatch.setenv("REA_AUTOMATOR_ILSPYCMD_CMD", f"{sys.executable} {FAKE_TOOL}")
    settings = load_settings(out_dir=tmp_path / "out", timeout_s=20)
    return replace(settings, jadx_argv=(sys.executable, FAKE_TOOL))


def test_android_bulk_decompile_produces_zip(settings, tmp_path):
    target = fakes.zipfile_bytes(tmp_path / "game.apk")
    res = decompile_target(target, settings)
    assert res.status == "ok"
    assert res.family == "android-package"
    assert res.file_count == 3
    assert res.zip_path is not None
    with zipfile.ZipFile(res.zip_path) as zf:
        names = set(zf.namelist())
    assert names == {"a.java", "b.java", "c.java"}


def test_managed_bulk_decompile_forced_family(settings, tmp_path):
    target = tmp_path / "weird_no_ext"
    target.write_bytes(b"\x00")
    res = decompile_target(target, settings, family="managed-pe")
    assert res.status == "ok"
    assert res.file_count == 3


def test_js_directory_is_just_zipped(settings, tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "index.js").write_text("console.log(1)")
    (d / "lib").mkdir()
    (d / "lib" / "util.js").write_text("module.exports = {}")
    res = decompile_target(d, settings)
    assert res.status == "ok"
    assert res.file_count == 2
    with zipfile.ZipFile(res.zip_path) as zf:
        names = set(zf.namelist())
    assert names == {"index.js", "lib/util.js"}


def test_missing_tool_is_reported_not_crashed(tmp_path, monkeypatch):
    s = replace(load_settings(out_dir=tmp_path / "out", timeout_s=20),
                jadx_argv=("comando-jadx-que-no-existe",))
    target = fakes.zipfile_bytes(tmp_path / "game.apk")
    res = decompile_target(target, s)
    assert res.status == "command_not_found"
    assert res.zip_path is None


def test_not_found_target(settings, tmp_path):
    res = decompile_target(tmp_path / "nope.apk", settings)
    assert res.status == "not_found"


def test_native_family_runs_ghidra_headless_path(settings, tmp_path, monkeypatch):
    # Para native no hay build_bulk_plan; decompile_target arma directo el argv de
    # analyzeHeadless. Simulamos ese binario para no depender de Ghidra real.
    monkeypatch.setenv("REA_AUTOMATOR_GHIDRA_HEADLESS_CMD", f"{sys.executable} {FAKE_TOOL}")
    s = load_settings(out_dir=tmp_path / "out", timeout_s=20)
    target = fakes.elf(tmp_path / "game.bin")
    res = decompile_target(target, s)
    assert res.family == "native-binary"
    assert res.status == "ok"
    # 3 archivos .c de ejemplo + _index.tsv (que ghidra_decompile_all.py
    # siempre escribe y que decompile.py analiza para confirmar el "ok").
    assert res.file_count == 4


def test_previous_outputs_are_removed_before_same_target_runs_again(settings, tmp_path):
    target = fakes.zipfile_bytes(tmp_path / "game.apk")
    first = decompile_target(target, settings)
    assert first.status == "ok"

    stale = Path(first.out_dir) / "stale-from-old-run.java"
    stale.write_text("this must not leak into the next result")

    second = decompile_target(target, settings)

    assert second.status == "ok"
    assert "stale-from-old-run.java" not in {
        p.name for p in Path(second.out_dir).rglob("*") if p.is_file()
    }
    with zipfile.ZipFile(second.zip_path) as zf:
        assert "stale-from-old-run.java" not in zf.namelist()
