from pathlib import Path

import pytest

from rea_automator.adapters.bulk_native import build_ghidra_headless_argv
from rea_automator.adapters.bulk_tools import KIND_COPY_DIR, KIND_SUBPROCESS, build_bulk_plan
from rea_automator.config import DEFAULT_JADX_CMD, PROJECT_JADX_CMD, load_settings
from rea_automator.routing import FAMILY_ANDROID, FAMILY_JS, FAMILY_MANAGED, FAMILY_NATIVE


@pytest.fixture
def settings(tmp_path):
    # env={}: prueba los valores por defecto del código, no el entorno del usuario.
    return load_settings(out_dir=tmp_path / "out", env={})


def test_android_plan_uses_jadx_bulk_mode(settings, tmp_path):
    target = tmp_path / "app.apk"
    out = tmp_path / "out"
    plan = build_bulk_plan(settings, FAMILY_ANDROID, target, out)
    assert plan.kind == KIND_SUBPROCESS
    assert plan.argv[-4:] == ("-d", str(out), str(target), "--no-res")
    assert plan.argv[0] == str(PROJECT_JADX_CMD)
    assert Path(plan.argv[0]).is_absolute()
    assert Path(plan.argv[0]).parts[-4:] == ("tool", "jadx", "bin", "jadx")


def test_managed_plan_uses_ilspycmd_project_mode(settings, tmp_path):
    target = tmp_path / "Assembly.dll"
    out = tmp_path / "out"
    plan = build_bulk_plan(settings, FAMILY_MANAGED, target, out)
    assert plan.kind == KIND_SUBPROCESS
    assert plan.argv == ("ilspycmd", "-p", "-o", str(out), str(target))


def test_js_asar_plan_extracts(settings, tmp_path):
    target = tmp_path / "app.asar"
    target.write_bytes(b"\x00")
    out = tmp_path / "out"
    plan = build_bulk_plan(settings, FAMILY_JS, target, out)
    assert plan.kind == KIND_SUBPROCESS
    assert plan.argv[-3:] == ("extract", str(target), str(out))


def test_js_directory_plan_just_copies(settings, tmp_path):
    target = tmp_path / "app_dir"
    target.mkdir()
    out = tmp_path / "out"
    plan = build_bulk_plan(settings, FAMILY_JS, target, out)
    assert plan.kind == KIND_COPY_DIR


def test_native_family_has_no_bulk_tools_plan(settings, tmp_path):
    # native-binary va por un camino separado (Ghidra headless), no por build_bulk_plan.
    with pytest.raises(NotImplementedError):
        build_bulk_plan(settings, FAMILY_NATIVE, tmp_path / "bin", tmp_path / "out")


def test_ghidra_headless_argv_shape(settings, tmp_path):
    target = tmp_path / "bin.exe"
    out_dir = tmp_path / "out"
    project_dir = tmp_path / "proj"
    argv = build_ghidra_headless_argv(settings, target, out_dir, project_dir=project_dir)
    # Ghidra 12 ejecuta scripts Python solo vía PyGhidra headless.
    assert argv[:2] == ("pyghidraRun", "-H")
    assert str(project_dir) in argv
    assert "-import" in argv
    assert str(target) in argv
    assert "-postScript" in argv
    assert "ghidra_decompile_all.py" in argv
    assert str(out_dir) in argv
    assert "-deleteProject" in argv


def test_jadx_cannot_be_redirected_to_a_global_install(tmp_path, monkeypatch):
    monkeypatch.setenv("REA_AUTOMATOR_JADX_CMD", "/opt/jadx/bin/jadx")
    s = load_settings(out_dir=tmp_path / "out")
    plan = build_bulk_plan(s, FAMILY_ANDROID, tmp_path / "a.apk", tmp_path / "out")
    assert plan.argv[0] == str(PROJECT_JADX_CMD)
    assert DEFAULT_JADX_CMD == str(PROJECT_JADX_CMD)
