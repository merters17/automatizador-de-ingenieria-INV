"""`summarize_jadx_run` y los datos de JADX que `decompile_target` deja en `details`."""

import sys
from dataclasses import replace

import pytest

from rea_automator.config import load_settings
from rea_automator.decompile import JADX_EXIT_MEANINGS, decompile_target, summarize_jadx_run

from . import fakes
from . import jadx_fakes as jf

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="lanzadores sh")


def _run_dir(tmp_path, stdout="", stderr=""):
    run_dir = tmp_path / "run"
    src = run_dir / "sources"
    src.mkdir(parents=True)
    (run_dir / "stdout.log").write_text(stdout)
    (run_dir / "stderr.log").write_text(stderr)
    return run_dir, src


@pytest.mark.parametrize("code", [0, 1, 2, 3])
def test_summary_names_each_documented_exit_code(tmp_path, code):
    run_dir, src = _run_dir(tmp_path)
    out = summarize_jadx_run(code, run_dir, src)
    assert out["exit_code"] == code and out["exit_meaning"] == JADX_EXIT_MEANINGS[code]


def test_summary_unknown_and_timeout(tmp_path):
    run_dir, src = _run_dir(tmp_path)
    assert "no documentado" in summarize_jadx_run(7, run_dir, src)["exit_meaning"]
    assert "timeout" in summarize_jadx_run(None, run_dir, src)["exit_meaning"]


def test_summary_reads_error_count_and_counts_java(tmp_path):
    run_dir, src = _run_dir(tmp_path, stdout="x\nERROR - finished with errors, count: 12\n")
    (src / "p").mkdir()
    (src / "p" / "A.java").write_text("class A {}")
    (src / "p" / "notas.txt").write_text("no cuenta")
    out = summarize_jadx_run(3, run_dir, src)
    assert out["errors"] == 12 and out["java_files"] == 1


def test_summary_without_error_line_has_none(tmp_path):
    run_dir, src = _run_dir(tmp_path, stdout="INFO - done")
    assert summarize_jadx_run(0, run_dir, src)["errors"] is None


def _settings(tmp_path):
    jadx_dir = jf.make_install(tmp_path / "tool")
    settings = load_settings(out_dir=tmp_path / "out", timeout_s=30)
    return replace(settings, jadx_argv=(str(jadx_dir / "bin" / "jadx"),))


def test_decompile_apk_records_jadx_details(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "errors")
    apk = fakes.apk(tmp_path / "app.apk", ["Lrea/demo/A;", "Lrea/demo/B;"])
    res = decompile_target(apk, _settings(tmp_path))
    assert res.status == "partial", res.to_dict()
    jx = res.details["jadx"]
    assert (jx["exit_code"], jx["errors"], jx["java_files"]) == (3, 4, 2)
    assert "jadx_errors:4" in res.unknowns


def test_decompile_apk_clean_run_is_ok(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    apk = fakes.apk(tmp_path / "app.apk", ["Lrea/demo/A;"])
    res = decompile_target(apk, _settings(tmp_path))
    assert res.status == "ok", res.to_dict()
    assert res.details["jadx"]["exit_code"] == 0 and res.details["jadx"]["errors"] is None


def test_decompile_apk_with_missing_jadx_hints_setup(tmp_path):
    settings = replace(load_settings(out_dir=tmp_path / "out", timeout_s=10), jadx_argv=("comando-jadx-que-no-existe",))
    apk = fakes.apk(tmp_path / "app.apk", ["La/B;"])
    res = decompile_target(apk, settings)
    assert res.status == "command_not_found"
    assert "setup-jadx" in res.error["hint"]
