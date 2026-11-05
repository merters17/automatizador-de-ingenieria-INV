import sys
from pathlib import Path

import pytest

from rea_automator.adapters.rea_cli import build_argv
from rea_automator.analyzer import analyze_target
from rea_automator.config import Settings

from . import fakes

FAKE = str(Path(__file__).parent / "fake_rea.py")


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("REA_AUTOMATOR_REA_CMD", f"{sys.executable} {FAKE}")
    from rea_automator.config import load_settings
    return load_settings(out_dir=tmp_path / "out", timeout_s=20)


def _mode(monkeypatch, mode):
    monkeypatch.setenv("FAKE_REA_MODE", mode)


def test_argv_per_family(settings, tmp_path):
    t = str(tmp_path / "x")
    assert build_argv(settings, "javascript-application", t)[-4:] == ("analyze-javascript-application", t, "--format", "json")
    assert build_argv(settings, "managed-pe", t)[-4:] == ("inspect-managed-artifact", t, "--format", "json")
    assert build_argv(settings, "android-package", t)[-4:] == ("inspect-android-package", t, "--format", "json")
    native = build_argv(settings, "native-binary", t)
    assert native[-6:] == ("analyze", t, "--provider", "ghidra", "--format", "json")


def test_ok_run_produces_evidence_and_progress(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "ok")
    target = fakes.elf(tmp_path / "game.bin")
    res = analyze_target(target, settings)
    assert res.status == "ok" and res.family == "native-binary"
    assert res.evidence["evidence_id"] == "ev_test"
    assert res.progress_events == 2 and res.last_progress == "second"
    assert (settings.out_dir / res.stdout_path.split("/")[-2] / "result.json").exists()


def test_error_envelope_exit1(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "error")
    res = analyze_target(fakes.elf(tmp_path / "g"), settings)
    assert res.status == "failed" and res.exit_code == 1
    assert res.error["code"] == "target_unavailable"


def test_exit0_with_error_envelope_is_failed_not_ok(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "exit0err")
    res = analyze_target(fakes.elf(tmp_path / "g"), settings)
    assert res.status == "failed" and "exit0_with_error_envelope" in res.unknowns


def test_exit0_bad_json_is_unparseable(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "badjson")
    res = analyze_target(fakes.elf(tmp_path / "g"), settings)
    assert res.status == "unparseable_output" and "stdout_not_json" in res.unknowns


def test_exit1_without_envelope_is_marked_unknown(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "noerror")
    res = analyze_target(fakes.elf(tmp_path / "g"), settings)
    assert res.status == "failed" and "error_envelope_missing" in res.unknowns


def test_undocumented_exit_code_is_recorded(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "exit5")
    res = analyze_target(fakes.elf(tmp_path / "g"), settings)
    assert res.status == "failed" and "exit_code_unexplained:5" in res.unknowns


def test_timeout_status(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "sleep")
    s = Settings(**{**settings.__dict__, "timeout_s": 1})
    res = analyze_target(fakes.elf(tmp_path / "g"), s)
    assert res.status == "timeout" and "timeout_killed" in res.unknowns


def test_routing_error_does_not_execute(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "ok")
    res = analyze_target(tmp_path / "missing", settings)
    assert res.status == "not_found" and res.argv == []
    bad = tmp_path / "bad.exe"
    bad.write_text("not a binary")
    res = analyze_target(bad, settings)
    assert res.status == "routing_error" and res.argv == []
    assert "routing:unknown_format" in res.unknowns


def test_forced_family_skips_routing(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "ok")
    bad = tmp_path / "bad.exe"
    bad.write_text("not a binary")
    res = analyze_target(bad, settings, family="native-binary")
    assert res.status == "ok" and res.route_reasons == ["override"]


def test_managed_family_with_rea_not_managed_is_family_mismatch(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "managed_notmanaged")
    res = analyze_target(fakes.pe(tmp_path / "n.exe", managed=False), settings, family="managed-pe")
    assert res.status == "family_mismatch" and res.exit_code == 0
    assert "rea_reports:not-managed" in res.unknowns


def test_managed_family_confirmed_is_ok(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "managed_ok")
    res = analyze_target(fakes.pe(tmp_path / "m.dll", managed=True), settings, family="managed-pe")
    assert res.status == "ok" and res.unknowns == []


def test_js_empty_application_is_ok_but_flagged(settings, tmp_path, monkeypatch):
    _mode(monkeypatch, "js_empty")
    d = tmp_path / "empty_app"
    d.mkdir()
    res = analyze_target(d, settings)
    assert res.status == "ok" and "no_relevant_files" in res.unknowns


def test_missing_rea_command_is_reported_not_crashed(tmp_path, monkeypatch):
    """Regresión: argv[0] inexistente no debe propagar FileNotFoundError sin capturar."""
    monkeypatch.setenv("REA_AUTOMATOR_REA_CMD", "este-comando-no-existe-en-ningun-lado")
    from rea_automator.config import load_settings
    s = load_settings(out_dir=tmp_path / "out", timeout_s=20)
    res = analyze_target(fakes.elf(tmp_path / "g"), s)
    assert res.status == "command_not_found"
    assert "command_not_found" in res.unknowns
    assert res.error["argv0"] == "este-comando-no-existe-en-ningun-lado"
