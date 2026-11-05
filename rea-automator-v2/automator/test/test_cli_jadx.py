"""Comandos `setup-jadx`, `check-jadx` y `verify-jadx` del CLI (JADX simulado, sin red)."""

import json
import sys
from dataclasses import replace
from functools import partial

import pytest

from rea_automator import __main__ as cli
from rea_automator import jadx_tool
from rea_automator.config import load_settings
from rea_automator.jadx_tool import JADX_VERSION

from . import fakes
from . import jadx_fakes as jf

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="lanzadores sh")


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(
        jadx_tool,
        "check_java",
        lambda **_kw: {"command": "java", "ok": True, "version": "21", "major": 21, "detail": "Java 21 (simulado)"},
    )
    monkeypatch.setenv("FAKE_JADX_VERSION", JADX_VERSION)


def test_setup_jadx_installs_from_local_zip_and_rejects_bad_sha(tmp_path, monkeypatch, capsys):
    zip_path = tmp_path / "jadx.zip"
    sha = jf.make_zip(zip_path, JADX_VERSION)
    tool = tmp_path / "tool"
    monkeypatch.setattr(cli, "install_jadx", partial(jadx_tool.install_jadx, tool_dir=tool, sha256=sha))

    assert cli.main(["setup-jadx", "--jadx-zip", str(zip_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "installed" and (tool / "jadx" / "bin" / "jadx").is_file()

    assert cli.main(["setup-jadx", "--jadx-zip", str(zip_path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "already_installed"

    monkeypatch.setattr(cli, "install_jadx", partial(jadx_tool.install_jadx, tool_dir=tmp_path / "t2", sha256="0" * 64))
    assert cli.main(["setup-jadx", "--jadx-zip", str(zip_path)]) == 1
    err = json.loads(capsys.readouterr().out)
    assert err["ok"] is False and err["error"]["code"]
    assert not (tmp_path / "t2" / "jadx").exists()


def test_check_jadx_exit_code_follows_the_check(tmp_path, monkeypatch, capsys):
    jadx_dir = jf.make_install(tmp_path / "tool", JADX_VERSION)
    monkeypatch.setattr(cli, "check_jadx", partial(jadx_tool.check_jadx, jadx_dir))
    assert cli.main(["check-jadx"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    monkeypatch.setattr(cli, "check_jadx", partial(jadx_tool.check_jadx, tmp_path / "no-hay"))
    assert cli.main(["check-jadx"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


def _patch_verify(monkeypatch, tmp_path):
    import rea_automator.verify as verify

    jadx_dir = jf.make_install(tmp_path / "tool", JADX_VERSION)

    def run(apk, settings, **kw):
        settings = replace(settings, jadx_argv=(str(jadx_dir / "bin" / "jadx"),))
        return verify.verify_apk(apk, settings, jadx_dir=jadx_dir, **kw)

    monkeypatch.setattr(cli, "verify_apk", run)


def test_verify_jadx_exit_zero_only_when_approved(tmp_path, monkeypatch, capsys):
    _patch_verify(monkeypatch, tmp_path)
    apk = fakes.apk(tmp_path / "calc.apk", ["Lrea/demo/A;", "Lrea/demo/B;"])

    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    assert cli.main(["verify-jadx", str(apk), "--out", str(tmp_path / "ok"), "--no-install"]) == 0
    assert "**Veredicto: APROBADO**" in capsys.readouterr().out
    assert (tmp_path / "ok" / "calc-informe.json").is_file()

    monkeypatch.setenv("FAKE_JADX_MODE", "junk")
    assert cli.main(["verify-jadx", str(apk), "--out", str(tmp_path / "ko"), "--no-install"]) == 1
    assert "NO APROBADO" in capsys.readouterr().out


def test_pipeline_exit_code_is_still_1_for_partial(tmp_path, monkeypatch, capsys):
    jadx_dir = jf.make_install(tmp_path / "tool", JADX_VERSION)
    monkeypatch.setattr(
        cli, "load_settings",
        lambda **kw: replace(load_settings(**kw), jadx_argv=(str(jadx_dir / "bin" / "jadx"),)),
    )
    monkeypatch.setenv("FAKE_JADX_MODE", "errors")
    apk = fakes.apk(tmp_path / "calc.apk", ["Lrea/demo/A;"])
    assert cli.main(["pipeline", str(apk), "--out", str(tmp_path / "o")]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "partial"
