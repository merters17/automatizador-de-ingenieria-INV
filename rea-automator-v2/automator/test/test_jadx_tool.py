"""Preparación y comprobación de JADX (v2): instalación con SHA-256, extracción segura,
reversión y comprobación desde la ruta del proyecto. Usan un JADX simulado (tests/fake_jadx.py);
solo el último bloque usa el JADX real y se salta si no está instalado."""

import os
from pathlib import Path

import pytest

from rea_automator import jadx_tool
from rea_automator.config import PROJECT_JADX_CMD
from rea_automator.jadx_tool import (
    JADX_VERSION,
    SMOKE_CLASS,
    JadxInstallError,
    check_java,
    check_jadx,
    install_jadx,
    parse_java_major,
    sha256_file,
)

from . import jadx_fakes as jf

pytestmark = pytest.mark.skipif(os.name != "posix", reason="los lanzadores simulados son scripts sh")

STEP_NAMES = [
    "launcher_existe",
    "launcher_ejecutable",
    "jar_existe",
    "java_disponible",
    "version_desde_la_ruta_del_proyecto",
    "descompila_clase_de_prueba",
]


@pytest.fixture(autouse=True)
def java_ok(monkeypatch):
    # Las pruebas de JADX no dependen del Java de la máquina. `check_java` importado arriba
    # sigue siendo la función real (se prueba aparte).
    monkeypatch.setattr(
        jadx_tool,
        "check_java",
        lambda **_kw: {"command": "java", "ok": True, "version": "21", "major": 21, "detail": "Java 21 (simulado)"},
    )


def _zip(tmp_path, **kw):
    path = tmp_path / f"jadx-{jf.VERSION}.zip"
    return path, jf.make_zip(path, **kw)


def _install(tool_dir, zip_path, sha, **kw):
    return install_jadx(tool_dir=tool_dir, zip_path=zip_path, version=jf.VERSION, sha256=sha, **kw)


# ── Java ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "text, major",
    [("21.0.12.1", 21), ("1.8.0_292", 8), ("11", 11), ("17-ea", 17), ("11.0.2", 11), ("abc", None)],
)
def test_parse_java_major(text, major):
    assert parse_java_major(text) == major


def _fake_java_home(tmp_path, line, code=0):
    home = tmp_path / "jdk"
    (home / "bin").mkdir(parents=True)
    java = home / "bin" / "java"
    java.write_text(f"#!/bin/sh\necho '{line}' >&2\nexit {code}\n")
    java.chmod(0o755)
    return home


def test_check_java_reads_the_version_from_stderr(tmp_path, monkeypatch):
    monkeypatch.setenv("JAVA_HOME", str(_fake_java_home(tmp_path, 'openjdk version "17.0.2" 2022-01-18')))
    info = check_java()
    assert info["ok"] and info["major"] == 17 and info["version"] == "17.0.2"


def test_check_java_rejects_java_8(tmp_path, monkeypatch):
    monkeypatch.setenv("JAVA_HOME", str(_fake_java_home(tmp_path, 'java version "1.8.0_292"')))
    info = check_java()
    assert not info["ok"] and info["major"] == 8 and "11" in info["detail"]


def test_check_java_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("JAVA_HOME", str(tmp_path / "no-existe"))
    info = check_java()
    assert not info["ok"] and "no se pudo ejecutar" in info["detail"]


# ── instalación ──────────────────────────────────────────────────────────────

def test_install_from_local_zip_prepares_tool_jadx(tmp_path):
    z, sha = _zip(tmp_path)
    tool = tmp_path / "tool"

    res = _install(tool, z, sha)

    assert res.status == "installed" and res.ok
    assert res.source == "local-zip" and res.zip_sha256 == sha
    launcher = tool / "jadx" / "bin" / "jadx"
    assert launcher.is_file()
    assert os.access(launcher, os.X_OK), "el zip no traía bit de ejecución: el instalador debe ponerlo"
    assert res.check.ok and res.check.version == "9.9.9"
    assert [s.name for s in res.check.steps] == STEP_NAMES
    assert not list(tool.glob(".jadx-staging-*")), "no deben quedar restos temporales"


def test_install_downloads_from_the_url(tmp_path):
    z, sha = _zip(tmp_path)
    res = install_jadx(tool_dir=tmp_path / "tool", url=z.as_uri(), version=jf.VERSION, sha256=sha)
    assert res.status == "installed" and res.source == "download" and res.ok


def test_download_failure_is_explicit_and_actionable(tmp_path):
    with pytest.raises(JadxInstallError) as err:
        install_jadx(
            tool_dir=tmp_path / "tool",
            url=(tmp_path / "no-existe.zip").as_uri(),
            version=jf.VERSION,
            sha256="0" * 64,
        )
    assert err.value.code == "download_failed"
    assert "--jadx-zip" in err.value.hint
    assert not (tmp_path / "tool" / "jadx").exists()


def test_wrong_sha256_installs_nothing(tmp_path):
    z, _ = _zip(tmp_path)
    tool = tmp_path / "tool"
    with pytest.raises(JadxInstallError) as err:
        _install(tool, z, "0" * 64)
    assert err.value.code == "checksum_mismatch"
    assert not (tool / "jadx").exists()
    assert not list(tool.glob(".jadx-staging-*"))


def test_zip_slip_is_rejected(tmp_path):
    z, sha = _zip(tmp_path, extra={"../evil.txt": b"x"})
    tool = tmp_path / "tool"
    with pytest.raises(JadxInstallError) as err:
        _install(tool, z, sha)
    assert err.value.code == "unsafe_path"
    assert not any(tool.rglob("evil.txt")) and not (tmp_path / "evil.txt").exists()
    assert not (tool / "jadx").exists()


def test_symlink_entries_are_rejected(tmp_path):
    z, sha = _zip(tmp_path, symlink="bin/atajo")
    with pytest.raises(JadxInstallError) as err:
        _install(tmp_path / "tool", z, sha)
    assert err.value.code == "unsafe_entry"


def test_zip_without_the_jadx_layout_is_rejected(tmp_path):
    z, sha = _zip(tmp_path, omit=("bin/jadx",))
    with pytest.raises(JadxInstallError) as err:
        _install(tmp_path / "tool", z, sha)
    assert err.value.code == "bad_layout" and "bin/jadx" in err.value.message
    assert not (tmp_path / "tool" / "jadx").exists()


def test_a_file_that_is_not_a_zip_is_rejected(tmp_path):
    fake = tmp_path / "jadx.zip"
    fake.write_text("esto no es un zip")
    with pytest.raises(JadxInstallError) as err:
        _install(tmp_path / "tool", fake, sha256_file(fake))
    assert err.value.code == "bad_zip"


def test_missing_local_zip(tmp_path):
    with pytest.raises(JadxInstallError) as err:
        _install(tmp_path / "tool", tmp_path / "nada.zip", "0" * 64)
    assert err.value.code == "zip_not_found"


def test_second_install_is_a_noop_and_force_reinstalls(tmp_path):
    z, sha = _zip(tmp_path)
    tool = tmp_path / "tool"
    assert _install(tool, z, sha).status == "installed"
    marker = tool / "jadx" / "MARCA"
    marker.write_text("x")

    second = _install(tool, z, sha)
    assert second.status == "already_installed" and second.ok and second.source is None
    assert marker.exists(), "una instalación sana no se toca"

    third = _install(tool, z, sha, force=True)
    assert third.status == "reinstalled" and third.ok and third.source == "local-zip"
    assert not marker.exists()


def test_a_broken_fresh_install_is_kept_but_reported_as_not_ok(tmp_path):
    z, sha = _zip(tmp_path, launcher=jf.BROKEN_LAUNCHER)
    tool = tmp_path / "tool"

    res = _install(tool, z, sha)

    assert res.status == "installed" and not res.ok and not res.restored_previous
    assert (tool / "jadx" / "bin" / "jadx").is_file()
    failing = [s.name for s in res.check.steps if not s.ok]
    assert failing == ["version_desde_la_ruta_del_proyecto"]


def test_a_failed_replacement_restores_the_previous_healthy_install(tmp_path):
    good, good_sha = _zip(tmp_path)
    tool = tmp_path / "tool"
    assert _install(tool, good, good_sha).ok
    broken = tmp_path / "roto.zip"
    broken_sha = jf.make_zip(broken, launcher=jf.BROKEN_LAUNCHER)

    res = _install(tool, broken, broken_sha, force=True)

    assert res.status == "rolled_back" and res.restored_previous and not res.ok
    assert not res.check.ok, "el detalle del fallo es el de la instalación nueva"
    assert check_jadx(tool / "jadx", expected_version=jf.VERSION).ok, "la anterior debe seguir funcionando"


def test_leftovers_of_an_interrupted_install_are_removed(tmp_path):
    z, sha = _zip(tmp_path)
    tool = tmp_path / "tool"
    leftover = tool / ".jadx-staging-viejo"
    leftover.mkdir(parents=True)
    (leftover / "x").write_text("x")

    _install(tool, z, sha)

    assert not leftover.exists()


def test_a_broken_existing_directory_is_replaced(tmp_path):
    z, sha = _zip(tmp_path)
    tool = tmp_path / "tool"
    (tool / "jadx").mkdir(parents=True)
    (tool / "jadx" / "basura.txt").write_text("x")

    res = _install(tool, z, sha)

    assert res.status == "reinstalled" and res.ok and res.previous_version is None
    assert not (tool / "jadx" / "basura.txt").exists()


# ── comprobación desde la ruta del proyecto ──────────────────────────────────

def test_check_passes_for_a_healthy_install(tmp_path):
    jadx_dir = jf.make_install(tmp_path / "tool")

    chk = check_jadx(jadx_dir, expected_version=jf.VERSION)

    assert chk.ok and chk.version == "9.9.9" and not chk.warnings
    assert chk.jar_sha256 == sha256_file(jadx_dir / "lib" / "jadx-9.9.9-all.jar")
    assert [s.name for s in chk.steps] == STEP_NAMES
    assert all(s.ok for s in chk.steps)
    assert chk.smoke["java_files"] == ["sources/rea/smoke/Hello.java"]
    assert chk.smoke["markers"] and all(chk.smoke["markers"].values())


def test_check_reports_a_missing_launcher_with_its_path_and_the_fix(tmp_path):
    jadx_dir = tmp_path / "tool" / "jadx"

    chk = check_jadx(jadx_dir)

    assert not chk.ok and len(chk.steps) == 1
    step = chk.steps[0]
    assert step.name == "launcher_existe" and not step.ok
    assert str(jadx_dir / "bin" / "jadx") in step.detail
    assert "setup-jadx" in step.detail


def test_check_restores_a_lost_exec_bit(tmp_path):
    jadx_dir = jf.make_install(tmp_path / "tool", executable=False)

    chk = check_jadx(jadx_dir, expected_version=jf.VERSION)

    assert chk.ok
    assert any("bit de ejecución" in w for w in chk.warnings)
    assert os.access(jadx_dir / "bin" / "jadx", os.X_OK)


def test_check_without_fix_permissions_fails_on_a_lost_exec_bit(tmp_path):
    jadx_dir = jf.make_install(tmp_path / "tool", executable=False)

    chk = check_jadx(jadx_dir, expected_version=jf.VERSION, fix_permissions=False)

    assert not chk.ok
    assert chk.steps[-1].name == "launcher_ejecutable" and not chk.steps[-1].ok
    assert not os.access(jadx_dir / "bin" / "jadx", os.X_OK)


def test_check_fails_without_the_jar(tmp_path):
    jadx_dir = jf.make_install(tmp_path / "tool")
    (jadx_dir / "lib" / "jadx-9.9.9-all.jar").unlink()

    chk = check_jadx(jadx_dir, expected_version=jf.VERSION)

    assert not chk.ok and chk.steps[-1].name == "jar_existe"


def test_check_fails_when_java_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        jadx_tool, "check_java", lambda **_kw: {"command": "java", "ok": False, "detail": "no hay java"}
    )
    chk = check_jadx(jf.make_install(tmp_path / "tool"), expected_version=jf.VERSION)

    assert not chk.ok and chk.steps[-1].name == "java_disponible" and chk.steps[-1].detail == "no hay java"


def test_check_fails_when_the_launcher_cannot_report_a_version(tmp_path):
    jadx_dir = jf.make_install(tmp_path / "tool", launcher=jf.BROKEN_LAUNCHER)

    chk = check_jadx(jadx_dir, expected_version=jf.VERSION)

    assert not chk.ok and chk.version is None
    assert chk.steps[-1].name == "version_desde_la_ruta_del_proyecto"
    assert "código 1" in chk.steps[-1].detail


def test_check_fails_when_the_smoke_decompile_recovers_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "smoke_broken")
    jadx_dir = jf.make_install(tmp_path / "tool")

    chk = check_jadx(jadx_dir, expected_version=jf.VERSION)

    assert not chk.ok and chk.version == "9.9.9"
    assert chk.steps[-1].name == "descompila_clase_de_prueba" and not chk.steps[-1].ok
    assert not any(chk.smoke["markers"].values())


def test_check_warns_on_a_version_that_is_not_the_pinned_one(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_VERSION", "9.9.8")
    jadx_dir = jf.make_install(tmp_path / "tool")

    chk = check_jadx(jadx_dir, expected_version="9.9.9")

    assert chk.ok and chk.version == "9.9.8"
    assert any("fija 9.9.9" in w for w in chk.warnings)
    assert any("jadx-9.9.9-all.jar" in w for w in chk.warnings)


def test_check_never_uses_path_to_find_jadx(tmp_path, monkeypatch):
    otro = tmp_path / "otro"
    otro.mkdir()
    (otro / "jadx").write_text("#!/bin/sh\necho 0.0.1\n")
    (otro / "jadx").chmod(0o755)
    monkeypatch.setenv("PATH", f"{otro}:{os.environ['PATH']}")

    chk = check_jadx(jf.make_install(tmp_path / "tool"), expected_version=jf.VERSION)

    assert chk.ok and chk.version == "9.9.9", "se ejecutó el jadx del PATH en vez del del proyecto"


def test_check_with_a_missing_smoke_fixture_fails_clearly(tmp_path):
    chk = check_jadx(jf.make_install(tmp_path / "tool"), expected_version=jf.VERSION, smoke_class=tmp_path / "nada.class")

    assert not chk.ok and "falta la clase de prueba" in chk.steps[-1].detail


def test_the_bundled_smoke_fixture_is_a_java8_class():
    data = SMOKE_CLASS.read_bytes()
    assert data[:4] == b"\xca\xfe\xba\xbe"
    assert int.from_bytes(data[6:8], "big") == 52  # Java 8
    assert b"rea/smoke/Hello" in data and b"hola-jadx-smoke:" in data
    assert (SMOKE_CLASS.parent / "Hello.java").is_file(), "debe quedar su fuente junto a la clase"


# ── JADX real (se salta si no está instalado en tool/jadx/) ───────────────────

needs_real_jadx = pytest.mark.skipif(
    not PROJECT_JADX_CMD.is_file(), reason="JADX real no instalado: python -m rea_automator setup-jadx"
)


@needs_real_jadx
def test_real_jadx_works_from_the_project_path(monkeypatch):
    monkeypatch.undo()  # sin el Java simulado: aquí se usa el Java real
    chk = check_jadx()

    assert chk.ok, chk.to_dict()
    assert chk.version == JADX_VERSION
    assert Path(chk.launcher) == PROJECT_JADX_CMD
    assert chk.smoke["markers"] and all(chk.smoke["markers"].values())
