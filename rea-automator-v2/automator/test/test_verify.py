"""Prueba de aceptación (verify): criterios, veredicto e informe, con un JADX simulado.

Un JADX real no hace falta: lo que se comprueba aquí es la lógica del informe (que no dé
APROBADO cuando no hay código Java recuperado) y que se ejecute el pipeline del proyecto."""

import json
import sys
import zipfile
from dataclasses import replace

import pytest

from rea_automator import jadx_tool
from rea_automator.config import load_settings
from rea_automator.jadx_tool import JADX_VERSION
from rea_automator.verify import (
    CRITERIA,
    VERDICT_FAIL,
    VERDICT_PASS,
    analyze_output_zip,
    has_type_declaration,
    verify_apk,
)

from . import fakes
from . import jadx_fakes as jf

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="lanzadores sh")

DESCRIPTORS = ["Lrea/demo/A;", "Lrea/demo/B;"]


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setattr(
        jadx_tool,
        "check_java",
        lambda **_kw: {"command": "java", "ok": True, "version": "21", "major": 21, "detail": "Java 21 (simulado)"},
    )
    monkeypatch.setenv("FAKE_JADX_VERSION", JADX_VERSION)


def _setup(tmp_path, descriptors=DESCRIPTORS, **install_kw):
    jadx_dir = jf.make_install(tmp_path / "tool", JADX_VERSION, **install_kw)
    settings = replace(
        load_settings(out_dir=tmp_path / "out", timeout_s=30),
        jadx_argv=(str(jadx_dir / "bin" / "jadx"),),
    )
    apk = fakes.apk(tmp_path / "calc.apk", descriptors)
    return apk, settings, jadx_dir


def _verify(tmp_path, mode="ok", **kw):
    apk, settings, jadx_dir = _setup(tmp_path, **kw.pop("setup", {}))
    return verify_apk(apk, settings, out_dir=tmp_path / "res", jadx_dir=jadx_dir, install=False, **kw)


def _by_id(report):
    return {c["id"]: c for c in report.data["criteria"]}


def test_passes_with_recovered_java(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    report = _verify(tmp_path)
    failed = [c for c in report.data["criteria"] if not c["ok"]]
    assert report.passed and report.verdict == VERDICT_PASS, failed
    assert set(_by_id(report)) == set(CRITERIA) and len(CRITERIA) == 13
    dec = report.data["decompilation"]
    assert dec["confirmed"] and dec["java_files"] == 2 and dec["java_files_with_type_declaration"] == 2
    assert dec["dex"]["coverage_pct"] == 100.0
    assert dec["sample"]["file"] == "sources/rea/demo/A.java"
    assert report.data["pipeline"]["status"] == "ok"


def test_jadx_exit_3_is_partial_but_still_passes(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "errors")
    report = _verify(tmp_path)
    assert report.passed
    assert report.data["pipeline"]["status"] == "partial" and report.data["pipeline"]["cli_exit_code"] == 1
    assert report.data["decompilation"]["jadx_errors"] == 4
    assert any("partial" in w for w in report.data["warnings"])


@pytest.mark.parametrize("mode, failing", [
    ("junk", "codigo_java_recuperado"),
    ("loadfail", "jadx_codigo_de_salida_valido"),
    ("crash", "jadx_codigo_de_salida_valido"),
    ("empty", "pipeline_proceso_el_apk"),
])
def test_not_approved_when_nothing_was_recovered(tmp_path, monkeypatch, mode, failing):
    monkeypatch.setenv("FAKE_JADX_MODE", mode)
    report = _verify(tmp_path)
    assert not report.passed and report.verdict == VERDICT_FAIL
    assert not _by_id(report)[failing]["ok"], _by_id(report)[failing]


def test_low_coverage_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    many = ["Lrea/demo/A;"] + [f"Lotro/Clase{i};" for i in range(9)]  # 1 de 10 con .java
    report = _verify(tmp_path, setup={"descriptors": many})
    assert not _by_id(report)["cobertura_de_clases_del_apk"]["ok"]
    assert not report.passed


def test_broken_jadx_skips_pipeline_and_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    report = _verify(tmp_path, setup={"launcher": jf.BROKEN_LAUNCHER})
    assert not report.passed and report.data["pipeline"] is None
    assert not _by_id(report)["descompila_clase_de_prueba"]["ok"] or not _by_id(report)["version_desde_la_ruta_del_proyecto"]["ok"]
    assert not _by_id(report)["pipeline_proceso_el_apk"]["evaluated"]


def test_missing_apk_and_wrong_extension(tmp_path):
    apk, settings, jadx_dir = _setup(tmp_path)
    missing = verify_apk(tmp_path / "no-existe.apk", settings, out_dir=tmp_path / "r1", jadx_dir=jadx_dir, install=False)
    assert not missing.passed and not _by_id(missing)["apk_valido"]["ok"]
    renamed = apk.rename(tmp_path / "calc.zip")
    wrong = verify_apk(renamed, settings, out_dir=tmp_path / "r2", jadx_dir=jadx_dir, install=False)
    assert not wrong.passed and ".apk" in _by_id(wrong)["apk_valido"]["detail"]


def test_pipeline_must_use_the_project_jadx(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    apk, settings, jadx_dir = _setup(tmp_path)
    other = jf.make_install(tmp_path / "otra", JADX_VERSION)
    settings = replace(settings, jadx_argv=(str(other / "bin" / "jadx"),))
    report = verify_apk(apk, settings, out_dir=tmp_path / "res", jadx_dir=jadx_dir, install=False)
    assert not _by_id(report)["pipeline_usa_el_jadx_del_proyecto"]["ok"] and not report.passed


def test_report_files_match_returned_data(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_JADX_MODE", "ok")
    report = _verify(tmp_path)
    assert report.json_path.name == "calc-informe.json" and report.md_path.name == "calc-informe.md"
    assert json.loads(report.json_path.read_text())["verdict"] == VERDICT_PASS
    md = report.md_path.read_text()
    assert md == report.markdown and VERDICT_PASS in md and "A.java" in md


def test_install_flag_requires_jadx_folder_name(tmp_path):
    apk, settings, _ = _setup(tmp_path)
    with pytest.raises(ValueError):
        verify_apk(apk, settings, out_dir=tmp_path / "r", jadx_dir=tmp_path / "otro-nombre", install=True)


# ── análisis independiente del zip ─────────────────────────────────────────────

@pytest.mark.parametrize("text, expected", [
    ("package a;\npublic class A {}", True),
    ("public interface B { }", True),
    ("enum C { X }", True),
    ("@interface D {}", True),
    ("public /* synthetic */ class E extends F {}", True),   # comentario entre modificadores (real en JADX)
    ("public final /* synthetic */ interface G {}", True),
    ("/* class A { } */\n// class B {}\n", False),
    ("/* JADX WARN: nada */", False),
    ("", False),
])
def test_has_type_declaration(text, expected):
    assert has_type_declaration(text) is expected


def _result_zip(tmp_path, files):
    path = tmp_path / "r.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("report.json", json.dumps({"entries": []}))
        for name, text in files.items():
            zf.writestr(name, text)
    return path


def test_analyze_output_zip_counts_only_under_prefix(tmp_path):
    flow = "\n".join(["class A {"] + ["  void f() { if (x) { return; } }"] * 40 + ["}"])
    path = _result_zip(tmp_path, {
        "decompilado/a.apk/sources/p/A.java": flow,
        "decompilado/a.apk/sources/p/Vacia.java": "/* JADX WARN: x */",
        "decompilado/a.apk/sources/p/Err.java": "class E {}\n/* JADX ERROR: m */",
        "decompilado/a.apk/resources/x.xml": "<a/>",
        "decompilado/otro.apk/sources/q/Z.java": "class Z {}",
    })
    an = analyze_output_zip(path, "a.apk")
    assert (an.files_total, an.java_files, an.java_with_declaration) == (4, 3, 2)
    assert an.files_with_jadx_error_marker == 1 and an.files_with_jadx_warn_marker == 1
    assert an.java_paths == {"p/A.java", "p/Vacia.java", "p/Err.java"}
    assert an.sample["file"] == "sources/p/A.java" and an.sample["total_lines"] == 42


def test_analyze_output_zip_without_candidates_has_no_sample(tmp_path):
    path = _result_zip(tmp_path, {"decompilado/a.apk/sources/p/A.java": "class A {}"})
    assert analyze_output_zip(path, "a.apk").sample is None
