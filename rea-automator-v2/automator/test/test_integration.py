"""Pruebas contra la CLI real de rea. Se saltan si REA_AUTOMATOR_REA_CMD no está definido."""
import os
import shutil

import pytest

from rea_automator.analyzer import analyze_target
from rea_automator.config import load_settings


pytestmark = pytest.mark.skipif(
    not os.environ.get("REA_AUTOMATOR_REA_CMD"),
    reason="defina REA_AUTOMATOR_REA_CMD para ejecutar contra rea real",
)


def test_real_rea_rejects_malformed_pe_with_its_own_error(tmp_path):
    # Cabecera MZ válida en el primer byte pero sin PE: el enrutamiento lo rechaza antes;
    # forzamos la familia nativa para comprobar que rea también lo rechaza.
    bad = tmp_path / "bad.dll"
    bad.write_bytes(b"MZ" + b"\x00" * 62)
    res = analyze_target(bad, load_settings(out_dir=tmp_path / "out", timeout_s=300), family="managed-pe")
    assert res.status == "failed"
    assert res.error is not None and "code" in res.error
    assert res.exit_code == 1


def test_real_rea_directory_is_ok(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "index.js").write_text("module.exports = 1;\n")
    res = analyze_target(d, load_settings(out_dir=tmp_path / "out", timeout_s=300))
    assert res.status == "ok" and res.family == "javascript-application"
    assert res.evidence["evidence_id"].startswith("ev_")


@pytest.mark.skipif(shutil.which("true") is None, reason="sin binario de sistema")
def test_real_rea_native_without_ghidra_reports_provider_unavailable(tmp_path):
    res = analyze_target("/bin/true", load_settings(out_dir=tmp_path / "out", timeout_s=300))
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip("Ghidra configurado: este caso requiere ausencia de Ghidra")
    assert res.status == "failed"
    assert res.error["code"] == "provider_unavailable"
