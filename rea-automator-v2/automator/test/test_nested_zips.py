"""Regresiones de ZIP anidados. Antes del cambio:

A. Un .zip corrupto (texto con extensión .zip) se trataba como archivo normal
   y el informe declaraba `ok`.
B. Un zip anidado con extensión en mayúsculas (`inner.ZIP`) no se extraía,
   porque la búsqueda distinguía mayúsculas en Linux.
C. Al alcanzar el límite de profundidad, el zip sobrante no generaba ningún
   registro y el informe también declaraba `ok`.
"""

import io
import zipfile
from pathlib import Path

from rea_automator.config import load_settings
from rea_automator.pipeline import run_pipeline


def _zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _outer(path: Path, members) -> Path:
    path.write_bytes(_zip_bytes(members))
    return path


def _settings(tmp_path):
    return load_settings(out_dir=tmp_path / "out", timeout_s=20, env={})


def _names(zip_path: Path) -> set[str]:
    with zipfile.ZipFile(zip_path) as zf:
        return set(zf.namelist())


def _entry(res, path):
    return next(e for e in res.entries if e.path == path)


def test_zip_anidado_corrupto_se_marca_failed_y_no_es_ok(tmp_path):
    outer = _outer(tmp_path / "entrada.zip", [
        ("bad.zip", "esto es texto, no un zip"),
        ("LEEME.txt", "hola"),
    ])

    res = run_pipeline(outer, _settings(tmp_path))

    assert res.status != "ok", res.to_dict()
    assert res.status == "partial"
    assert res.failed_targets == 1
    bad = _entry(res, "bad.zip")
    assert bad.action == "failed"
    assert bad.error["code"] == "nested_zip_invalid"
    # El original se conserva para diagnóstico.
    assert "otros_archivos/bad.zip" in _names(Path(res.output_zip))


def test_zip_anidado_con_extension_en_mayusculas_se_extrae(tmp_path):
    outer = _outer(tmp_path / "entrada.zip", [
        ("inner.ZIP", _zip_bytes([("dentro.txt", "contenido")])),
    ])

    res = run_pipeline(outer, _settings(tmp_path))

    assert res.status == "ok", res.to_dict()
    assert "inner/dentro.txt" in {e.path for e in res.entries}
    names = _names(Path(res.output_zip))
    assert "otros_archivos/inner/dentro.txt" in names
    # El zip anidado fue reemplazado por su contenido, no quedó como archivo copiado.
    assert "otros_archivos/inner.ZIP" not in names


def test_limite_de_profundidad_queda_registrado_y_no_es_ok(tmp_path):
    l3 = _zip_bytes([("final.txt", "fondo")])
    l2 = _zip_bytes([("l3.zip", l3)])
    l1 = _zip_bytes([("l2.zip", l2)])
    outer = _outer(tmp_path / "entrada.zip", [("l1.zip", l1)])

    res = run_pipeline(outer, _settings(tmp_path))

    assert res.status != "ok", res.to_dict()
    assert res.status == "skipped"
    assert res.skipped_files == 1
    deep = _entry(res, "l1/l2/l3.zip")
    assert deep.action == "skipped"
    assert deep.error["code"] == "nested_zip_depth_limit"
    # El contenido que quedó fuera no se extrae, pero sí se conserva el zip original.
    assert "otros_archivos/l1/l2/l3.zip" in _names(Path(res.output_zip))
    assert not any(e.path.endswith("final.txt") for e in res.entries)


def test_ejecucion_limpia_con_zip_anidado_valido_sigue_siendo_ok(tmp_path):
    # Control: el arreglo no debe degradar un caso correcto.
    outer = _outer(tmp_path / "entrada.zip", [
        ("nivel1.zip", _zip_bytes([("a.txt", "x"), ("sub.zip", _zip_bytes([("b.txt", "y")]))])),
    ])
    res = run_pipeline(outer, _settings(tmp_path))
    assert res.status == "ok", res.to_dict()
