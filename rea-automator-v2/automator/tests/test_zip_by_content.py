"""Opción 2: un zip sin extensión .zip dentro del paquete no se expande, pero
se registra como `skipped` (código zip_by_content_not_expanded). Antes se copiaba
como `unknown_format` y el informe global salía `ok`.
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


def _settings(tmp_path):
    return load_settings(out_dir=tmp_path / "out", timeout_s=20, env={})


def _entry(res, path):
    return next(e for e in res.entries if e.path == path)


def test_zip_sin_extension_se_registra_como_skipped_y_no_es_ok(tmp_path):
    entrada = tmp_path / "entrada.zip"
    entrada.write_bytes(_zip_bytes([("datos.bin", _zip_bytes([("a.txt", "x")]))]))

    res = run_pipeline(entrada, _settings(tmp_path))

    assert res.status != "ok", res.to_dict()
    e = _entry(res, "datos.bin")
    assert e.action == "skipped"
    assert e.error["code"] == "zip_by_content_not_expanded"
    assert res.skipped_files == 1
    assert res.copied_files == 0


def test_zip_sin_extension_anidado_en_otro_zip_tambien_se_registra(tmp_path):
    interior = _zip_bytes([("oculto.bin", _zip_bytes([("h.txt", "hola")]))])
    entrada = tmp_path / "entrada.zip"
    entrada.write_bytes(_zip_bytes([("nivel1.zip", interior)]))

    res = run_pipeline(entrada, _settings(tmp_path))

    assert res.status != "ok", res.to_dict()
    assert _entry(res, "nivel1/oculto.bin").error["code"] == "zip_by_content_not_expanded"


def test_docx_dentro_de_paquete_mixto_da_partial(tmp_path):
    # Un .docx también es un zip por dentro. Con otros archivos válidos el
    # resultado es partial, no ok, porque el docx no se analizó.
    entrada = tmp_path / "entrada.zip"
    entrada.write_bytes(_zip_bytes([
        ("doc.docx", _zip_bytes([("word/document.xml", "<x/>")])),
        ("LEEME.txt", "hola"),
    ]))

    res = run_pipeline(entrada, _settings(tmp_path))

    assert res.status == "partial", res.to_dict()
    assert _entry(res, "doc.docx").action == "skipped"
    assert _entry(res, "LEEME.txt").action == "copied"


def test_texto_plano_no_se_ve_afectado(tmp_path):
    # Control: un archivo de texto sigue copiándose sin marcar problemas.
    entrada = tmp_path / "entrada.zip"
    entrada.write_bytes(_zip_bytes([("LEEME.txt", "hola")]))

    res = run_pipeline(entrada, _settings(tmp_path))

    assert res.status == "ok", res.to_dict()
    assert _entry(res, "LEEME.txt").action == "copied"
