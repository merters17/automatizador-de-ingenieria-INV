"""Pruebas del flujo zip -> descompilado -> zip final. Usan herramientas simuladas
(fake_bulk_tool.py) para no depender de jadx/ilspycmd/Ghidra reales."""

import json
from dataclasses import replace
import sys
import zipfile
from pathlib import Path

import pytest

from rea_automator.config import load_settings
from rea_automator.pipeline import run_pipeline

from . import fakes

FAKE_TOOL = str(Path(__file__).parent / "fake_bulk_tool.py")


@pytest.fixture
def settings(tmp_path, monkeypatch):
    cmd = f"{sys.executable} {FAKE_TOOL}"
    monkeypatch.setenv("REA_AUTOMATOR_ILSPYCMD_CMD", cmd)
    monkeypatch.setenv("REA_AUTOMATOR_GHIDRA_HEADLESS_CMD", cmd)
    settings = load_settings(out_dir=tmp_path / "out", timeout_s=20)
    return replace(settings, jadx_argv=(sys.executable, FAKE_TOOL))


def _names(zip_path: Path) -> set[str]:
    with zipfile.ZipFile(zip_path) as zf:
        return set(zf.namelist())


def test_zip_with_managed_native_and_plain_files(settings, tmp_path):
    src = tmp_path / "entrada"
    (src / "bin").mkdir(parents=True)
    fakes.pe(src / "bin" / "app.dll", managed=True)
    fakes.elf(src / "bin" / "tool")
    (src / "LEEME.txt").write_text("hola")
    entrada = tmp_path / "entrada.zip"
    with zipfile.ZipFile(entrada, "w") as zf:
        zf.write(src / "bin" / "app.dll", "bin/app.dll")
        zf.write(src / "bin" / "tool", "bin/tool")
        zf.write(src / "LEEME.txt", "LEEME.txt")

    res = run_pipeline(entrada, settings)

    assert res.status == "ok", res.to_dict()
    assert res.decompiled_targets == 2
    assert res.copied_files == 1
    names = _names(Path(res.output_zip))
    assert "decompilado/bin/app.dll/a.cs" in names
    assert "decompilado/bin/tool/a.c" in names
    assert "otros_archivos/LEEME.txt" in names
    assert "report.json" in names


def test_nested_zip_is_extracted_and_processed(settings, tmp_path):
    inner = tmp_path / "interno.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("dentro.txt", "contenido")
    entrada = tmp_path / "entrada.zip"
    with zipfile.ZipFile(entrada, "w") as zf:
        zf.write(inner, "interno.zip")

    res = run_pipeline(entrada, settings)

    assert res.status == "ok", res.to_dict()
    names = _names(Path(res.output_zip))
    assert "otros_archivos/interno/dentro.txt" in names
    assert not any(n.endswith("interno.zip") for n in names)


def test_zip_slip_is_rejected(settings, tmp_path):
    entrada = tmp_path / "malo.zip"
    with zipfile.ZipFile(entrada, "w") as zf:
        zf.writestr("../escapa.txt", "x")

    res = run_pipeline(entrada, settings)

    assert res.status == "failed"
    assert res.error["code"] == "unsafe_path"
    assert res.output_zip is None


def test_too_many_files_is_rejected(settings, tmp_path):
    entrada = tmp_path / "grande.zip"
    with zipfile.ZipFile(entrada, "w") as zf:
        for i in range(5):
            zf.writestr(f"f{i}.txt", "x")

    res = run_pipeline(entrada, settings, max_files=2)

    assert res.status == "failed"
    assert res.error["code"] == "too_many_files"


def test_failed_tool_keeps_its_logs_in_output(tmp_path, monkeypatch):
    # ilspycmd no existe: el binario .NET debe fallar, quedar reportado y con log.
    monkeypatch.setenv("REA_AUTOMATOR_ILSPYCMD_CMD", "comando-que-no-existe-xyz")
    settings = load_settings(out_dir=tmp_path / "out", timeout_s=20)
    src = tmp_path / "entrada"
    src.mkdir()
    fakes.pe(src / "app.dll", managed=True)
    entrada = tmp_path / "entrada.zip"
    with zipfile.ZipFile(entrada, "w") as zf:
        zf.write(src / "app.dll", "app.dll")

    res = run_pipeline(entrada, settings)

    assert res.status == "failed"
    assert res.failed_targets == 1
    report = json.loads(zipfile.ZipFile(res.output_zip).read("report.json"))
    entry = report["entries"][0]
    assert entry["action"] == "failed"
    assert entry["decompile_status"] == "command_not_found"


def test_single_non_zip_file_is_processed(settings, tmp_path):
    f = tmp_path / "suelto.exe"
    fakes.pe(f, managed=True)

    res = run_pipeline(f, settings)

    assert res.status == "ok", res.to_dict()
    assert "decompilado/suelto.exe/a.cs" in _names(Path(res.output_zip))


def test_keep_originals_false_drops_plain_files(settings, tmp_path):
    entrada = tmp_path / "solo_texto.zip"
    with zipfile.ZipFile(entrada, "w") as zf:
        zf.writestr("notas.txt", "x")

    res = run_pipeline(entrada, settings, keep_originals=False)

    assert res.status == "ok"
    assert not any(n.startswith("otros_archivos/") for n in _names(Path(res.output_zip)))


def test_ambiguous_only_is_skipped_and_original_is_preserved(settings, tmp_path):
    # La extensión dice APK, pero los bytes corresponden a ELF: no se debe
    # declarar éxito ni perder el archivo original.
    src = tmp_path / "app.apk"
    fakes.elf(src)

    res = run_pipeline(src, settings)

    assert res.status == "skipped"
    assert res.skipped_files == 1
    assert res.entries[0].action == "ambiguous"
    with zipfile.ZipFile(res.output_zip) as zf:
        assert "otros_archivos/app.apk" in zf.namelist()
        report = json.loads(zf.read("report.json"))
    assert report["status"] == "skipped"
    assert report["summary"]["skipped_files"] == 1


def test_success_plus_ambiguous_is_partial(settings, tmp_path):
    src = tmp_path / "entrada"
    src.mkdir()
    fakes.elf(src / "fake.apk")
    (src / "readme.txt").write_text("original")

    res = run_pipeline(src, settings)

    assert res.status == "partial"
    assert res.copied_files == 1
    assert res.skipped_files == 1
    with zipfile.ZipFile(res.output_zip) as zf:
        report = json.loads(zf.read("report.json"))
    assert report["status"] == "partial"


def test_partial_tool_exit_is_not_reported_as_ok(settings, tmp_path, monkeypatch):
    tool = tmp_path / "partial_tool.py"
    tool.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "a=sys.argv[1:]\n"
        "out=Path(a[a.index('-o')+1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out/'Recovered.cs').write_text('// partial result')\n"
        "sys.exit(3)\n"
    )
    monkeypatch.setenv("REA_AUTOMATOR_ILSPYCMD_CMD", f"{sys.executable} {tool}")
    s = load_settings(out_dir=tmp_path / "out", timeout_s=20)
    src = tmp_path / "app.dll"
    fakes.pe(src, managed=True)

    res = run_pipeline(src, s)

    assert res.status == "partial"
    assert res.partial_targets == 1
    assert res.failed_targets == 0
    assert res.entries[0].action == "partial"
    assert res.entries[0].decompile_status == "partial"
    with zipfile.ZipFile(res.output_zip) as zf:
        report = json.loads(zf.read("report.json"))
        assert "decompilado/app.dll/Recovered.cs" in zf.namelist()
    assert report["status"] == "partial"
    assert report["summary"]["partial_targets"] == 1


def test_bad_zip_extension_is_rejected_not_ok(settings, tmp_path):
    # Extensión .zip pero contenido que no es un zip real (texto plano
    # renombrado, cabecera corrupta, truncado, etc.). No debe tratarse como
    # "archivo suelto" y reportarse ok: debe detenerse con bad_zip.
    src = tmp_path / "roto.zip"
    src.write_text("esto es texto plano, no un zip real")

    res = run_pipeline(src, settings)

    assert res.status == "failed"
    assert res.output_zip is None
    assert res.error == {
        "code": "bad_zip",
        "message": "la extensión es .zip pero el contenido no es un zip válido: roto.zip",
    }


def test_empty_zip_is_skipped_not_ok(settings, tmp_path):
    src = tmp_path / "vacio.zip"
    with zipfile.ZipFile(src, "w"):
        pass

    res = run_pipeline(src, settings)

    assert res.status == "skipped"
    assert res.output_zip is not None
    with zipfile.ZipFile(res.output_zip) as zf:
        report = json.loads(zf.read("report.json"))
    assert report["status"] == "skipped"
    assert report["entries"] == []
