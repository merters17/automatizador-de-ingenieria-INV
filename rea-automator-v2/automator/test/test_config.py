"""Validación de configuración: timeouts y límites de salida/entrada.

Antes, `load_settings` aceptaba -1, nan, inf, 0 y -3 sin quejarse; un timeout NaN
o negativo y un tope de stdout negativo llegaban hasta los subprocesos.
"""

from pathlib import Path

import pytest

from rea_automator.config import ConfigError, Settings, load_settings
from rea_automator.pipeline import run_pipeline


@pytest.mark.parametrize("valor", ["-1", "nan", "NaN", "inf", "-inf", "0", "abc", ""])
def test_timeout_env_invalido_se_rechaza(valor):
    with pytest.raises(ConfigError, match="REA_AUTOMATOR_TIMEOUT_S"):
        load_settings(env={"REA_AUTOMATOR_TIMEOUT_S": valor})


@pytest.mark.parametrize("valor", [-5, float("nan"), float("inf"), 0])
def test_timeout_argumento_invalido_se_rechaza(valor):
    with pytest.raises(ConfigError, match="--timeout"):
        load_settings(timeout_s=valor, env={})


@pytest.mark.parametrize("valor", ["-3", "0", "1.5", "abc"])
def test_max_stdout_invalido_se_rechaza(valor):
    with pytest.raises(ConfigError, match="REA_AUTOMATOR_MAX_STDOUT"):
        load_settings(env={"REA_AUTOMATOR_MAX_STDOUT": valor})


@pytest.mark.parametrize("valor", ["-1", "0"])
def test_max_stderr_invalido_se_rechaza(valor):
    with pytest.raises(ConfigError, match="REA_AUTOMATOR_MAX_STDERR"):
        load_settings(env={"REA_AUTOMATOR_MAX_STDERR": valor})


def test_valores_validos_se_aceptan():
    s = load_settings(
        timeout_s=None,
        env={
            "REA_AUTOMATOR_TIMEOUT_S": "60",
            "REA_AUTOMATOR_MAX_STDOUT": "1048576",
            "REA_AUTOMATOR_MAX_STDERR": "4096",
        },
    )
    assert s.timeout_s == 60.0
    assert s.max_stdout_bytes == 1048576
    assert s.max_stderr_bytes == 4096


def test_settings_directo_tambien_valida():
    # Construir Settings a mano no debe saltarse la validación.
    with pytest.raises(ConfigError, match="timeout_s"):
        Settings(
            rea_argv=("rea",), native_provider="ghidra", timeout_s=float("nan"),
            max_stdout_bytes=1, max_stderr_bytes=1, out_dir=Path("/tmp"),
        )
    with pytest.raises(ConfigError, match="max_stdout_bytes"):
        Settings(
            rea_argv=("rea",), native_provider="ghidra", timeout_s=10.0,
            max_stdout_bytes=-3, max_stderr_bytes=1, out_dir=Path("/tmp"),
        )


@pytest.mark.parametrize("kwargs, campo", [
    ({"max_files": -1}, "max_files"),
    ({"max_files": 0}, "max_files"),
    ({"max_bytes": -10}, "max_bytes"),
    ({"max_bytes": 0}, "max_bytes"),
])
def test_pipeline_limites_invalidos_fallan_antes_de_tocar_disco(tmp_path, kwargs, campo):
    settings = load_settings(out_dir=tmp_path / "out", timeout_s=20, env={})
    with pytest.raises(ConfigError, match=campo):
        run_pipeline(tmp_path / "no_importa.zip", settings, **kwargs)
    # Validar antes significa que no se creó ni la carpeta de salida.
    assert not (tmp_path / "out").exists()
