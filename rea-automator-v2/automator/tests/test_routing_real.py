"""Enrutamiento sobre binarios REALES compilados en Linux (no sintéticos).

- hello_elf: ELF x86-64 compilado con gcc.
- hello_pe.exe: PE32+ compilado con x86_64-w64-mingw32-gcc (sin CLI header).
- managedapp.dll: ensamblado .NET 8 compilado con dotnet build (con CLI header).
"""
from pathlib import Path

from rea_automator.routing import FAMILY_MANAGED, FAMILY_NATIVE, route, byte_kind

REAL = Path(__file__).parent / "fixtures" / "real"


def test_real_elf_routes_native():
    assert byte_kind(REAL / "hello_elf") == "elf"
    assert route(REAL / "hello_elf").family == FAMILY_NATIVE


def test_real_native_pe_is_not_managed():
    assert byte_kind(REAL / "hello_pe.exe") == "pe-native"
    assert route(REAL / "hello_pe.exe").family == FAMILY_NATIVE


def test_real_dotnet_assembly_routes_managed():
    assert byte_kind(REAL / "managedapp.dll") == "pe-managed"
    assert route(REAL / "managedapp.dll").family == FAMILY_MANAGED
