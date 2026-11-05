
import pytest

from rea_automator import routing
from rea_automator.routing import (
    FAMILY_ANDROID, FAMILY_JS, FAMILY_MANAGED, FAMILY_NATIVE, RoutingError, route,
)

from . import fakes


def test_directory_routes_to_js_like_rea_analyze(tmp_path):
    d = tmp_path / "game"
    d.mkdir()
    assert route(d).family == FAMILY_JS


def test_app_bundle_routes_native(tmp_path):
    d = tmp_path / "Game.app"
    d.mkdir()
    assert route(d).family == FAMILY_NATIVE


def test_pe_managed(tmp_path):
    p = fakes.pe(tmp_path / "Assembly-CSharp.dll", managed=True)
    assert routing.byte_kind(p) == "pe-managed"
    assert route(p).family == FAMILY_MANAGED


def test_pe_native(tmp_path):
    p = fakes.pe(tmp_path / "GameAssembly.dll", managed=False)
    assert routing.byte_kind(p) == "pe-native"
    assert route(p).family == FAMILY_NATIVE


def test_pe32_32bit_native(tmp_path):
    p = fakes.pe(tmp_path / "old.exe", managed=False, pe32plus=False)
    assert route(p).family == FAMILY_NATIVE


def test_elf_without_extension_routes_native(tmp_path):
    p = fakes.elf(tmp_path / "MyGame.x86_64")
    assert route(p).family == FAMILY_NATIVE


def test_macho_thin_and_fat_route_native(tmp_path):
    assert route(fakes.macho_thin(tmp_path / "a")).family == FAMILY_NATIVE
    assert route(fakes.macho_fat(tmp_path / "b")).family == FAMILY_NATIVE


def test_java_class_is_not_macho_fat(tmp_path):
    p = fakes.java_class(tmp_path / "Main.class")
    with pytest.raises(RoutingError) as e:
        route(p)
    assert e.value.code == "unknown_format"


def test_text_starting_with_mz_is_rejected(tmp_path):
    p = tmp_path / "notes.exe"
    p.write_text("MZ this is just text, not a PE file at all\n")
    with pytest.raises(RoutingError) as e:
        route(p)
    assert e.value.code == "unknown_format"


def test_asar_routes_js(tmp_path):
    assert route(fakes.asar(tmp_path / "app.asar")).family == FAMILY_JS


def test_apk_routes_android(tmp_path):
    assert route(fakes.zipfile_bytes(tmp_path / "game.apk")).family == FAMILY_ANDROID


def test_plain_zip_without_known_extension_is_not_guessed(tmp_path):
    with pytest.raises(RoutingError) as e:
        route(fakes.zipfile_bytes(tmp_path / "bundle.zip"))
    assert e.value.code == "unknown_format"


def test_asar_extension_with_elf_bytes_is_ambiguous(tmp_path):
    p = fakes.elf(tmp_path / "weird.asar")
    with pytest.raises(RoutingError) as e:
        route(p)
    assert e.value.code == "ambiguous"
    assert set(e.value.candidates) == {FAMILY_JS, FAMILY_NATIVE}


def test_apk_extension_with_elf_bytes_is_ambiguous(tmp_path):
    p = fakes.elf(tmp_path / "tricky.apk")
    with pytest.raises(RoutingError) as e:
        route(p)
    assert e.value.code == "ambiguous"


def test_missing_target(tmp_path):
    with pytest.raises(RoutingError) as e:
        route(tmp_path / "nope")
    assert e.value.code == "not_found"


def test_unreadable_file_is_routing_error_not_crash(tmp_path, monkeypatch):
    p = fakes.elf(tmp_path / "locked.bin")

    def boom(_):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(routing, "byte_kind", boom)
    with pytest.raises(RoutingError) as e:
        route(p)
    assert e.value.code == "unreadable"
