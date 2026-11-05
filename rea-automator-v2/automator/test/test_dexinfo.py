"""Lector de DEX (dexinfo): clases, banderas, APK con varios dex, entradas corruptas y comparación con .java."""

import struct
import zipfile

import pytest

from rea_automator.dexinfo import (
    ACC_SYNTHETIC,
    DexError,
    compare_with_java_files,
    expected_java_paths,
    parse_dex,
    scan_apk,
)

from . import fakes


def test_parse_dex_returns_descriptors_and_flags():
    data = fakes.dex_bytes(["La/B;", "Lc/D$E;"], flags=[0x1, ACC_SYNTHETIC])
    classes = parse_dex(data, "classes.dex")
    assert [c.descriptor for c in classes] == ["La/B;", "Lc/D$E;"]
    assert [c.synthetic for c in classes] == [False, True]
    assert {c.dex for c in classes} == {"classes.dex"}


@pytest.mark.parametrize("data", [b"", b"nada", b"dex\n035\x00" + b"\x00" * 10])
def test_parse_dex_rejects_garbage(data):
    with pytest.raises(DexError):
        parse_dex(data)


def test_parse_dex_rejects_offsets_outside_the_file():
    data = bytearray(fakes.dex_bytes(["La/B;"]))
    struct.pack_into("<II", data, 0x60, 1, len(data) + 1000)  # class_defs fuera del archivo
    with pytest.raises((DexError, struct.error)):
        parse_dex(bytes(data))


def test_scan_apk_reads_all_dex_in_numeric_order(tmp_path):
    path = tmp_path / "multi.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes10.dex", fakes.dex_bytes(["Lz/Ten;"]))
        zf.writestr("classes2.dex", fakes.dex_bytes(["Lz/Two;"]))
        zf.writestr("classes.dex", fakes.dex_bytes(["Lz/One;", "Lz/Uno;"]))
        zf.writestr("assets/classes3.dex", fakes.dex_bytes(["Lz/NoCuenta;"]))  # no está en la raíz
    scan = scan_apk(path)
    assert list(scan.dex_files) == ["classes.dex", "classes2.dex", "classes10.dex"]
    assert scan.dex_files == {"classes.dex": 2, "classes2.dex": 1, "classes10.dex": 1}
    assert len(scan.classes) == 4
    assert scan.errors == []


def test_scan_apk_collects_errors_instead_of_raising(tmp_path):
    path = tmp_path / "mixed.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", fakes.dex_bytes(["La/Ok;"]))
        zf.writestr("classes2.dex", b"esto no es un dex")
    scan = scan_apk(path)
    assert scan.dex_files == {"classes.dex": 1}
    assert len(scan.errors) == 1 and scan.errors[0].startswith("classes2.dex:")


def test_scan_apk_on_non_zip_reports_error(tmp_path):
    path = tmp_path / "no.apk"
    path.write_bytes(b"no soy un zip")
    scan = scan_apk(path)
    assert scan.classes == [] and scan.errors


@pytest.mark.parametrize(
    "descriptor, expected",
    [
        ("Lcom/foo/Bar;", ("com/foo/Bar.java", "com/foo/Bar.java")),
        ("Lcom/foo/Bar$Baz;", ("com/foo/Bar.java", "com/foo/Bar$Baz.java")),
        ("La;", ("defpackage/a.java", "defpackage/a.java")),          # sin paquete -> defpackage
        ("La$b;", ("defpackage/a.java", "defpackage/a$b.java")),
    ],
)
def test_expected_java_paths(descriptor, expected):
    assert expected_java_paths(descriptor) == expected


def test_compare_with_java_files_counts_and_classifies_missing():
    classes = parse_dex(fakes.dex_bytes(
        ["Lp/A;", "Lp/A$In;", "Lp/Falta;", "Lp/Sint;", "Lp/Otra;"],
        flags=[0, 0, 0, ACC_SYNTHETIC, 0],
    ))
    cov = compare_with_java_files(classes, {"p/A.java", "p/Otra.java"})
    assert (cov.total, cov.with_own_file, cov.without_own_file) == (5, 3, 2)  # A$In se pliega en A.java
    assert cov.without_own_file_synthetic == 1
    assert cov.without_own_file_not_synthetic == 1
    assert cov.examples_not_synthetic == ["classes.dex: Lp/Falta;"]
    assert cov.to_dict()["coverage_pct"] == 60.0


def test_compare_with_no_classes_has_zero_ratio():
    assert compare_with_java_files([], set()).ratio == 0.0
