"""Lector mínimo de DEX (solo biblioteca estándar) para contrastar el resultado de JADX con el APK.

Lee únicamente las tablas `string_ids`, `type_ids` y `class_defs` de cada `classes*.dex` del
APK y devuelve la lista de clases con sus banderas de acceso. No ejecuta nada del APK y cada
lectura está acotada (tamaño del DEX, cantidad de clases), porque el APK es un archivo no
confiable. Cualquier irregularidad se informa como `DexError` / `DexScan.errors`, nunca se
adivina.

Sirve para una comprobación objetiva contra el APK: cuántas de las clases que el APK define
tienen un `.java` propio en lo recuperado. Es informativa; no sustituye a JADX.
"""

from __future__ import annotations

import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ACC_SYNTHETIC = 0x1000
MAX_DEX_BYTES = 256 * 1024 * 1024
MAX_CLASSES_PER_DEX = 1_000_000
_HEADER_SIZE = 0x70
_DEX_NAME_RE = re.compile(r"classes\d*\.dex")  # solo en la raíz del APK (fullmatch)


class DexError(ValueError):
    """El DEX no se pudo interpretar con seguridad."""


@dataclass(frozen=True)
class DexClass:
    descriptor: str  # 'Lcom/foo/Bar$Baz;'
    flags: int
    dex: str  # 'classes2.dex'

    @property
    def synthetic(self) -> bool:
        return bool(self.flags & ACC_SYNTHETIC)


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(5):  # un uleb128 de 32 bits ocupa como máximo 5 bytes
        if pos >= len(data):
            raise DexError("uleb128 truncado")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
    raise DexError("uleb128 demasiado largo")


def parse_dex(data: bytes, dex_name: str = "classes.dex") -> list[DexClass]:
    """Devuelve las clases definidas en un DEX (descriptor + banderas de acceso)."""
    if len(data) < _HEADER_SIZE or data[:4] != b"dex\n" or data[7:8] != b"\x00":
        raise DexError(f"{dex_name}: no es un DEX (cabecera inválida)")
    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
    type_ids_size, type_ids_off = struct.unpack_from("<II", data, 0x40)
    class_defs_size, class_defs_off = struct.unpack_from("<II", data, 0x60)
    if class_defs_size > MAX_CLASSES_PER_DEX:
        raise DexError(f"{dex_name}: declara {class_defs_size} clases (máximo {MAX_CLASSES_PER_DEX})")
    for table, offset, size, item in (
        ("string_ids", string_ids_off, string_ids_size, 4),
        ("type_ids", type_ids_off, type_ids_size, 4),
        ("class_defs", class_defs_off, class_defs_size, 32),
    ):
        if offset + size * item > len(data):
            raise DexError(f"{dex_name}: la tabla {table} no cabe en el archivo")

    classes: list[DexClass] = []
    for i in range(class_defs_size):
        class_idx, flags = struct.unpack_from("<II", data, class_defs_off + 32 * i)
        if class_idx >= type_ids_size:
            raise DexError(f"{dex_name}: class_def {i} apunta a un type_id inexistente")
        (descriptor_idx,) = struct.unpack_from("<I", data, type_ids_off + 4 * class_idx)
        if descriptor_idx >= string_ids_size:
            raise DexError(f"{dex_name}: type_id {class_idx} apunta a una cadena inexistente")
        (string_off,) = struct.unpack_from("<I", data, string_ids_off + 4 * descriptor_idx)
        _, start = _uleb128(data, string_off)
        end = data.find(b"\x00", start)
        if end < 0:
            raise DexError(f"{dex_name}: cadena sin terminador")
        classes.append(DexClass(data[start:end].decode("utf-8", errors="replace"), flags, dex_name))
    return classes


@dataclass
class DexScan:
    classes: list[DexClass] = field(default_factory=list)
    dex_files: dict[str, int] = field(default_factory=dict)  # nombre -> cantidad de clases
    errors: list[str] = field(default_factory=list)


def _dex_sort_key(name: str) -> int:
    digits = re.sub(r"\D", "", name)
    return int(digits) if digits else 1


def scan_apk(apk_path: str | Path) -> DexScan:
    """Lista las clases de todos los `classes*.dex` del APK. No lanza: los fallos van a `errors`."""
    scan = DexScan()
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        scan.errors.append(f"no se pudo abrir el APK como zip: {exc}")
        return scan
    with zf:
        dex_infos = [i for i in zf.infolist() if _DEX_NAME_RE.fullmatch(i.filename)]
        for info in sorted(dex_infos, key=lambda i: _dex_sort_key(i.filename)):
            if info.file_size > MAX_DEX_BYTES:
                scan.errors.append(
                    f"{info.filename}: {info.file_size} bytes superan el límite de lectura ({MAX_DEX_BYTES})"
                )
                continue
            try:
                with zf.open(info) as handle:
                    data = handle.read(MAX_DEX_BYTES + 1)
                if len(data) > MAX_DEX_BYTES:
                    raise DexError(f"{info.filename}: el contenido real supera el límite de lectura")
                classes = parse_dex(data, info.filename)
            except (DexError, struct.error, zipfile.BadZipFile, zlib.error, EOFError, OSError) as exc:
                scan.errors.append(f"{info.filename}: {exc}")
                continue
            scan.dex_files[info.filename] = len(classes)
            scan.classes.extend(classes)
    return scan


def expected_java_paths(descriptor: str) -> tuple[str, str]:
    """'Lcom/foo/Bar$Baz;' -> ('com/foo/Bar.java', 'com/foo/Bar$Baz.java').

    Las clases sin paquete van a `defpackage/` en JADX. JADX pliega una clase interna dentro
    del archivo de la externa; si la externa no está en el APK guarda la interna como
    `Externa$Interna.java`. Por eso se aceptan los dos nombres.
    """
    inner = descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
    package, sep, cls = inner.rpartition("/")
    if not sep:
        package = "defpackage"
    top = cls.split("$", 1)[0]
    return f"{package}/{top}.java", f"{package}/{cls}.java"


@dataclass
class DexCoverage:
    total: int
    with_own_file: int
    without_own_file: int
    without_own_file_synthetic: int
    without_own_file_not_synthetic: int
    examples_not_synthetic: list[str]

    @property
    def ratio(self) -> float:
        return self.with_own_file / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "classes_in_apk": self.total,
            "with_own_java_file": self.with_own_file,
            "without_own_java_file": self.without_own_file,
            "without_own_java_file_synthetic": self.without_own_file_synthetic,
            "without_own_java_file_not_synthetic": self.without_own_file_not_synthetic,
            "examples_without_file_not_synthetic": self.examples_not_synthetic,
            "coverage_pct": round(100.0 * self.ratio, 1),
        }


def compare_with_java_files(classes: list[DexClass], java_paths: set[str]) -> DexCoverage:
    """Cuántas clases del APK tienen un `.java` propio. `java_paths` son rutas relativas a `sources/`.

    Coincidencia por nombre exacto: JADX renombra las clases cuyo nombre es una palabra
    reservada de Java (p. ej. `do` -> `C0000do.java`), que aquí cuentan como "sin archivo
    propio". Es una métrica informativa, no una prueba formal.
    """
    with_file = 0
    missing: list[DexClass] = []
    for cls in classes:
        if any(path in java_paths for path in expected_java_paths(cls.descriptor)):
            with_file += 1
        else:
            missing.append(cls)
    synthetic = sum(1 for c in missing if c.synthetic)
    not_synthetic = [c for c in missing if not c.synthetic]
    return DexCoverage(
        total=len(classes),
        with_own_file=with_file,
        without_own_file=len(missing),
        without_own_file_synthetic=synthetic,
        without_own_file_not_synthetic=len(not_synthetic),
        examples_not_synthetic=[f"{c.dex}: {c.descriptor}" for c in not_synthetic[:10]],
    )
