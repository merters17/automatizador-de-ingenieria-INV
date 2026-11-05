"""Constructores de archivos sintéticos con las cabeceras exactas que lee routing.py."""
import struct
import zipfile
from pathlib import Path


def pe(path: Path, *, managed: bool, pe32plus: bool = True) -> Path:
    """PE mínimo con una sección en RVA 0x1000. managed -> COM descriptor dentro de la sección."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    opt_size = 240
    struct.pack_into("<HH", buf, e_lfanew + 4, 0x8664, 1)  # machine, nsections
    struct.pack_into("<H", buf, e_lfanew + 20, opt_size)
    opt = e_lfanew + 24
    magic = 0x20B if pe32plus else 0x10B
    struct.pack_into("<H", buf, opt, magic)
    dd_start = 112 if pe32plus else 96
    struct.pack_into("<I", buf, opt + (108 if pe32plus else 92), 16)
    if managed:
        struct.pack_into("<II", buf, opt + dd_start + 14 * 8, 0x1000, 0x48)
    sec = opt + opt_size
    # nombre(8) vsize va rawsize rawptr
    struct.pack_into("<II", buf, sec + 8, 0x100, 0x1000)
    struct.pack_into("<II", buf, sec + 16, 0x200, 0x200)
    path.write_bytes(bytes(buf))
    return path


def elf(path: Path) -> Path:
    path.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return path


def macho_thin(path: Path) -> Path:
    path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
    return path


def macho_fat(path: Path) -> Path:
    path.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 56)
    return path


def java_class(path: Path) -> Path:
    # CAFEBABE + minor(0) + major(52): nfat=52 > 20, no debe clasificarse como Mach-O fat.
    path.write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + b"\x00" * 56)
    return path


def asar(path: Path) -> Path:
    header = bytearray(32)
    struct.pack_into("<I", header, 0, 4)     # size pickle
    struct.pack_into("<I", header, 4, 32)    # header size
    struct.pack_into("<I", header, 8, 28)    # payload = header-4
    struct.pack_into("<I", header, 12, 20)   # string length
    header[16:17] = b"{"
    path.write_bytes(bytes(header) + b"}" + b"\x00" * 64)
    return path


def zipfile_bytes(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 60)
    return path


def dex_bytes(descriptors: list[str], flags: list[int] | None = None) -> bytes:
    """DEX mínimo y válido para el lector de dexinfo: cabecera + string_ids + type_ids +
    class_defs + datos de cadenas. Cada descriptor debe medir menos de 128 caracteres."""
    n = len(descriptors)
    flags = flags or [0] * n
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * n
    class_defs_off = type_ids_off + 4 * n
    data_off = class_defs_off + 32 * n
    blob = bytearray()
    string_offsets = []
    for descriptor in descriptors:
        string_offsets.append(data_off + len(blob))
        blob += bytes([len(descriptor)]) + descriptor.encode("utf-8") + b"\x00"  # uleb128 de 1 byte
    buf = bytearray(data_off + len(blob))
    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 0x20, len(buf))
    struct.pack_into("<I", buf, 0x24, header_size)
    struct.pack_into("<I", buf, 0x28, 0x12345678)
    struct.pack_into("<II", buf, 0x38, n, string_ids_off)
    struct.pack_into("<II", buf, 0x40, n, type_ids_off)
    struct.pack_into("<II", buf, 0x60, n, class_defs_off)
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", buf, string_ids_off + 4 * i, offset)
        struct.pack_into("<I", buf, type_ids_off + 4 * i, i)  # type i -> cadena i
        struct.pack_into("<II", buf, class_defs_off + 32 * i, i, flags[i])
    buf[data_off:] = blob
    return bytes(buf)


def apk(path: Path, descriptors: list[str], *, dex_name: str = "classes.dex") -> Path:
    """APK sintético: AndroidManifest.xml + un classes*.dex con las clases dadas."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr(dex_name, dex_bytes(descriptors))
    return path
