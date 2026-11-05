"""Enrutamiento por forma del objetivo: bytes primero, extensión como pista.

No detecta motores de juego. Solo decide qué comando de rea corresponde a la
forma del objetivo. Si la extensión y los bytes apuntan a familias distintas,
devuelve error `ambiguous` en lugar de elegir por orden.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

FAMILY_JS = "javascript-application"
FAMILY_ANDROID = "android-package"
FAMILY_MANAGED = "managed-pe"
FAMILY_NATIVE = "native-binary"

FAMILIES = (FAMILY_JS, FAMILY_ANDROID, FAMILY_MANAGED, FAMILY_NATIVE)

# Magic bytes de los kinds que reconoce el clasificador de bytes.
_ELF = b"\x7fELF"
_MACHO_THIN = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
               b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
_MACHO_FAT = b"\xca\xfe\xba\xbe"
_ZIP = b"PK\x03\x04"
_MAX_FAT_ARCHS = 20  # CAFEBABE también es el magic de Java class: el número de archs separa ambos.


class RoutingError(Exception):
    """El objetivo no puede enrutarse. `code` es estable para consumidores."""

    def __init__(self, code: str, message: str, candidates: tuple[str, ...] = ()):
        super().__init__(message)
        self.code = code
        self.message = message
        self.candidates = candidates


@dataclass(frozen=True)
class Route:
    family: str
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {"family": self.family, "reasons": list(self.reasons)}


# ── Clasificación por bytes ──────────────────────────────────────────────────

def _read(path: Path, offset: int, size: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(size)


def is_asar(path: Path) -> bool:
    """Cabecera ASAR de Electron: size pickle = 4, header pickle, JSON que empieza con '{'."""
    prefix = _read(path, 0, 17)
    if len(prefix) < 17 or struct.unpack_from("<I", prefix, 0)[0] != 4:
        return False
    header_size = struct.unpack_from("<I", prefix, 4)[0]
    payload_size = struct.unpack_from("<I", prefix, 8)[0]
    if header_size < 16 or payload_size != header_size - 4:
        return False
    string_len = struct.unpack_from("<I", prefix, 12)[0]
    return 2 <= string_len <= payload_size - 4 and prefix[16:17] == b"{"


def _pe_kind(path: Path) -> str | None:
    """'pe-managed', 'pe-native' o None si la cabecera MZ/PE no es válida."""
    size = path.stat().st_size
    head = _read(path, 0, 64)
    if len(head) < 64 or head[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew < 64 or e_lfanew + 24 > size:
        return None
    coff = _read(path, e_lfanew, 24)
    if coff[:4] != b"PE\x00\x00":
        return None
    n_sections = struct.unpack_from("<H", coff, 6)[0]
    opt_size = struct.unpack_from("<H", coff, 20)[0]
    opt_off = e_lfanew + 24
    opt = _read(path, opt_off, min(opt_size, 240))
    if len(opt) < 2:
        return None
    magic = struct.unpack_from("<H", opt, 0)[0]
    if magic == 0x10B:
        dd_start = 96
    elif magic == 0x20B:
        dd_start = 112
    else:
        return None
    if len(opt) < dd_start + 15 * 8:
        return "pe-native"  # sin directorio COM: sin CLI header
    com_rva, com_size = struct.unpack_from("<II", opt, dd_start + 14 * 8)
    if com_rva == 0 or com_size == 0:
        return "pe-native"
    # Convertir RVA a offset de archivo con la tabla de secciones.
    sec_off = opt_off + opt_size
    sections = _read(path, sec_off, n_sections * 40)
    for i in range(n_sections):
        base = i * 40
        if base + 40 > len(sections):
            break
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", sections, base + 8)
        span = max(vsize, raw_size)
        if va <= com_rva < va + span:
            return "pe-managed"
    return "pe-native"  # RVA fuera de secciones: se deja que rea lo rechace


def byte_kind(path: Path) -> str | None:
    """Clasifica por bytes. Devuelve un kind o None si no hay firma reconocida."""
    head = _read(path, 0, 4)
    if head == _ZIP:
        return "zip"
    if is_asar(path):
        return "asar"
    if head == _ELF:
        return "elf"
    if head in _MACHO_THIN:
        return "macho"
    if head == _MACHO_FAT:
        raw_nfat = _read(path, 4, 4)
        if len(raw_nfat) != 4:
            # Cabecera truncada: no hay forma de leer nfat_arch. Se trata como
            # formato no reconocido, no como una excepción inesperada.
            return None
        nfat = struct.unpack(">I", raw_nfat)[0]
        return "macho" if 1 <= nfat <= _MAX_FAT_ARCHS else None
    if head[:2] == b"MZ":
        return _pe_kind(path)
    return None


_KIND_TO_FAMILY = {
    "asar": FAMILY_JS,
    "elf": FAMILY_NATIVE,
    "macho": FAMILY_NATIVE,
    "pe-native": FAMILY_NATIVE,
    "pe-managed": FAMILY_MANAGED,
}

_EXT_TO_FAMILY = {".asar": FAMILY_JS, ".apk": FAMILY_ANDROID}


# ── Enrutamiento ─────────────────────────────────────────────────────────────

def route(path: str | Path) -> Route:
    p = Path(path)
    if not p.exists():
        raise RoutingError("not_found", f"no existe: {p}")

    if p.is_dir():
        # Igual que `rea analyze`: directorio (no .app) -> analizador JavaScript.
        if p.suffix.lower() == ".app":
            return Route(FAMILY_NATIVE, ("app-bundle",))
        return Route(FAMILY_JS, ("directory",))

    try:
        kind = byte_kind(p)
    except OSError as exc:
        raise RoutingError("unreadable", f"no se puede leer {p.name}: {exc.strerror or exc}") from exc
    ext_family = _EXT_TO_FAMILY.get(p.suffix.lower())

    if kind == "zip":
        if ext_family == FAMILY_ANDROID:
            return Route(FAMILY_ANDROID, ("zip-signature", "extension-apk"))
        raise RoutingError(
            "unknown_format",
            "archivo ZIP sin extensión .apk: no se puede elegir familia sin adivinar",
        )

    if kind is None:
        raise RoutingError("unknown_format", f"firma no reconocida: {p.name}")

    magic_family = _KIND_TO_FAMILY[kind]
    if ext_family is not None and ext_family != magic_family:
        raise RoutingError(
            "ambiguous",
            f"la extensión sugiere {ext_family} pero los bytes son {kind}",
            candidates=(ext_family, magic_family),
        )
    return Route(magic_family, (f"bytes:{kind}",))
