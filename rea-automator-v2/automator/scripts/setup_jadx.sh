#!/usr/bin/env bash
# Prepara JADX en automator/tool/jadx/ y comprueba que funciona desde esa ruta.
# Uso:  bash scripts/setup_jadx.sh                       (descarga la versión fijada, verifica SHA-256)
#       bash scripts/setup_jadx.sh --jadx-zip jadx-1.5.6.zip   (sin red; el SHA-256 se verifica igual)
#       bash scripts/setup_jadx.sh --force               (reinstala)
# Requiere Java 11 o superior y Python 3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
exec python3 -m rea_automator setup-jadx "$@"
