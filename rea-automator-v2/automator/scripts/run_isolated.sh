#!/usr/bin/env bash
# Corre el automatizador SIN red (namespace de red propio). Las herramientas están
# todas dentro de tool/ (ver scripts/setup_tools.sh), así que no necesitan descargar nada.
#
# Uso:  bash scripts/run_isolated.sh pipeline entrada.zip --out resultados/
#
# Límites de esta protección:
#  - Corta la red: un binario/zip malicioso no puede exfiltrar ni descargar cargas.
#  - NO es un sandbox completo: el proceso sigue pudiendo leer/escribir el sistema de
#    archivos del usuario. Para aislamiento fuerte usar una VM o contenedor.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f tool/env.sh ]; then
  echo "Falta tool/env.sh. Corre primero: bash scripts/setup_tools.sh" >&2
  exit 1
fi
if ! command -v unshare >/dev/null 2>&1; then
  echo "Falta 'unshare' (util-linux). No se puede aislar la red." >&2
  exit 1
fi

exec unshare --net --map-root-user bash -c '. tool/env.sh && exec python3 -m rea_automator "$@"' _ "$@"
