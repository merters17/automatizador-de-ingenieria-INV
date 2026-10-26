#!/usr/bin/env bash
# Prepara las herramientas de descompilación dentro de ./tool y genera tool/env.sh.
# Uso:  bash scripts/setup_tools.sh   (una vez)
#       source tool/env.sh            (en cada terminal, antes de correr el automatizador)
#
# Requiere: Linux Ubuntu/Debian con apt, Node >= 22.12, Python 3, acceso a internet.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$ROOT/tool"
mkdir -p "$TOOL"

GHIDRA_TAG="Ghidra_12.1.4_build"
GHIDRA_ZIP_NAME="ghidra_12.1.4_PUBLIC_20260921.zip"
JAVA_HOME_DIR="/usr/lib/jvm/java-21-openjdk-amd64"

log() { printf '\n==> %s\n' "$*"; }

# 1) Paquetes del sistema: .NET 10 SDK (para `dotnet tool install`, no solo el
#    runtime -- el comando de instalar tools vive en el SDK) y JDK 21 con javac
#    (Ghidra headless).
log "Paquetes del sistema"
need_apt=()
if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-sdks 2>/dev/null | grep -q .; then
  need_apt+=(dotnet-sdk-10.0)
fi
[ -x "$JAVA_HOME_DIR/bin/javac" ] || need_apt+=(openjdk-21-jdk-headless)
if [ "${#need_apt[@]}" -gt 0 ]; then
  apt-get update -y >/dev/null
  apt-get install -y "${need_apt[@]}"
fi

# 2) jadx: versión y SHA-256 fijados en rea_automator/jadx_tool.py. Lo instala (o lo deja
#    como está si ya funciona) y lo comprueba desde tool/jadx/bin/jadx. No consulta "latest".
log "jadx (versión fijada, SHA-256 verificado)"
( cd "$ROOT" && python3 -m rea_automator setup-jadx )

# 3) ilspycmd: se instala como dotnet tool con versión fijada (no se asume que
#    ya venga vendorizado en tool/ -- un checkout limpio no trae esa carpeta).
#    `--tool-path` lo deja contenido dentro de tool/, igual que el resto de
#    las herramientas, en vez de depender de ~/.dotnet/tools en el PATH.
log "ilspycmd (dotnet tool, versión fijada)"
ILSPY_VERSION="11.1.0.9782"
ILSPY_DIR="$TOOL/ilspycmd-tool"
ILSPY_BIN="$ILSPY_DIR/ilspycmd"
if [ ! -x "$ILSPY_BIN" ]; then
  rm -rf "$ILSPY_DIR" && mkdir -p "$ILSPY_DIR"
  dotnet tool install --tool-path "$ILSPY_DIR" --version "$ILSPY_VERSION" ilspycmd
fi
# No alcanza con que el instalador haya terminado sin error: se comprueba que
# el binario de verdad corre antes de darlo por bueno (y antes de escribirlo
# en tool/env.sh).
"$ILSPY_BIN" --version >/dev/null 2>&1 || {
  echo "ERROR: ilspycmd se instaló en $ILSPY_DIR pero '$ILSPY_BIN --version' falló"
  exit 1
}

# 4) Ghidra: la release precompilada (tool/ghidra-Ghidra_12.1.4_build es solo código fuente).
log "Ghidra (release precompilada)"
if [ ! -x "$TOOL/ghidra_release/support/pyghidraRun" ]; then
  curl -fL -o "$TOOL/ghidra_release.zip" \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_TAG}/${GHIDRA_ZIP_NAME}"
  rm -rf "$TOOL/ghidra_release_tmp" && mkdir -p "$TOOL/ghidra_release_tmp"
  unzip -q "$TOOL/ghidra_release.zip" -d "$TOOL/ghidra_release_tmp"
  rm -rf "$TOOL/ghidra_release" && mv "$TOOL"/ghidra_release_tmp/ghidra_* "$TOOL/ghidra_release"
  rm -rf "$TOOL/ghidra_release_tmp" "$TOOL/ghidra_release.zip"
  chmod +x "$TOOL/ghidra_release/support/"* "$TOOL/ghidra_release/ghidraRun" 2>/dev/null || true
fi

# 5) PyGhidra en un venv propio (Ghidra 12 ejecuta scripts Python solo con PyGhidra).
log "PyGhidra (venv)"
if [ ! -x "$TOOL/pyghidra-venv/bin/python" ]; then
  python3 -m venv "$TOOL/pyghidra-venv"
  "$TOOL/pyghidra-venv/bin/pip" install -q "$TOOL/ghidra_release/Ghidra/Features/PyGhidra/pypkg"
fi

# 5b) asar local (sin red en tiempo de ejecución: `npx -y asar` descargaría en cada corrida).
log "asar (local)"
if [ ! -x "$TOOL/asar/node_modules/.bin/asar" ]; then
  mkdir -p "$TOOL/asar" && (cd "$TOOL/asar" && npm init -y >/dev/null && npm install @electron/asar)
fi

# 6) rea (CLI de análisis) desde npm, y el JAR de jadx-headless-mcp verificado por SHA-256.
log "rea (npm rea-agents@6.5.0)"
if [ ! -f "$TOOL/rea/node_modules/rea-agents/scripts/rea.mjs" ]; then
  mkdir -p "$TOOL/rea" && (cd "$TOOL/rea" && npm init -y >/dev/null && npm install rea-agents@6.5.0)
fi

log "jadx-headless-mcp 0.7.1 (JAR verificado)"
JADX_MCP_JAR="$TOOL/rea-android/jadx-headless-mcp-0.7.1-all.jar"
JADX_MCP_SHA256="6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"
if [ ! -f "$JADX_MCP_JAR" ] || ! echo "$JADX_MCP_SHA256  $JADX_MCP_JAR" | sha256sum -c --status -; then
  mkdir -p "$TOOL/rea-android"
  curl -fL -o "$JADX_MCP_JAR" \
    "https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar"
  echo "$JADX_MCP_SHA256  $JADX_MCP_JAR" | sha256sum -c -
fi

# 7) Archivo de entorno que el automatizador lee por variables.
log "Escribiendo tool/env.sh"
cat > "$TOOL/env.sh" <<ENV
# Generado por scripts/setup_tools.sh. Cargar con: source tool/env.sh
export JAVA_HOME="$JAVA_HOME_DIR"
export PATH="$TOOL/pyghidra-venv/bin:\$PATH"
export REA_AUTOMATOR_ILSPYCMD_CMD="$ILSPY_BIN"
export REA_AUTOMATOR_ASAR_CMD="$TOOL/asar/node_modules/.bin/asar"
export REA_AUTOMATOR_GHIDRA_HEADLESS_CMD="$TOOL/ghidra_release/support/pyghidraRun -H"
export REA_AUTOMATOR_REA_CMD="node $TOOL/rea/node_modules/rea-agents/scripts/rea.mjs"
export GHIDRA_INSTALL_DIR="$TOOL/ghidra_release"
export REA_JADX_MCP_JAR="$JADX_MCP_JAR"
ENV

log "Listo. Ejecuta:  source tool/env.sh"
