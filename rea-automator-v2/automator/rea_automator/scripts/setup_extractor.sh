#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Verificando Python"
python3 --version

echo "==> Instalando/verificando JADX (versión fijada, SHA-256 verificado)"
python3 -m rea_automator setup-jadx

echo "==> Dependencias opcionales para aplicaciones de PC"
if ! command -v ilspycmd >/dev/null 2>&1; then
  echo "  ilspycmd no encontrado. Para .NET instale: dotnet tool install -g ilspycmd"
fi
if ! command -v asar >/dev/null 2>&1 && ! command -v npx >/dev/null 2>&1; then
  echo "  asar/npx no encontrados. Para Electron instale: npm install -g @electron/asar"
fi

echo "==> Listo."
echo "Uso:"
echo "  python -m rea_automator extract mi_app.apk --out ./resultado"
echo "  python -m rea_automator extract programa.exe --out ./resultado"