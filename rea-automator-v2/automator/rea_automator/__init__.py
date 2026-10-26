"""Automatizador de análisis que llama a la CLI de rea (sin MCP).

Capas, de adentro hacia afuera:
  routing.py   puro: decide la familia de análisis a partir de bytes y forma.
  runner.py    único punto que lanza procesos externos (límites y timeouts).
  adapters/    traduce cada familia a un comando de la CLI de rea.
  batch.py     recorre objetivos y escribe resultados y resumen.

Añadido en la v2 (JADX preparado y comprobado dentro del proyecto):
  jadx_tool.py instala JADX en tool/jadx/ (versión y SHA-256 fijados) y comprueba
               que funciona desde esa ruta.
  dexinfo.py   lector mínimo de DEX para contrastar el resultado con el APK.
  verify.py    prueba de aceptación: prepara JADX, ejecuta el APK con el pipeline
               y escribe el informe.
"""

__version__ = "0.2.0"
