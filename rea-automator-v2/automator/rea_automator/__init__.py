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


"""Automatizador de análisis que llama a la CLI de rea (sin MCP).
...
Añadido en la v2.1 (Ghidra mejorado):
  ghidra_decompile_all.py genera artefactos por función (.c, .s, .json) + manifest.json.
  ghidra_artifacts.py escritura atómica y publicación segura de directorios.
  ghidra_cache.py caché indexado por huella dactilar del binario y la solicitud.
  logger.py / string_util.py utilidades de logging y extracción de strings.
"""
__version__ = "0.2.1"