# -*- coding: utf-8 -*-
"""Script headless de Ghidra: descompila TODAS las funciones del programa importado
y escribe una entrada .c por función en el directorio pasado como argumento de script.

Uso (vía analyzeHeadless):
  analyzeHeadless <project_dir> <project_name> -import <binario> \
      -postScript ghidra_decompile_all.py <out_dir> \
      -scriptPath <carpeta_que_contiene_este_script> -deleteProject

No es un decompile dirigido como `rea decompile <addr>`: recorre el FunctionManager
completo, así que el out_dir termina con el código de TODO el binario, no de una
función elegida.
"""

import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
if len(args) < 1:
    print("ERROR: falta out_dir como argumento de script")
    exit(1)

out_dir = args[0]
if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

monitor = ConsoleTaskMonitor()
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

func_manager = currentProgram.getFunctionManager()
functions = list(func_manager.getFunctions(True))  # True = orden por dirección

index_lines = []
ok_count = 0
fail_count = 0

for func in functions:
    name = func.getName()
    addr = func.getEntryPoint().toString()
    safe_name = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)
    file_name = "%s_%s.c" % (safe_name[:120], addr)

    try:
        result = decompiler.decompileFunction(func, 60, monitor)
        if result.decompileCompleted():
            code = result.getDecompiledFunction().getC()
            status = "ok"
            ok_count += 1
        else:
            code = "// decompilacion incompleta: %s\n" % result.getErrorMessage()
            status = "failed"
            fail_count += 1
    except Exception as exc:  # noqa: BLE001 - script headless, se registra y se sigue
        code = "// excepcion durante decompilacion: %s\n" % str(exc)
        status = "exception"
        fail_count += 1

    out_path = os.path.join(out_dir, file_name)
    f = open(out_path, "w")
    try:
        f.write("// funcion: %s @ %s (%s)\n" % (name, addr, status))
        f.write(code)
    finally:
        f.close()
    index_lines.append("%s\t%s\t%s\t%s" % (addr, name, status, file_name))

index_path = os.path.join(out_dir, "_index.tsv")
f = open(index_path, "w")
try:
    f.write("address\tname\tstatus\tfile\n")
    f.write("\n".join(index_lines))
finally:
    f.close()

decompiler.dispose()
print("decompile_all: %d funciones ok, %d con problemas, total %d" % (
    ok_count, fail_count, len(functions)))

# AVISO: `analyzeHeadless`/`pyghidraRun` no garantiza de forma portable que un
# fallo del postScript se traduzca en un código de salida != 0 del proceso
# (depende de la versión de Ghidra y de si hay más proyectos en el batch), así
# que esto es una señal de mejor esfuerzo, no la fuente de verdad. La fuente
# de verdad es `_index.tsv`: el orquestador (decompile.py) lo analiza y decide
# ok/partial/failed en base al status por función, no solo en base a si el
# proceso terminó con código 0.
if fail_count > 0:
    print("decompile_all: ERROR -- %d funciones no se pudieron descompilar" % fail_count)
    exit(1)
