"""Simula una herramienta de volcado masivo (jadx/ilspycmd/ghidra headless) para
pruebas del automatizador. Encuentra el directorio de salida entre los argv y
escribe tres archivos de ejemplo ahí, con extensión según quién lo invocó.
"""
import sys
from pathlib import Path

argv = sys.argv[1:]

# jadx: ... -d <out_dir> <target> ...
if "-d" in argv:
    out_dir = Path(argv[argv.index("-d") + 1])
    ext = "java"
# ilspycmd: ... -o <out_dir> <target>
elif "-o" in argv:
    out_dir = Path(argv[argv.index("-o") + 1])
    ext = "cs"
# ghidra headless -postScript ghidra_decompile_all.py <out_dir> ...
elif "-postScript" in argv:
    script_idx = argv.index("-postScript")
    out_dir = Path(argv[script_idx + 2])
    ext = "c"
else:
    print("fake_bulk_tool: no se reconoce la forma de argv", argv)
    sys.exit(2)

out_dir.mkdir(parents=True, exist_ok=True)
for letter in "abc":
    (out_dir / f"{letter}.{ext}").write_text(f"// contenido de prueba {letter}\n")

if ext == "c":
    # Ghidra real siempre escribe este indice (ver ghidra_decompile_all.py);
    # decompile.py lo analiza para decidir ok/partial/failed, asi que el fake
    # debe reflejar eso para que los tests de la familia native-binary sean
    # representativos de una corrida real exitosa.
    rows = ["address\tname\tstatus\tfile"]
    for i, letter in enumerate("abc"):
        rows.append(f"0x100{i}\tfunc_{letter}\tok\t{letter}.{ext}")
    (out_dir / "_index.tsv").write_text("\n".join(rows))

print("fake_bulk_tool: listo")
sys.exit(0)
