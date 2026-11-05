"""JADX simulado para las pruebas de rea_automator.jadx_tool / verify (sin Java ni red).

Imita lo observable de JadxCLI 1.5.6: `--version` imprime la versión; con `-d <out> ... <entrada>`
escribe fuentes en <out>/sources/ y sale con 0 (limpio), 3 (con errores), 2 (no cargó clases)
o 1 (fallo de proceso). El comportamiento sobre un APK se elige con FAKE_JADX_MODE:

  ok        escribe rea/demo/A.java y B.java, código 0
  errors    igual, pero imprime "finished with errors, count: 4" y sale con 3
  loadfail  "Load failed!", no escribe nada, código 2
  crash     no escribe nada, código 1
  empty     no escribe nada, código 0
  junk      escribe .java que solo tienen comentarios (sin ninguna declaración), código 0

Sobre `Hello.class` (la clase de la prueba de humo) responde bien salvo FAKE_JADX_MODE=smoke_broken.
La versión sale de FAKE_JADX_VERSION (por defecto 9.9.9).
"""

import os
import sys
from pathlib import Path

MODE = os.environ.get("FAKE_JADX_MODE", "ok")
VERSION = os.environ.get("FAKE_JADX_VERSION", "9.9.9")
argv = sys.argv[1:]

if "--version" in argv:
    print(VERSION)
    sys.exit(0)

if "-d" not in argv:
    print("fake_jadx: falta -d", file=sys.stderr)
    sys.exit(1)

out = Path(argv[argv.index("-d") + 1])
target = Path([a for a in argv if not a.startswith("-")][-1])


def write(relative: str, text: str) -> None:
    path = out / "sources" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def long_class(name: str) -> str:
    """Una clase de ~45 líneas con lógica de control de flujo (candidata a muestra del informe)."""
    body = [f"package rea.demo;", "", f"/* JADX INFO: loaded from: classes.dex */", f"public class {name} {{"]
    for i in range(6):
        body += [
            f"    public static int op{i}(int[] values) {{",
            "        int total = 0;",
            "        for (int v : values) {",
            f"            if (v > {i}) {{",
            "                total += v;",
            "            }",
            "        }",
            "        return total;",
            "    }",
        ]
    body.append("}")
    return "\n".join(body) + "\n"


if target.name == "Hello.class":
    if MODE == "smoke_broken":
        write("rea/smoke/Hello.java", "/* JADX WARN: nada se pudo recuperar */\n")
    else:
        write(
            "rea/smoke/Hello.java",
            "package rea.smoke;\n\n/* JADX INFO: loaded from: Hello.class */\npublic class Hello {\n"
            "    public static int add(int i, int i2) {\n        return i + i2;\n    }\n\n"
            "    public static String greet(String str) {\n"
            '        return "hola-jadx-smoke:" + str + ":" + add(2, 3);\n    }\n}\n',
        )
    print("INFO  - done")
    sys.exit(0)

if MODE == "loadfail":
    print("ERROR - Load failed! No classes for decompile!")
    sys.exit(2)
if MODE == "crash":
    print("ERROR - Process error:", file=sys.stderr)
    sys.exit(1)
if MODE == "empty":
    print("INFO  - done")
    sys.exit(0)
if MODE == "junk":
    write("rea/demo/A.java", "/* JADX WARN: class A no se pudo decompilar */\n// nada aquí\n")
    write("rea/demo/B.java", "/* class B comentada: class B { } */\n")
    print("INFO  - done")
    sys.exit(0)

write("rea/demo/A.java", long_class("A"))
write("rea/demo/B.java", "package rea.demo;\n\npublic interface B {\n    int size();\n}\n")
if MODE == "errors":
    print("ERROR - finished with errors, count: 4")
    sys.exit(3)
print("INFO  - done")
sys.exit(0)
