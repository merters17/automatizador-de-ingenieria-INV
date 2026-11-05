"""Script headless de Ghidra: descompila TODAS las funciones del programa importado.
Escribe:
  - Un archivo .c por función (con cabecera de metadatos).
  - Un archivo .s por función (ensamblaje con direcciones y bytes).
  - Un archivo .json por función (sidecar con firma, rangos, artefactos y hashes).
  - Un manifest.json global (schema_version, counts, lenguaje, compilador, base de imagen).
Uso (vía analyzeHeadless / pyghidraRun -H):
  analyzeHeadless <project_dir> <project_name> -import <binario> \
      -postScript ghidra_decompile_all.py <out_dir> \
      -scriptPath <carpeta_del_script> -deleteProject
Opciones opcionales tras el out_dir:
  --timeout-per-func SEGUNDOS   Timeout de decompilación por función (default 60).
  --combined                    Genera además all_functions.c con todo el código.
  --include REGEX               Solo exporta funciones cuyo nombre coincida.
  --exclude REGEX               Omite funciones cuyo nombre coincida.
"""
import os
import re
import json
import hashlib
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_args(args: list[str]) -> dict:
    out_dir = None
    timeout_per_func = 60
    combined = False
    include_patterns: list[str] = []
    exclude_patterns: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--timeout-per-func" and i + 1 < len(args):
            timeout_per_func = int(args[i + 1])
            i += 2
        elif a == "--combined":
            combined = True
            i += 1
        elif a == "--include" and i + 1 < len(args):
            include_patterns.append(args[i + 1])
            i += 2
        elif a == "--exclude" and i + 1 < len(args):
            exclude_patterns.append(args[i + 1])
            i += 2
        elif not a.startswith("-") and out_dir is None:
            out_dir = a
            i += 1
        else:
            i += 1
    if out_dir is None:
        raise SystemExit("ERROR: falta out_dir como argumento de script")
    return {
        "out_dir": out_dir,
        "timeout_per_func": timeout_per_func,
        "combined": combined,
        "include": include_patterns,
        "exclude": exclude_patterns,
    }


def _sanitize_name(name: str, max_length: int = 80) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).rstrip(". ") or "_"
    return safe[:max_length]


def _artifact_stem(address: str, name: str, max_length: int = 120) -> str:
    digest = hashlib.sha256(f"{address}\0{name}".encode()).hexdigest()[:24]
    safe_address = _sanitize_name(address, 40)
    name_limit = max(1, max_length - len(safe_address) - len(digest) - 2)
    safe_name = _sanitize_name(name, name_limit)
    return f"{safe_address}_{digest}_{safe_name}"


def _write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> None:
    args = getScriptArgs()
    config = _parse_args(args)
    out_dir = config["out_dir"]
    timeout_per_func = config["timeout_per_func"]
    combined = config["combined"]
    include_re = [re.compile(p) for p in config["include"]]
    exclude_re = [re.compile(p) for p in config["exclude"]]
    os.makedirs(out_dir, exist_ok=True)

    def name_matches(name: str) -> bool:
        if include_re and not any(p.search(name) for p in include_re):
            return False
        return not any(p.search(name) for p in exclude_re)

    monitor = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    func_manager = currentProgram.getFunctionManager()
    functions = list(func_manager.getFunctions(True))
    records: list[dict] = []
    ok_count = 0
    fail_count = 0
    total = len(functions)

    for func in functions:
        name = func.getName()
        if not name_matches(name):
            continue
        addr = func.getEntryPoint().toString()
        stem = _artifact_stem(addr, name)
        c_path = os.path.join(out_dir, f"{stem}.c")
        s_path = os.path.join(out_dir, f"{stem}.s")
        json_path = os.path.join(out_dir, f"{stem}.json")

        listing = currentProgram.getListing()
        asm_lines: list[str] = []
        for instr in listing.getInstructions(func.getBody(), True):
            a = instr.getAddress()
            raw_bytes = " ".join(f"{int(v) & 0xFF:02x}" for v in instr.getBytes())
            mnemonic = instr.getMnemonicString()
            num_ops = instr.getNumOperands()
            operands = ", ".join(
                instr.getDefaultOperandRepresentation(k) for k in range(num_ops)
            )
            asm_lines.append(f"{a}:  {raw_bytes:<24}  {mnemonic:<10} {operands}")
        _write_text(s_path, "\n".join(asm_lines) + "\n")

        header = (
            f"// Function: {name}\n"
            f"// Address:  {addr}\n"
            f"// Size:     {func.getBody().getNumAddresses()} bytes\n"
            f"// Calling:  {func.getCallingConventionName() or 'unknown'}\n"
            f"// Params:   {func.getParameterCount()}\n\n"
        )

        try:
            result = decompiler.decompileFunction(func, timeout_per_func, monitor)
            if result.decompileCompleted():
                decompiled = result.getDecompiledFunction()
                code = decompiled.getC() if decompiled else ""
                status = "ok"
                ok_count += 1
            else:
                code = f"// decompilacion incompleta: {result.getErrorMessage()}\n"
                status = "failed"
                fail_count += 1
        except Exception as exc:
            code = f"// excepcion durante decompilacion: {exc}\n"
            status = "exception"
            fail_count += 1

        _write_text(c_path, header + code)

        parameters = []
        for parameter in func.getParameters():
            dt = parameter.getDataType()
            parameters.append(
                {
                    "type": dt.getName() if dt else "undefined",
                    "name": parameter.getName(),
                    "ordinal": parameter.getOrdinal(),
                }
            )
        return_type = func.getReturnType()

        # Hashes de los artefactos ya escritos
        c_hash = _sha256_file(c_path) if os.path.exists(c_path) else None
        s_hash = _sha256_file(s_path) if os.path.exists(s_path) else None

        record = {
            "schema_version": 1,
            "name": name,
            "address": addr,
            "body_ranges": [
                {
                    "start": r.getMinAddress().toString(),
                    "end": r.getMaxAddress().toString(),
                }
                for r in func.getBody().getAddressRanges(True)
            ],
            "size": func.getBody().getNumAddresses(),
            "signature": {
                "return_type": return_type.getName() if return_type else "void",
                "calling_convention": func.getCallingConventionName() or "unknown",
                "parameters": parameters,
            },
            "is_thunk": func.isThunk(),
            "artifacts": {
                "pseudocode": f"{stem}.c",
                "pseudocode_sha256": c_hash,
                "assembly": f"{stem}.s",
                "assembly_sha256": s_hash,
                "sidecar": f"{stem}.json",
                "sidecar_sha256": None,  # se rellena tras escribir el JSON
            },
            "decompilation": {"status": status},
        }
        _write_json(json_path, record)

        # Ahora que el sidecar existe, calcular su hash y actualizar el archivo
        s_hash_val = _sha256_file(json_path) if os.path.exists(json_path) else None
        record["artifacts"]["sidecar_sha256"] = s_hash_val
        _write_json(json_path, record)

        records.append(record)

    manifest = {
        "schema_version": 1,
        "status": "complete",
        "tool": {"name": "rea-automator", "version": "0.2.1"},
        "input": str(
            currentProgram.getDomainFile().getName()
            if currentProgram.getDomainFile()
            else currentProgram.getName()
        ),
        "language_id": str(currentProgram.getLanguageID()),
        "compiler_id": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
        "image_base": currentProgram.getImageBase().toString(),
        "num_functions": total,
        "num_successful": ok_count,
        "num_fallback": fail_count,
        "num_failed": fail_count,
        "counts": {
            "discovered": total,
            "successful": ok_count,
            "fallback": fail_count,
            "failed": fail_count,
            "skipped": 0,
        },
        "functions": records,
    }
    _write_json(os.path.join(out_dir, "manifest.json"), manifest)

    if combined:
        combined_path = os.path.join(out_dir, "all_functions.c")
        separator = "\n" + ("/" * 80) + "\n\n"
        with open(combined_path, "w", encoding="utf-8") as out:
            for idx, rec in enumerate(records):
                if idx:
                    out.write(separator)
                c_file = os.path.join(out_dir, rec["artifacts"]["pseudocode"])
                if os.path.exists(c_file):
                    with open(c_file, "r", encoding="utf-8") as src:
                        out.write(src.read())

    decompiler.dispose()
    print(
        f"decompile_all: {ok_count} funciones ok, {fail_count} con problemas, total {total}"
    )
    if fail_count > 0:
        print(
            f"decompile_all: WARNING -- {fail_count} funciones no se pudieron decompilar completamente"
        )


main()