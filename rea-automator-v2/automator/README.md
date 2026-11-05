# rea-automator

Automatizador de análisis que llama a la **CLI** de [rea](https://github.com/morluto/rea)
en lugar de usar su servidor MCP. Sin dependencias de Python en tiempo de ejecución.

## Qué hace

1. **Enruta** el objetivo por forma: bytes primero, extensión como pista.
   - directorio (no `.app`) → `analyze-javascript-application`
   - `.asar` → `analyze-javascript-application`
   - PE con directorio COM (.NET) → `inspect-managed-artifact`
   - PE/ELF/Mach-O → `analyze --provider ghidra`
   - `.apk` (ZIP) → `inspect-android-package`
2. **Ejecuta** `rea <comando> --format json` con timeout, tope de bytes y kill del grupo de procesos.
3. **Interpreta** el resultado con estados explícitos y `unknowns` para lo que no se puede establecer.

Si la extensión y los bytes apuntan a familias distintas, devuelve `ambiguous` en lugar de elegir.
No detecta motores de juego: eso es responsabilidad de la capa que llama.

## Dos modos distintos: evidencia dirigida vs. volcado masivo

- **`analyze` / `batch`** llaman a la CLI de `rea`. `rea` devuelve **evidencia
  dirigida**: clase por clase, método por método (pensado para que un agente
  de IA investigue algo puntual). No sirve para "quiero TODO el código fuente".
- **`decompile`** (nuevo) llama **directo** a la herramienta de descompilación
  subyacente en su modo de **volcado completo** — sin pasar por `rea` — y
  empaqueta el resultado en un `.zip`:

  | Familia | Herramienta invocada |
  |---|---|
  | `android-package` | `jadx -d <out>/ <apk> --no-res` |
  | `managed-pe` (.NET) | `ilspycmd -p -o <out>/ <dll>` |
  | `javascript-application` (.asar) | `asar extract <asar> <out>/` |
  | `javascript-application` (directorio) | se copia tal cual (ya es fuente) |
  | `native-binary` | `analyzeHeadless` + script propio (`scripts/ghidra_decompile_all.py`) que descompila **todas** las funciones a `.c` |

  Ninguna de estas herramientas viene incluida compilada: `scripts/setup_tools.sh` las
  instala dentro de `tool/` y genera `tool/env.sh` con las variables de entorno.
  `tool/` no viene en el repo/zip entregado (es un checkout limpio): el script
  instala **todo** desde cero, incluido `ilspycmd` -- no asume que ya esté
  vendorizado. En `tool/` queda código fuente de Ghidra y de ILSpy; Ghidra
  necesita la release precompilada (la descarga el script), no el código fuente.

  `ilspycmd` se instala como *dotnet tool* con versión fijada, contenido dentro
  de `tool/` (no en `~/.dotnet/tools` global):

  ```bash
  dotnet tool install --tool-path tool/ilspycmd-tool --version 11.1.0.9782 ilspycmd
  ```

  Requiere el **SDK** de .NET 10 (`dotnet-sdk-10.0`), no solo el runtime: el
  comando `dotnet tool install` es parte del SDK. El script verifica además que
  el binario resultante corre (`ilspycmd --version`) antes de darlo por
  instalado y de escribirlo en `tool/env.sh`.

## Flujo completo: un zip entra, un zip descompilado sale

Es el modo pensado para usuarios finales: se entrega un `.zip` (o un binario suelto) y
se obtiene **un único `.zip`** con todo el código descompilado.

```bash
bash scripts/setup_tools.sh          # una vez: instala jadx, ilspycmd, Ghidra, PyGhidra, JDK 21 y .NET 10 SDK dentro de tool/
source tool/env.sh                   # en cada terminal

python -m rea_automator pipeline entrada.zip --out resultados/
# -> resultados/entrada-decompilado.zip
```

El automatizador usa exclusivamente el binario local `tool/jadx/bin/jadx` del propio proyecto. No lee `PATH` ni una variable de entorno para elegir otro JADX; si el binario local falta, reporta esa ruta como ausente. La carpeta `tool/` se crea al ejecutar el instalador y no se incluye en el ZIP del código fuente.

Contenido del zip de salida:

- `decompilado/<ruta-del-binario>/...`: código fuente generado (`.c` para nativos, `.cs` para .NET, `.java` para APK, JS para `.asar`).
- `otros_archivos/...`: archivos no binarios del zip original (se omiten con `--sin-originales`).
- `logs/...`: stdout/stderr de las herramientas que fallaron, para diagnosticar.
- `report.json`: estado global, resumen de conteos y estado de cada archivo (`decompiled`, `partial`, `copied`, `failed`, `ambiguous`, `skipped`).

Estados globales de `pipeline`:

- `ok`: hay archivos procesados y todos terminaron sin errores, ambigüedades ni resultados parciales. Los archivos ordinarios copiados se consideran procesados correctamente.
- `partial`: se generó un resultado utilizable, pero hubo al menos un fallo, ambigüedad, archivo omitido o descompilación parcial.
- `failed`: el pipeline no pudo completar la operación o todos los objetivos que requerían procesamiento fallaron.
- `skipped`: no había archivos procesables o todos quedaron sin procesar por estar vacíos/ambiguos. No debe confundirse con éxito.

El CLI devuelve código de salida `0` únicamente para `ok`; `partial`, `failed` y `skipped` devuelven `1` para que los scripts que encadenan ejecuciones no interpreten un resultado incompleto como éxito total. Cada ejecución escribe en su propia carpeta nueva, así que las salidas de una corrida nunca se mezclan con las de otra; las carpetas antiguas y sin uso se limpian según la regla descrita en "Cambios recientes".

Para correrlo sin red (recomendado con archivos que no son de confianza):

```bash
bash scripts/run_isolated.sh pipeline entrada.zip --out resultados/
```

Reglas de seguridad del flujo: rechaza rutas que escapan de la carpeta (zip-slip), tiene tope de
archivos (20 000) y de bytes descomprimidos (4 GiB), y descomprime zips anidados (no `.apk`) hasta
2 niveles. Ver "Límites" sobre aislamiento.

## Uso

```bash
export REA_AUTOMATOR_REA_CMD="rea"            # o: "node /ruta/a/scripts/rea.mjs"
python -m rea_automator route  ./objetivo
python -m rea_automator analyze ./objetivo --out resultados/
python -m rea_automator analyze ./objetivo --family native-binary
python -m rea_automator batch ./carpeta_de_objetivos --out resultados/

# Volcado masivo: todo el objetivo descompilado, empaquetado en un .zip
python -m rea_automator decompile ./objetivo.apk --out resultados/
python -m rea_automator decompile ./objetivo.dll --family managed-pe --out resultados/
```

Variables de entorno:

| Variable | Por defecto | Uso |
|---|---|---|
| `REA_AUTOMATOR_REA_CMD` | `rea` | Comando de la CLI (acepta argumentos) |
| `REA_AUTOMATOR_NATIVE_PROVIDER` | `ghidra` | Proveedor para familias nativas (modo `analyze`) |
| `REA_AUTOMATOR_TIMEOUT_S` | `1800` | Timeout por objetivo |
| `REA_AUTOMATOR_MAX_STDOUT` | 256 MiB | Tope de stdout (se escribe a archivo) |
| `REA_AUTOMATOR_MAX_STDERR` | 4 MiB | Tope de stderr |
| `REA_AUTOMATOR_ILSPYCMD_CMD` | `ilspycmd` | Comando de ilspycmd (modo `decompile`, familia .NET) |
| `REA_AUTOMATOR_ASAR_CMD` | `npx asar` | Comando de asar (modo `decompile`, familia JS/.asar) |
| `REA_AUTOMATOR_GHIDRA_HEADLESS_CMD` | `pyghidraRun -H` | Ghidra headless vía PyGhidra (modo `decompile`, familia nativa). Ghidra 12 no ejecuta scripts Python con `analyzeHeadless` a secas. |

## v2: JADX dentro del proyecto y prueba de aceptación

```bash
python -m rea_automator setup-jadx                 # prepara automator/tool/jadx/ y lo comprueba
python -m rea_automator setup-jadx --jadx-zip jadx-1.5.6.zip   # sin red (se verifica el mismo SHA-256)
python -m rea_automator check-jadx                 # comprueba, sin instalar nada
python -m rea_automator verify-jadx mi.apk --out resultados/   # instala si falta, comprueba, ejecuta el APK y escribe el informe
```

- **Versión fijada**: JADX 1.5.6 (necesita Java 11 o superior). Nunca se consulta «latest».
  `setup-jadx` descarga la release de GitHub, **verifica su SHA-256 antes de extraer**, extrae con
  protección contra zip-slip y enlaces simbólicos, y solo reemplaza una instalación anterior si la
  nueva pasa la comprobación (si no, restaura la anterior).
- **Origen del SHA-256** (`rea_automator/jadx_tool.py`): se calculó al descargar la release y se fijó
  desde entonces («confianza en el primer uso»). No se pudo contrastar con una fuente independiente
  desde el entorno de desarrollo. Si dispones de una, compárala.
- **Comprobación «desde esa ruta»**: ejecuta `tool/jadx/bin/jadx` (nunca el del `PATH`), comprueba
  la versión y descompila una clase de prueba incluida (`rea_automator/smoke/Hello.class`),
  verificando que sale el código Java esperado.
- **Códigos de salida de JADX 1.5.6**: 0 limpio · 1 argumentos o fallo de proceso · 2 no cargó clases
  (no guarda nada) · 3 guardó el código pero con errores en algunas clases/métodos. El pipeline
  marca 3 como `partial` (y el CLI sale con 1), y deja en el informe cuántos errores reportó JADX.
  `verify-jadx` acepta 0 y 3.
- **Criterios de aprobación** (13, todos deben cumplirse): APK válido; JADX existe, es ejecutable,
  tiene su jar y Java disponible; la versión y la clase de prueba funcionan desde la ruta del
  proyecto; el pipeline usa ese JADX; el pipeline procesó el APK; código de salida de JADX válido;
  hay al menos un `.java` con declaración de clase/interfaz/enum (comentarios descartados); al menos
  el 50 % de las clases del `classes*.dex` tienen `.java` propio; y el informe del pipeline coincide
  con el contenido real del zip. Los números del zip se cuentan de nuevo, archivo por archivo, sin
  fiarse de los del pipeline.
- **Informe**: `<apk>-informe.json` y `<apk>-informe.md` junto al zip de resultado. `verify-jadx`
  sale con 0 solo si el veredicto es APROBADO.
- **Acceso a GitHub**: la descarga necesita llegar a `github.com`. Si tu red lo bloquea, descarga
  `jadx-1.5.6.zip` por otra vía y usa `--jadx-zip`.
- `scripts/setup_jadx.sh` es un atajo de `setup-jadx`; `scripts/setup_tools.sh` lo usa en su paso 2.

## Cambios recientes

- **v2 (0.2.0)**: `setup-jadx`, `check-jadx` y `verify-jadx` (ver la sección anterior); el estado de
  JADX (código de salida, nº de errores, `.java` escritos) queda en `details` de cada entrada del
  informe. **Corregido**: `test_apk_input_with_missing_jadx_is_not_reported_ok` dependía de que no
  hubiera JADX en `tool/jadx/`; ahora usa un comando inexistente y es independiente de lo instalado.
- **Corregido**: un zip sin extensión `.zip` dentro del paquete (p. ej. `datos.bin`) ya no se
  copia como si fuera un archivo cualquiera. Se registra como `skipped` con código
  `zip_by_content_not_expanded`, y el estado global deja de ser `ok`. Un `.docx` o `.xlsx`
  dentro del paquete entra en el mismo caso (son zips por dentro). Pruebas en
  `tests/test_zip_by_content.py`.
- **Corregido**: los zips anidados ya no pueden pasar como `ok` sin procesarse. Tres casos:
  (a) un archivo `.zip` que no es un zip válido se registra como `failed` (`nested_zip_invalid`);
  (b) la búsqueda ya no distingue mayúsculas, así que `inner.ZIP` se extrae;
  (c) un zip que queda más allá del límite de 2 niveles se registra como `skipped`
  (`nested_zip_depth_limit`). Los originales de esos casos quedan en `otros_archivos/`.
  Pruebas en `tests/test_nested_zips.py`.
- **Corregido**: dos ejecuciones de `decompile` sobre el mismo archivo podían borrarse entre sí.
  Antes, cada ejecución eliminaba las carpetas con el mismo prefijo antes de crear la suya.
  Ahora cada ejecución crea su propia carpeta y mantiene un bloqueo (`.lock`) mientras corre.
  La limpieza solo borra carpetas que tengan `.lock`, lleven más de 24 h sin cambios y cuyo
  bloqueo se pueda tomar sin esperar. En Windows (sin `fcntl`) no se borra nada.
  Pruebas en `tests/test_run_dirs.py`.
- **Corregido**: la configuración aceptaba valores inválidos. Ahora `REA_AUTOMATOR_TIMEOUT_S` y
  `--timeout` deben ser finitos y mayores que 0 (se rechazan `nan`, `inf`, `0` y negativos);
  `REA_AUTOMATOR_MAX_STDOUT`/`MAX_STDERR` deben ser enteros mayores que 0; `max_files` y `max_bytes`
  de `run_pipeline` reciben la misma validación antes de crear nada en disco. Un valor inválido
  produce `error de configuración: ...` y código de salida 2. Pruebas en `tests/test_config.py`.
- **Corregido**: un `.apk` pasado directamente a `pipeline` se extraía como zip (un APK
  también es zip) y el pipeline reportaba `ok` sin haber ejecutado jadx. Ahora se trata como
  objetivo Android y se descompila.
- **Corregido**: `decompile` sobre una carpeta usaba `shutil.copytree`, que sigue enlaces
  simbólicos: contenido de fuera de la carpeta podía quedar en el zip. Ahora los enlaces se
  omiten, igual que en `pipeline` (aparecen como `symlinks_excluded:N` en `unknowns`).
- Pruebas de regresión para ambos casos en `tests/test_regresiones_apk_symlink.py`.
- **Corregido**: si `argv[0]` (p. ej. `rea`, `jadx`) no existe o no es
  ejecutable, antes el proceso terminaba con un `FileNotFoundError` sin
  capturar. Ahora se reporta como `status: "command_not_found"` en el
  `result.json` / salida de `decompile`, igual que cualquier otro estado de fallo.
- **Nuevo**: comando `decompile` para volcado masivo (ver arriba). Reusa el
  mismo enrutamiento por bytes (`routing.py`) que `analyze`.

## Estados

`analyze`/`batch`: `ok`, `failed`, `signaled`, `timeout`, `unparseable_output`, `family_mismatch`, `routing_error`, `not_found`, `command_not_found`.

`decompile`: `ok`, `partial` (la herramienta devolvió código ≠0 pero sí escribió algo), `empty_output`, `timeout`, `command_not_found`, `routing_error`, `not_found`, `unsupported_family`.

`family_mismatch`: rea terminó bien pero su veredicto de dominio contradice la familia pedida
(p. ej. un PE nativo analizado como managed devuelve `classification.status: not-managed`).
El automatizador no lo trata como `ok`.

Un código de salida 0 con envoltorio `{"error": ...}` se reporta como `failed`, no como `ok`.
Un código no documentado se registra en `unknowns` como `exit_code_unexplained:N`.

## Verificado

Contra rea v6.5.0 compilado desde el zip, con Ghidra 12.1.4, JDK 21 y .NET SDK 8.0 reales:

| Objetivo | Familia | Resultado |
|---|---|---|
| ELF compilado con gcc | native-binary | `ok` (Ghidra, 24 s; `main` y `add` presentes) |
| PE32+ compilado con mingw | native-binary | `ok` (Ghidra, 43 s) |
| PE32+ compilado con mingw | managed-pe (forzado) | `family_mismatch` (`rea_reports:not-managed`) |
| ensamblado .NET 8 compilado | managed-pe | `ok` (`runtime_family: modern-dotnet`) |

Los binarios están en `tests/fixtures/real/` para que el enrutamiento se pruebe sin rea.

## Límites

- **Inconsistencia conocida**: si un zip sin extensión `.zip` es el archivo de entrada directa de
  `pipeline`, se expande (la entrada se detecta por contenido). Dentro de un paquete no se expande
  y se registra como `skipped`. Pendiente de decisión: unificar ambos casos.
- **No verificado en Windows.** El código tiene ramas para Windows (sin `start_new_session`,
  `proc.kill()`), pero no se ejecutaron. rea solo admite Ghidra en Windows como P0 experimental
  de solo lectura para PE x86/x64.
- **No verificado con Unity real.** La detección managed es genérica (directorio COM); no se probó
  un assembly de Unity Mono ni IL2CPP.
- **Ghidra en esta release**: las pruebas se hicieron con Ghidra 12.1.4 precompilado (PyGhidra). El flujo `decompile` de nativos depende de que `pyghidraRun` esté en `tool/env.sh`.
- **Ejecución aislada**: `scripts/run_isolated.sh` corre todo en un namespace de red sin conexión (verificado: no hay salida a internet). Las herramientas están todas dentro de `tool/`, así que no necesitan descargar nada en tiempo de ejecución. No limita memoria (la JVM de Ghidra la necesita) ni archivos del usuario.
- **No es un sandbox.** Los límites del runner no aíslan el proceso del sistema. El aislamiento
  (contenedor, usuario sin privilegios, red deshabilitada) lo debe aportar quien ejecuta el automatizador.
- Las familias nativas dependen de un proveedor instalado (Ghidra por defecto). Sin él, rea responde
  `provider_unavailable` y el automatizador lo reporta tal cual.

## Pruebas

```bash
python -m pytest                                       # 192 pruebas + 3 saltadas, sin herramientas reales (usan simuladores)
source tool/env.sh && python -m pytest                 # incluye integración real con rea, Ghidra y jadx
```

## Probado con herramientas reales

- **APK**: se compiló un APK de prueba (Java -> DEX -> manifest binario -> firma). jadx lo descompiló
  y el código recuperado conserva la lógica del original. `rea analyze` lo analizó con el proveedor jadx MCP
  (jadx-headless-mcp 0.7.1, SHA-256 verificado).
- **`.asar`**: se empaquetó una app JS de 3 archivos con asar y se recuperó byte a byte.
- **Binarios nativos (ELF y PE)**: Ghidra 12.1.4 release, vía PyGhidra. `main` se descompila como `add(2,3)`.
- **.NET**: ilspycmd 11.1.0.9782 sobre una DLL con su proyecto C#.
- **Modo aislado**: el flujo corre sin red; ver `scripts/run_isolated.sh`.
