#!/usr/bin/env python3
"""Guarda PreToolUse: bloquea una lista corta de actos de techo duro.

"Nombrar no es leer", rehecho -- 2026-08-30 (TEC-0059, gate 128,
id_acto TEC-0059-rehacer-guarda-nombrar-no-es-leer-20260830, aprobador
steve, message_id 128, verificado por tausa-orquestador con la cuádrupla
exacta, exit 0, sin tubería). Reemplaza la reversión de contención del
mismo día: el intento anterior de "nombrar no es leer" tenía un bypass
real (dictamen de tausa-auditor) -- un valor citado con sustitución de
comandos ($(...), backticks) se vaciaba en la copia que la guarda evalúa
sin vaciar lo que el shell expande al ejecutar, así que el contenido crudo
de un archivo gobernado salía como --resumen por el propio canal de gates.

Qué corrige, contra el dictamen:
  1. Ninguna sustitución de comandos, subshell o backtick sobrevive dentro
     del valor de --resumen/--motivo/--descripcion antes de la comparación
     -- no solo se vacía el texto plano.
  2. Comilla simple y doble reciben el MISMO tratamiento a propósito.
     tausa-auditor retiró su nota de tratarlas distinto: modelar cuál
     construcción de sustitución se expande en cuál tipo de comilla es
     exactamente la clase de detalle de quoting específico de shell que
     produjo el bypass original. Tratar ambas como igual de sospechosas es
     más estricto y no depende de esa semántica.

TEC-0065, gate 138 (2026-08-30): la rama `Read` no bloqueaba el custodio de
secretos (`Agente_Accesos`, `secrets/`, `.env*`, credenciales) -- bloqueaba
`Edit`/`Write` y dejaba pasar `Read`, la mitad invertida del defecto que
`TEC-0063` corrigió del lado de los archivos de gates. `PROTEGIDO_SECRETOS`
ahora es una sola constante que gobierna las dos ramas.
"""
import json
import os
import re
import sys
from pathlib import Path

# Raiz del workspace: este archivo vive dos niveles bajo ella
# (.claude/hooks/guarda_techo_duro.py o .codex/hooks/guarda_techo_duro.py).
# Definida aqui arriba (y no donde vivia en el original, mas abajo) porque
# _RE_RAIZ_ANCHA y _OBJETIVO_GATES la necesitan al compilarse, no solo en
# tiempo de ejecucion -- corregido en TEC-0169 al portar este hook a
# `plantilla-entorno`: la version que vivia mas abajo dejaba ambas
# constantes con el nombre de la carpeta raiz de origen escrito a mano en
# vez de derivarlo de esta variable (ver bitacora de TEC-0169, T3, "hallazgo
# fuera de alcance": el detalle completo, con el valor concreto que traia
# antes, queda documentado ahi y no en este archivo).
_RAIZ_WORKSPACE = Path(__file__).resolve().parent.parent.parent


def deny(reason: str) -> None:
    global _ULTIMA_RAZON
    _ULTIMA_RAZON = reason  # G2 (TEC-0175): en zona Orca, sale con 2
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}, ensure_ascii=False))


# --------------------------------------------------------------------------
# "Nombrar no es leer" (TEC-0059, gate 128)
# --------------------------------------------------------------------------

# Banderas de texto libre conocidas hoy en el repo que pueden legítimamente
# nombrar un archivo gobernado en prosa: --resumen (gates_telegram.py
# enviar-prueba), --motivo y --descripcion (registrar_evento_acto.py,
# ADR-0021). Lista cerrada, no un patrón genérico -- una bandera nueva de
# texto libre se agrega aquí a mano cuando se construya, mismo criterio que
# ya rige para las banderas y patrones de abajo.
_FLAGS_PROSA = ("--resumen", "--motivo", "--descripcion")

# Captura el valor citado completo (grupo 3) y por separado su contenido sin
# comillas (grupo 4 para dobles, grupo 5 para simples) para poder inspeccionar
# el contenido sin las comillas mismas.
_RE_VALOR_PROSA = re.compile(
    r'(' + "|".join(re.escape(f) for f in _FLAGS_PROSA) + r')(=|\s+)("([^"]*)"|\'([^\']*)\')'
)

# Cualquier sintaxis de sustitución de comandos o subshell -- $(...), backtick,
# ${...}. No se intenta distinguir cuál de las tres expande en qué shell: las
# tres son ilegítimas dentro de prosa que se envía a Telegram, así que
# cualquiera de las tres, en cualquier tipo de comilla, basta para bloquear.
_RE_SUBSHELL = re.compile(r'\$\(|`|\$\{')

# TEC-0065, gate 138 (id_acto TEC-0065-guarda-lectura-secretos-en-C-20260830,
# firmado 2026-08-30): un solo lugar para las dos ramas (Read y Edit/Write) --
# antes cada rama tenia su propia lista y nadie escribio la mitad de Read,
# que es exactamente como TEC-0063 paso con Edit/Write. Constante de modulo,
# no una copia local por rama.
PROTEGIDO_SECRETOS = ("/agente_accesos/", "/secrets/", "/.env", "/credentials.json", "/token.json")


def _valor_citado(m: "re.Match") -> str:
    return m.group(4) if m.group(4) is not None else m.group(5)


def _tiene_subshell_en_prosa(command: str) -> bool:
    """Si el valor citado de una bandera de texto libre trae sustitución de
    comandos, eso es motivo de bloqueo por sí solo -- exista o no, además,
    un archivo gobernado nombrado dentro. Se evalúa ANTES de intentar
    vaciar nada, así que un valor así nunca llega a la etapa de "vaciado"
    de abajo."""
    return any(_RE_SUBSHELL.search(_valor_citado(m)) for m in _RE_VALOR_PROSA.finditer(command))


def _sin_prosa_de_argumentos_libres(command: str) -> str:
    """"Nombrar no es leer" (TEC-0059 S4quater): vacía el valor citado de
    una bandera de texto libre conocida SOLO cuando ese valor no contiene
    ninguna sustitución de comandos/subshell -- si la contiene, se deja el
    valor tal cual en la copia que la guarda evalúa (defensa en
    profundidad; en la práctica `_tiene_subshell_en_prosa` ya bloqueó antes
    de llegar aquí, pero esta función no depende de ese orden para ser
    correcta por sí misma)."""
    def _reemplazar(m: "re.Match") -> str:
        if _RE_SUBSHELL.search(_valor_citado(m)):
            return m.group(0)
        return m.group(1) + m.group(2) + "''"
    return _RE_VALOR_PROSA.sub(_reemplazar, command)



# --------------------------------------------------------------------------
# "No nombrar tampoco es no leer" (TEC-0141, 2026-09-07)
# --------------------------------------------------------------------------
# Las tres comparaciones de archivo gobernado de la rama Bash/PowerShell solo
# ven el nombre. Un barrido recursivo desde la raiz abre los mismos archivos
# sin escribir su nombre en ninguna parte. Medido el 2026-09-07: os.walk(".")
# sobre 39 676 archivos leyo avisos_enviados.jsonl completo y la guarda no
# reacciono; el comando siguiente, que si lo nombraba, si fue bloqueado.
#
# Alcance: esto NO sella la lectura -- un hook que inspecciona texto no puede
# probar que abrira un programa. Impone un contrato declarativo: un barrido
# ancho debe DECIR que excluye el registro. El incumplimiento invisible pasa a
# ser una negacion ruidosa, y la exclusion queda grepeable en el comando.
#
# Listas CERRADAS a proposito, igual que _FLAGS_PROSA: un patron generico
# produce falsos positivos sobre trabajo legitimo, y una guarda que estorba se
# termina desactivando. Una primitiva o una raiz nueva se agregan aqui a mano.
#
# La rama de grep detecta la bandera dentro de un CUMULO (-rn, -irn, -rln), no
# solo suelta. La primera version pedia \br\b y por eso dejaba pasar `grep -rn`,
# que es la forma mas comun de todas: lo encontro el banco de pruebas, no la
# lectura. El comando se compara ya en minusculas (linea 150 de la guarda), asi
# que -R queda cubierto por el mismo patron.
#
# Los tramos usan [^|;\n] y no [^|]: un match no debe poder cruzar de un comando
# encadenado al siguiente y volver recursivo un grep que no lo es.
_RE_RECURSIVO = re.compile(
    r"os\.walk\s*\(|"
    r"\.rglob\s*\(|"
    r"glob\.i?glob\s*\([^)]*\*\*|"
    r"\bfind\s+\S|"
    r"\bgrep\b[^|;\n]*\s-[a-z]*r|"
    r"--recursive\b|"
    r"\brg\s+|"
    r"get-childitem\b[^|;\n]*-recurse|"
    r"\bgci\b[^|;\n]*-recurse|"
    r"\bdir\b[^|;\n]*\s/s\b"
)

# Raices que alcanzan Tausa_Labs/gates_telegram. Un barrido acotado a otra rama
# -- Obsidian/, execution/, directives/ -- no puede llegar y no se le exige nada.
#
# El nombre de la carpeta raiz NO es una constante: se lee de
# `_RAIZ_WORKSPACE.name` (derivada de `Path(__file__)`, nunca escrita a
# mano) para que esta guarda siga reconociendo un barrido "desde la raiz
# por su nombre" sin importar como se llame la carpeta en la instancia que
# corre este hook -- corregido en TEC-0169: la version portada de esta
# plantilla traia el nombre de la carpeta de origen escrito a mano, lo
# que rompe el criterio de cero rutas absolutas de este encargo (detalle
# en la bitacora de TEC-0169, no repetido aqui).
# S1 (revision del Auditor de TEC-0169, cerrado en TEC-0170/T0): el literal
# de abajo llevaba solo un limite a la derecha; sin uno a la izquierda, una
# raiz de nombre generico (p. ej. "casa", "app") podia coincidir dentro de
# una palabra mas larga ("micasa", "apple") y disparar un falso positivo. El
# `(?<![a-z0-9_])` es ese limite -- equivalente a un `\b` de apertura, dado
# que los nombres de carpeta que compara son siempre caracteres de palabra
# ASCII.
_RE_RAIZ_ANCHA = re.compile(
    r"os\.walk\s*\(\s*[\"']\.?[\\/]?[\"']|"
    r"os\.walk\s*\(\s*(raiz|root|base|cwd|os\.getcwd\(\))|"
    r"rglob\s*\(\s*[\"']\*|"
    r"(?<![a-z0-9_])" + re.escape(_RAIZ_WORKSPACE.name.lower()) + r"(?![\\/][a-z0-9_])|"
    r"\btausa_labs\b|"
    r"\bfind\s+\.(\s|$)|"
    r"\bgrep\b[^|;\n]*\s\.(\s|$)"
)

# ADR-0043 D1, "Condicion del anidamiento" (TEC-0170, T4, CA4). Si la raiz del
# workspace se llama exactamente "Tausa_Labs" (el nombre que decide D1), el
# repo de infraestructura queda anidado en Tausa_Labs\Tausa_Labs\ y la
# alternativa `\btausa_labs\b` de arriba deja de ser un token inequivoco: una
# ruta ABSOLUTA que solo nombra la raiz por fuera (`C:\Workspaces\Tausa_Labs\
# Obsidian`, sin alcanzar el repo interior) tambien contiene la subcadena
# "tausa_labs" y dispararia el mismo bloqueo que un barrido que si alcanza el
# repo interior.
#
# La correccion, tal como la fija D1, no reescribe esa alternativa: relativiza
# el PREFIJO ABSOLUTO de la raiz antes de evaluar el resto de la funcion. Cada
# aparicion de `c:\workspaces\tausa_labs\` (con `/` o `\`, sin distinguir
# mayusculas) se sustituye por `./`. Una ruta que solo nombra la raiz por
# fuera pierde ahi mismo la subcadena "tausa_labs" y ninguna alternativa de
# `_RE_RAIZ_ANCHA` la vuelve a encontrar; una ruta que sigue de largo hacia el
# repo interior (`...Tausa_Labs\Tausa_Labs`) conserva el segundo "tausa_labs"
# despues de relativizar, y ese es exactamente el que tiene que seguir
# bloqueando. Literal fijo, no `_RAIZ_WORKSPACE.name`: el anidamiento solo
# puede ocurrir cuando la raiz se llama asi -- con cualquier otro nombre de
# raiz (hoy: "Entorno_Claude") el patron nunca encuentra nada que sustituir y
# el comando llega sin cambios a las comparaciones de abajo.
#
# El comportamiento lo fijan los casos F1-F5 de D1 (banco de la plantilla y
# banco vivo), no esta expresion por si sola.
_RE_RELATIVIZAR_RAIZ_ANIDADA = re.compile(r"c:[\\/]+workspaces[\\/]+tausa_labs[\\/]+", re.IGNORECASE)

# La exclusion se declara nombrando el directorio gobernado en el propio
# comando. Nombrar gates_telegram (el directorio) nunca estuvo bloqueado: lo
# bloqueado son los tres .jsonl, y esos siguen teniendo su propia comparacion
# con precedencia sobre esta.
_RE_EXCLUSION = re.compile(r"gates_telegram")


def _barrido_ancho_sin_declarar(comando: str) -> bool:
    comando = _RE_RELATIVIZAR_RAIZ_ANIDADA.sub("./", comando)
    if not _RE_RECURSIVO.search(comando):
        return False
    if not _RE_RAIZ_ANCHA.search(comando):
        return False
    return not _RE_EXCLUSION.search(comando)


# --------------------------------------------------------------------------
# "Un comodin no nombra y si lee" (TEC-0161, 2026-09-21, incidente de
# Arquitectura): `grep ... Tausa_Labs/gates_telegram/*.jsonl` leyo los tres
# archivos gobernados sin escribir ninguno de sus nombres. Las tres
# comparaciones de arriba miran el NOMBRE del archivo; esta mira el
# DIRECTORIO. Quinta comparacion de la rama Bash/PowerShell.
#
# Regla: un tramo del comando (separado por ; && || | & o salto de linea)
# que alcanza el directorio gobernado se niega, salvo que el tramo ENTERO
# sea la invocacion de un script sancionado. Tres formas de alcanzar:
#   (a) nombrar gates_telegram como componente de ruta -- descenso
#       (gates_telegram/*.jsonl, gates_telegram/$f), el directorio como
#       operando (grep -r x Tausa_Labs/gates_telegram, cd, D=...), en
#       cualquier forma de comilla;
#   (b) un comodin en posicion de DIRECTORIO (*/*.jsonl, Tausa_Labs/g*/x):
#       alcanza el registro sin nombrarlo;
#   (c) un comodin o una variable en el segmento que cuelga de Tausa_Labs
#       (Tausa_Labs/*, Tausa_Labs/$d, Tausa_Labs/gates_%s).
# Y (d): si el cwd del evento ya esta dentro de Tausa_Labs, un comodin suelto
# alcanza lo mismo sin prefijo ninguno.
#
# Nombrar el directorio para EXCLUIRLO sigue pasando (contrato de TEC-0141):
# las construcciones de exclusion de la lista cerrada de abajo se vacian
# ANTES de comparar. Una exclusion sin comillas que trae un comodin NO se
# vacia: `--exclude gates_telegram/*` sin comillas lo expande el shell y
# el primer archivo se vuelve patron y los demas se vuelven operandos.
#
# La excepcion por script es por TRAMO, no por comando: la de las tres
# comparaciones de nombre es por comando entero y por eso
# `cat .../libro_firmas.jsonl; python execution/vigilante_gates.py citar`
# pasa en ellas; aqui no. Un tramo sancionado con sustitucion de comandos o
# con una redireccion hacia el directorio deja de ser sancionado.
#
# Alcance declarado: es una guarda de PATRON, no un sandbox. No ve una ruta
# construida en tiempo de ejecucion ('gates_'+'telegram', chr(), base64, una
# variable cargada en un tramo anterior de otra llamada), ni un script escrito
# a disco y ejecutado despues, ni un enlace creado antes. La fuente primaria
# (code.claude.com/docs/en/permissions, seccion Read and Edit) dice lo mismo
# de las reglas de permisos: no alcanzan a un subproceso que abre archivos por
# su cuenta. El cierre real de esa clase es el sandbox de SO.
# --------------------------------------------------------------------------

_DIR_GATES = "gates_telegram"

# Componente de ruta: no precedido ni seguido por [\w.-]. Asi
# `gates_telegram.py` (el script del canal) y `tec_gates_telegram_x` no
# cuentan; `gates_telegram/`, `gates_telegram\`, `gates_telegram*`,
# `gates_telegram"` y el nombre suelto si.
_RE_COMPONENTE_GATES = re.compile(r"(?<![\w.\-])gates_telegram(?![\w.\-])")
# Forma de RUTA: pegado a un separador o a un comodin. Siempre cuenta.
# El nombre suelto (sin separador) solo cuenta si el comando o el cwd estan
# en Tausa_Labs: `grep -rn "gates_telegram" execution/` busca la PALABRA y
# no puede llegar al directorio; `cd Tausa_Labs && grep -r x gates_telegram`
# si llega.
_RE_RUTA_GATES = re.compile(r"[\\/]gates_telegram(?![\w.\-])|(?<![\w.\-])gates_telegram[\\/*?]")

# Valor de una bandera de exclusion: citado (cualquier contenido) o sin
# comillas y SIN metacaracteres de comodin.
_V_EXCL = r"""(?:"[^"\n]*gates_telegram[^"\n]*"|'[^'\n]*gates_telegram[^'\n]*'|[^\s*?\[\]{}"';|&]*gates_telegram[^\s*?\[\]{}"';|&]*(?=[\s;|&)]|$))"""

# Lista CERRADA de construcciones de exclusion, mismo criterio que
# _FLAGS_PROSA y _RE_RECURSIVO: una nueva se agrega aqui a mano.
_RE_EXCLUSIONES = re.compile(
    # grep / rg / tar / rsync
    r"--exclude(?:-dir)?(?:=|\s+)" + _V_EXCL + r"|"
    r"(?:\s-g|--i?glob)(?:=|\s+)[\"']?!" + r"[^\s\"']*gates_telegram[^\s\"']*[\"']?|"
    # find
    r"(?:-not|!)\s+-i?(?:path|wholename|name)\s+" + _V_EXCL + r"|"
    r"-i?(?:path|wholename|name)\s+" + _V_EXCL + r"\s+-prune\b|"
    # PowerShell
    r"-exclude\s+" + _V_EXCL + r"|"
    r"-not(?:match|like)\s+" + _V_EXCL + r"|"
    # robocopy
    r"/xd\s+" + _V_EXCL + r"|"
    # git pathspec
    r":(?:\(exclude\)|!|\^)" + _V_EXCL + r"|"
    # Python, solo el directorio en si (terminal, sin descenso): literal a la
    # izquierda de `in`/`not in`, a la derecha de `not in`/`!=`, argumento de
    # .remove()/.discard(), o asignado a un nombre de exclusion.
    r"""["'][^"'\n]*(?<![\w.\-])gates_telegram[\\/]?["']\s*(?:not\s+)?in\b|"""
    r"""(?:not\s+in|!=)\s*["'][^"'\n]*(?<![\w.\-])gates_telegram[\\/]?["']|"""
    r"""\.(?:remove|discard)\s*\(\s*["'][^"'\n]*(?<![\w.\-])gates_telegram[\\/]?["']\s*\)|"""
    r"""\b\w*(?:excl|skip|omit|ignor|prune)\w*\s*=\s*(?:os\.path\.\w+\(|path\(|str\()?\s*["'][^"'\n]*(?<![\w.\-])gates_telegram[\\/]?["']\s*\)?"""
)

# Un tramo es sancionado si ES la invocacion de uno de los tres scripts
# existentes: prefijo opcional de asignaciones de entorno (VAR=valor), el
# interprete, banderas del interprete, y la ruta del script.
_RE_TRAMO_SANCIONADO = re.compile(
    r"""^\s*&?\s*(?:[a-z_][a-z0-9_]*=\S*\s+)*"""
    r"""(?:\S*[\\/])?(?:python3?|py)(?:\.exe)?["']?\s+(?:-[a-z]\s+)*"""
    r"""["']?(?:\S*[\\/])?(?:vigilante_gates\.py["']?\s+(?:citar|vigilar)\b|"""
    r"""verificar_aprobacion_telegram\.py\b|registrar_evento_acto\.py\b)"""
)
_RE_TRAMO_CONTAMINADO = re.compile(r"\$\(|`|<\(|>\(|[<>]\s*[\"']?\S*gates_telegram")

_RE_SEPARADOR_TRAMOS = re.compile(r"\|\||&&|[;|\n]|(?<![<>0-9])&(?!>)")

# (b) comodin en posicion de directorio: el PRIMER segmento de un token de
# ruta (con ./ o ../ opcionales) lleva * o ? y le sigue un separador. Se
# descartan los que contienen `.*`, que es la forma de una regex y no de un
# glob (`grep -o "http.*/"`).
_RE_COMODIN_DIRECTORIO = re.compile(r"(?:^|(?<=[\s=(,]))(?:\.{1,2}[\\/])*[\w.\-]*[*?][\w.\-*?]*[\\/]")
# (c) comodin o variable en el segmento que cuelga de Tausa_Labs.
_RE_COMODIN_BAJO_TAUSA = re.compile(r"tausa_labs[\\/]+[^\s\\/\"']*[*?\[{$%]")
# (d) comodin suelto, para cuando el cwd ya esta dentro de Tausa_Labs.
_RE_COMODIN_SUELTO = re.compile(r"[*?\[]")


def _cwd_bajo_tausa_labs(cwd: str) -> bool:
    c = _normalizar_ruta(cwd)
    return "/tausa_labs/" in c + "/"


def _normalizar_ruta(ruta: str) -> str:
    """Minusculas, separador /, sin `.`/`..`/`//`. La comparacion por
    subcadena sobre la ruta cruda la esquivaba `Tausa_Labs/./gates_telegram`
    o `Tausa_Labs/x/../gates_telegram` (TEC-0161, rama Read)."""
    import posixpath
    r = str(ruta).replace("\\", "/").lower()
    if not r:
        return r
    prefijo = ""
    if r.startswith("//"):
        prefijo, r = "/", r[1:]
    r = posixpath.normpath(r)
    return prefijo + r


_RE_CITADO = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'')
# Construido desde _RAIZ_WORKSPACE, nunca escrito a mano -- corregido en
# TEC-0169: la version portada traia esta ruta fija, absoluta y valida
# solo en el entorno de origen (detalle en la bitacora de TEC-0169).
_OBJETIVO_GATES = _normalizar_ruta(str(_RAIZ_WORKSPACE / "Tausa_Labs" / "gates_telegram"))


def _cwd_es_ancestro_de_gates(cwd: str) -> bool:
    if not cwd:
        return True  # sin cwd no se puede descartar
    c = _normalizar_ruta(cwd).rstrip("/")
    return _OBJETIVO_GATES.startswith(c + "/") or _OBJETIVO_GATES == c


def _comodin_en_directorio(tramo: str, cwd: str) -> bool:
    """(b) solo sobre el texto SIN comillas -- el que el shell expande; un
    comodin citado es argumento de un programa (sed, grep -E) y su forma es la
    de una regex, no la de un glob (medido el 2026-09-21: `sed 's/.*x: *//'`
    de la lista de permitidos daba deny). Y solo si el cwd es ancestro del
    directorio gobernado, o si el token sube con ../: `*/*.jsonl` desde
    ~/.claude/projects no puede llegar (misma medicion)."""
    sin_citas = _RE_CITADO.sub(" ", tramo)
    ancestro = _cwd_es_ancestro_de_gates(cwd)
    for m in _RE_COMODIN_DIRECTORIO.finditer(sin_citas):
        token = m.group(0)
        if ".*" in token:
            continue
        if ancestro or token.startswith(".."):
            return True
    return False


def _alcanza_dir_gates(comando_sin_prosa: str, cwd: str = "") -> bool:
    neutro = _RE_EXCLUSIONES.sub(" <exclusion> ", comando_sin_prosa)
    en_tausa = _cwd_bajo_tausa_labs(cwd) if cwd else False
    en_gates = en_tausa and "/gates_telegram/" in _normalizar_ruta(cwd) + "/"
    nombre_suelto_cuenta = en_tausa or "tausa_labs" in neutro
    for tramo in _RE_SEPARADOR_TRAMOS.split(neutro):
        if not tramo.strip():
            continue
        if _RE_TRAMO_SANCIONADO.search(tramo) and not _RE_TRAMO_CONTAMINADO.search(tramo):
            continue
        plano = tramo.replace('"', "").replace("'", "").replace("^", "")
        if _RE_RUTA_GATES.search(plano):
            return True
        if nombre_suelto_cuenta and _RE_COMPONENTE_GATES.search(plano):
            return True
        if _comodin_en_directorio(tramo.replace("^", ""), cwd) or _RE_COMODIN_BAJO_TAUSA.search(plano):
            return True
        if en_gates:
            return True
        if en_tausa and _RE_COMODIN_SUELTO.search(plano):
            return True
    return False


# Rama Grep (herramienta). Solo actua si el matcher PreToolUse de
# settings.local.json incluye Grep; hoy no lo incluye (matcher vivo:
# "Read|Edit|Write|Bash|PowerShell|mcp__.*"). Queda escrita para que la
# ampliacion del matcher sea un acto de configuracion y no de codigo.
_NOMBRES_GOBERNADOS = ("libro_firmas.jsonl", "avisos_enviados.jsonl", "eventos_acto.jsonl")


def _grep_herramienta_alcanza(inp: dict, cwd: str) -> bool:
    import fnmatch
    crudo = str(inp.get("path") or "")
    if crudo and not re.match(r"^([a-z]:|[\\/])", crudo, re.I) and cwd:
        crudo = cwd.rstrip("\\/") + "/" + crudo
    base = _normalizar_ruta(crudo or cwd or "")
    if "/tausa_labs/gates_telegram/" in base + "/":
        return True
    # Ancestro del directorio gobernado: la raiz del workspace, Tausa_Labs, o
    # cualquier prefijo de esa ruta.
    es_ancestro = _OBJETIVO_GATES.startswith(base.rstrip("/") + "/") if base else True
    if not es_ancestro:
        return False
    glob = str(inp.get("glob") or "").lower()
    tipo = str(inp.get("type") or "").lower()
    if glob.startswith("!") and _DIR_GATES in glob:
        return False
    if tipo and tipo not in ("json", "jsonl", "all"):
        return False
    if glob:
        patrones = [g.strip() for g in glob.strip("{}").split(",") if g.strip()]
        candidatos = list(_NOMBRES_GOBERNADOS) + ["x.jsonl"]
        return any(fnmatch.fnmatch(n, p.split("/")[-1]) for p in patrones for n in candidatos)
    return True


# --------------------------------------------------------------------------
# "La frontera real" (TEC-0147, ADR-0036 S4/D3, E3): clausulas (a)(b)(c) mas
# criterio 11 (S11). Una llamada de publicacion de Composio sin cuenta
# explicita, con una cuenta fuera de las registradas para la compania del
# encargo en curso, o con un mapa de frontera que no se puede leer o esta mal
# formado, se niega. Un payload de forma no reconocida tambien se niega
# (criterio 11): ausencia de forma reconocible no es permiso, igual que
# ausencia de mapa no es permiso (ADR-0028/ADR-0036 S11).
# --------------------------------------------------------------------------

# Lista cerrada de slugs de publicacion medidos/documentados (SKILL.md de
# faceless-content-engine, ARCHITECTURE.md de Faceless/faceless-creator).
# Comparacion por subcadena en mayusculas sobre tool_name completo porque dos
# prefijos MCP distintos sirven al mismo servidor Composio en este entorno.
# Lista cerrada a proposito, igual que _FLAGS_PROSA/_RE_RECURSIVO: un slug
# nuevo se agrega aqui a mano cuando se mida/documente.
ACCIONES_PUBLICACION_COMPOSIO = (
    "YOUTUBE_MULTIPART_UPLOAD_VIDEO",
    "YOUTUBE_UPDATE_THUMBNAIL",
    "INSTAGRAM_POST_IG_USER_MEDIA_PUBLISH",
    "INSTAGRAM_POST_IG_USER_MEDIA",
    "INSTAGRAM_CREATE_MEDIA_CONTAINER",
    "INSTAGRAM_GET_POST_STATUS",
    "TIKTOK_UPLOAD_VIDEO",
    "TIKTOK_PUBLISH_VIDEO",
)


def _es_accion_publicacion(tool: str) -> bool:
    t = tool.upper()
    return any(accion in t for accion in ACCIONES_PUBLICACION_COMPOSIO)


# _RAIZ_WORKSPACE se define arriba, justo tras los imports (la necesitan
# _RE_RAIZ_ANCHA y _OBJETIVO_GATES antes de este punto del archivo).

# Ruta por defecto del mapa de frontera (capa C, ADR-0036 D2/3). Overridable
# por TAUSA_REGISTRO_MARCAS -- mismo patron que TAUSA_HOOK_STATE_DIR en
# sello_atribucion.py -- para poder probar las clausulas (b)/(c) sin tocar el
# mapa real ni depender de su contenido de hoy.
_RUTA_MAPA_FRONTERA_DEFECTO = _RAIZ_WORKSPACE / "execution" / "registro_marcas.json"

# Compania del encargo en curso: no existe ese campo en el evento PreToolUse
# ni en el esquema de ninguna herramienta de Composio (medido: TEC-0136).
# TAUSA_COMPANIA_ENCARGO lo declara explicitamente; por defecto "Tausa Labs",
# la unica compania real con uso en produccion hoy (DT-117, sin onboarding de
# cliente ejecutado). Una futura incorporacion de cliente debe fijar esta
# variable antes de publicar bajo esa compania -- esto es una decision
# declarada, no un supuesto silencioso.
COMPANIA_POR_DEFECTO = "Tausa Labs"


class _MapaFronteraInvalido(Exception):
    """El mapa de frontera no se pudo leer, esta vacio o no tiene la forma
    compania -> marca -> red -> destino esperada. Clausula (c)."""


def _companias_de_frontera() -> dict:
    ruta = Path(os.environ.get("TAUSA_REGISTRO_MARCAS", str(_RUTA_MAPA_FRONTERA_DEFECTO)))
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise _MapaFronteraInvalido(f"no se pudo leer el mapa de frontera: {exc}") from exc
    if not isinstance(datos, dict):
        raise _MapaFronteraInvalido("el mapa de frontera no tiene forma de objeto")
    companias = datos.get("companias")
    if not isinstance(companias, dict) or not companias:
        raise _MapaFronteraInvalido("el mapa de frontera no tiene 'companias' o esta vacio")
    return companias


def _cuentas_permitidas(compania: str) -> set:
    """Aplana marca->red->destino de UNA compania a un set de cuentas
    (destinos) permitidas. Una compania ausente del mapa devuelve un set
    vacio a proposito -- eso es clausula (b): la cuenta cae fuera de una
    lista vacia, no un mapa roto. Una marca con forma invalida (no
    marca->red->destino) SI es clausula (c): eso es el mapa mal formado."""
    companias = _companias_de_frontera()
    marcas = companias.get(compania, {})
    if not isinstance(marcas, dict):
        raise _MapaFronteraInvalido(f"la compania '{compania}' no tiene forma marca->red->destino en el mapa de frontera")
    cuentas = set()
    for redes in marcas.values():
        if not isinstance(redes, dict):
            raise _MapaFronteraInvalido("una marca del mapa de frontera no tiene forma red->destino")
        for destino in redes.values():
            if not isinstance(destino, str) or not destino:
                raise _MapaFronteraInvalido("un destino del mapa de frontera no es una cadena no vacia")
            cuentas.add(destino)
    return cuentas


def _cuenta_de_publicacion(inp):
    """Extrae 'account' de un payload de publicacion. Criterio 11 (S11): una
    forma no reconocida (tool_input sin forma de objeto, o 'account' presente
    pero no como cadena) se declara invalida via _MapaFronteraInvalido -- nunca
    pasa silenciosa como "sin cuenta" ni revienta con una excepcion no
    controlada."""
    if not isinstance(inp, dict):
        raise _MapaFronteraInvalido("tool_input de una accion de publicacion no tiene forma de objeto")
    if "account" not in inp:
        return None
    cuenta = inp["account"]
    if not isinstance(cuenta, str) or not cuenta:
        raise _MapaFronteraInvalido("'account' de una accion de publicacion no es una cadena no vacia")
    return cuenta


# --------------------------------------------------------------------------
# G2 (ADR-0044 E7, TEC-0175 T1): techo duro del worker de Orca.
# --------------------------------------------------------------------------
# Actua solo "en zona Orca": cuando la cwd del evento, $CLAUDE_PROJECT_DIR o
# la ruta de este mismo archivo caen bajo `.../orca/workspaces/` (donde Orca
# crea los worktrees). Fuera de la zona, nada de esto cambia el
# comportamiento de la guarda. Dentro:
#   a) git push / remote / send-pack / receive-pack / credential en las
#      formas que la regla `deny` de settings.json (G1) no ve por ser texto:
#      `git -C . push`, `git -c k=v push`, `git 'push'`, `git.exe push`,
#      ruta absoluta a git, escapes de PowerShell (`) o cmd (^);
#   b) git config o `-c` que toque remote.*, url.*, credential.*, alias.*,
#      pushurl, insteadOf, pushremote (un alias o un insteadOf es un push o
#      un remoto disfrazado);
#   c) `gh` en posicion de comando: gh, gh.exe, ruta absoluta, `& "...\gh.exe"`;
#   d) asignar o borrar GH_CONFIG_DIR / GH_TOKEN / GITHUB_TOKEN / GH_HOST /
#      *_ENTERPRISE_TOKEN (G3). Nombrarlas para leerlas (printenv) pasa;
#   e) (G2-bis, pendiente de D6) nombrar Agente_Accesos, gates_telegram,
#      la vault Obsidian o los almacenes de cuentas de Orca/Claude/gh;
#   f) (TEC-0178 M1.5, S7 de TEC-0176) `gate-resolve` de Orca: resolver un
#      gate es del Tech Lead, nunca de un worker. Se busca la palabra con las
#      comillas y las barras invertidas quitadas, en cualquier posicion,
#      porque es texto y no una frontera; nombrarla en un `grep` tambien se
#      niega (falso positivo aceptado: en la zona no hay por que buscarla).
# Y, dentro de la zona, TODA denegacion de esta guarda sale con codigo 2
# (ADR-0044 D4(2)): el JSON `permissionDecision: deny` se sigue imprimiendo
# (lo lee el banco de pruebas), pero lo que bloquea sin depender del modo de
# permisos es el 2. Un fallo de la propia guarda en zona tambien sale con 2.
# El prefijo "G2 worker Orca:" distingue en la evidencia a G2 de G1: G1 es la
# regla `deny` y rechaza antes de que este hook llegue a correr.
# Esto es texto, no una frontera: un script que abre procesos por su cuenta
# lo esquiva. La frontera real de `gh` y del push a GitHub es G3.
_ZONA_ORCA = "/orca/workspaces/"
_ZONA_ACTIVA = False
_ULTIMA_RAZON = ""


def _en_zona_orca(cwd: str) -> bool:
    candidatos = (cwd, os.environ.get("CLAUDE_PROJECT_DIR", ""), str(Path(__file__).resolve()))
    return any(_ZONA_ORCA in _normalizar_ruta(c) + "/" for c in candidatos if c)


# Prosa de un mensaje de commit: se vacia para que `-m "sin push"` no dispare.
_RE_G2_MENSAJE = re.compile(r"""((?:^|\s)(?:-m|--message)(?:=|\s+))("[^"\n]*"|'[^'\n]*')""")
_G2_INICIO = r"(?:^|[\s;&|(){}\\/=])"
_G2_FIN = r"(?=$|[\s;&|)])"
_RE_G2_GIT_SUB = re.compile(
    _G2_INICIO + r"git(?:\.exe)?(?=\s)[^;&|\n]*?\s"
    r"(push|remote|send-pack|receive-pack|credential|credential-[\w-]+)" + _G2_FIN)
_RE_G2_GIT_CONF = re.compile(
    _G2_INICIO + r"git(?:\.exe)?(?=\s)[^;&|\n]*?"
    r"(?:(?<![\w.-])(?:remote|url|credential|alias)\.|\b(?:pushurl|insteadof|pushremote)\b|\.remote\b)")
_RE_G2_GH = re.compile(_G2_INICIO + r"gh(?:\.exe)?" + _G2_FIN)
_G2_VARS = r"(?:gh_config_dir|gh_token|github_token|gh_host|gh_enterprise_token|github_enterprise_token)"
_RE_G2_VAR_ESCRITA = re.compile(
    r"\b" + _G2_VARS + r"\b\s*\]?\s*=|"
    r"\bunset\b[^;&|\n]*\b" + _G2_VARS + r"\b|"
    r"\benv\b[^;&|\n]*-u\s*" + _G2_VARS + r"\b|"
    r"\bremove-item\b[^;&|\n]*env:" + _G2_VARS + r"\b|"
    r"setenvironmentvariable\s*\(\s*" + _G2_VARS + r"\b|"
    r"\bpop\s*\(\s*" + _G2_VARS + r"\b|"
    r"\bdel\s+os\.environ\s*\[\s*" + _G2_VARS + r"\b")
# G2-bis (pendiente de D6): si Steve no lo aprueba, se borran esta constante
# y su bloque en _g2_motivo, sin tocar el resto.
_RE_G2_GATE_RESOLVE = re.compile(r"gate[-_]?resolve")
_RE_G2BIS = re.compile(
    r"agente_accesos|gates_telegram|(?:^|[\s\\/=])obsidian(?:[\\/]|$|\s)|"
    r"claude-accounts|claude-runtime-auth|codex-pane-accounts|agent-session-authority|"
    r"orca-data\.json|last-status\.json|endpoint\.cmd|github cli[\\/]|"
    r"\.git-credentials|\.credentials\.json")


def _g2_motivo(comando: str) -> str:
    """Motivo de bloqueo G2 para un comando ya en minusculas, o "" si pasa."""
    c = _RE_G2_MENSAJE.sub(r"\1", comando)
    c = c.replace("`", "").replace("^", "")
    if _RE_G2_GATE_RESOLVE.search(re.sub(r"[\"'\\]", "", c)):
        return ("gate-resolve no se usa desde un worker de Orca: resolver un gate es del "
                "Tech Lead, con la firma verificada (TEC-0178 M1.5).")
    c = re.sub(r"[\"']", " ", c)
    if _RE_G2_GIT_SUB.search(c):
        return ("push, remotos y credenciales de git no se tocan desde un worker; "
                "la integracion la hace el Tech Lead con la delegacion del Owner.")
    if _RE_G2_GIT_CONF.search(c):
        return ("git config o -c sobre remote/url/credential/alias no se permite en un worker "
                "(es un remoto o un push disfrazado).")
    if _RE_G2_GH.search(c):
        return "gh no se usa desde un worker de Orca (G1/G3)."
    if _RE_G2_VAR_ESCRITA.search(c):
        return ("GH_CONFIG_DIR y los tokens de GitHub no se asignan ni se borran desde un "
                "worker (G3); leerlos con printenv si se permite.")
    if _RE_G2BIS.search(c):
        return ("este comando nombra Agente_Accesos, gates_telegram, la vault o un almacen "
                "de cuentas; un worker no los toca por ninguna via.")
    return ""


def main() -> int:
    global _ZONA_ACTIVA
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    tool = event.get("tool_name", "")
    inp = event.get("tool_input") or {}
    cwd = str(event.get("cwd") or "")
    _ZONA_ACTIVA = _en_zona_orca(cwd)
    if tool == "Read":
        path = _normalizar_ruta(inp.get("file_path", ""))
        if "/tausa_labs/gates_telegram/libro_firmas.jsonl" in path:
            deny("Gobierno de gates: no leas el libro crudo; usa vigilante_gates.py citar.")
            return 0
        if "/tausa_labs/gates_telegram/avisos_enviados.jsonl" in path:
            deny("Gobierno de gates: no leas los avisos crudos; usa verificar_aprobacion_telegram.py.")
            return 0
        if "/tausa_labs/gates_telegram/eventos_acto.jsonl" in path:
            deny("Gobierno de gates: no leas los eventos de acto crudos; usa registrar_evento_acto.py o verificar_aprobacion_telegram.py.")
            return 0
        # TEC-0161: cualquier otro archivo dentro del directorio gobernado.
        if "/tausa_labs/gates_telegram/" in path:
            deny("Gobierno de gates: nada dentro de Tausa_Labs/gates_telegram se lee crudo; "
                 "usa vigilante_gates.py, verificar_aprobacion_telegram.py o registrar_evento_acto.py.")
            return 0
        if any(part in path for part in PROTEGIDO_SECRETOS):
            deny("Techo duro: el custodio de secretos no se lee desde un agente.")
            return 0
    if tool == "Grep" and _grep_herramienta_alcanza(inp, cwd):
        deny("Gobierno de gates: esta busqueda alcanza Tausa_Labs/gates_telegram. Acota "
             "path fuera de Tausa_Labs, o declara glob \"!**/gates_telegram/**\", o un "
             "type/glob que no pueda coincidir con .jsonl.")
        return 0
    if tool in {"Edit", "Write"}:
        path = _normalizar_ruta(inp.get("file_path", ""))
        if any(part in path for part in PROTEGIDO_SECRETOS):
            deny("Techo duro: secretos y el registro de accesos no se editan desde un agente.")
            return 0
        # TEC-0063, gate 133 (id_acto TEC-0063-guarda-escritura-gates-telegram-20260830,
        # firmado 2026-08-30): el verificador lee estos tres archivos como si
        # fueran el canal (TEC-0059 S11); quien pueda escribirlos fabrica una
        # firma que exit 0 confirma como autentica, sin necesidad de leerlos.
        # Bloqueo total, sin excepcion por nombre de script -- esa excepcion es
        # la clase exacta que produjo el bypass del gate 128. Los recolectores
        # y registradores legitimos escriben con open()/_append_jsonl() dentro
        # de su propio proceso, nunca con esta herramienta; esta guarda es
        # PreToolUse sobre llamadas de herramienta y nunca ve esa escritura
        # interna, asi que el bloqueo total no rompe el canal.
        rutas_gates = (
            "/tausa_labs/gates_telegram/libro_firmas.jsonl",
            "/tausa_labs/gates_telegram/avisos_enviados.jsonl",
            "/tausa_labs/gates_telegram/eventos_acto.jsonl",
        )
        if any(ruta in path for ruta in rutas_gates) or "/tausa_labs/gates_telegram/" in path:
            deny("Gobierno de gates: estos archivos no se editan con la herramienta de edición; los escriben sus scripts.")
            return 0
    if tool in {"Bash", "PowerShell"}:
        command = str(inp.get("command", "")).lower()
        blocked = (
            (r"\bgit\s+push\b", "Techo duro: un push externo exige revisión humana."),
            (r"\bwrangler\b.*\bdeploy\b", "Techo duro: desplegar producción exige firma."),
            (r"\bnpm\s+publish\b", "Techo duro: publicar un paquete exige firma."),
            (r"\b(remove-item\s+.*-recurse|rm\s+-rf|rmdir\s+/s|rd\s+/s|del\s+/[sq])", "Techo duro: borrado recursivo exige firma."),
            (r"\bclaude\s+mcp\s+(add|remove)\b", "Techo duro: crear o retirar conexiones exige firma."),
        )
        # G2 (TEC-0175): primero, y solo en zona Orca. Mas estricta que todo
        # lo que sigue; su prefijo propio identifica la regla en la evidencia.
        if _ZONA_ACTIVA:
            razon_g2 = _g2_motivo(command)
            if razon_g2:
                deny("G2 worker Orca: " + razon_g2)
                return 0
        # Orden que importa: primero el chequeo de subshell (bloquea sin
        # excepción), después el vaciado condicional, después las tres
        # comparaciones de archivo gobernado sobre la copia resultante.
        if _tiene_subshell_en_prosa(command):
            deny("Gobierno de gates: sustitución de comandos o subshell dentro de "
                 "--resumen/--motivo/--descripcion no se permite, con o sin archivo gobernado de por medio.")
            return 0
        comando_sin_prosa = _sin_prosa_de_argumentos_libres(command)
        if "libro_firmas.jsonl" in comando_sin_prosa and not re.search(r"vigilante_gates\.py\s+(citar|vigilar)\b", command):
            deny("Gobierno de gates: el libro solo se consulta mediante vigilante_gates.py.")
            return 0
        if "avisos_enviados.jsonl" in comando_sin_prosa and not re.search(r"verificar_aprobacion_telegram\.py\b", command):
            deny("Gobierno de gates: los avisos solo se consultan mediante verificar_aprobacion_telegram.py.")
            return 0
        if "eventos_acto.jsonl" in comando_sin_prosa and not re.search(r"registrar_evento_acto\.py\b|verificar_aprobacion_telegram\.py\b", command):
            deny("Gobierno de gates: los eventos de acto solo se consultan mediante registrar_evento_acto.py o verificar_aprobacion_telegram.py.")
            return 0
        # TEC-0161 (2026-09-21): quinta comparacion, por directorio y no por
        # nombre. Despues de las tres de nombre (conservan su mensaje) y antes
        # del barrido de TEC-0141 (esta es mas estricta: un barrido que nombra
        # el directorio fuera de una exclusion ya no cuenta como declarado).
        if _alcanza_dir_gates(comando_sin_prosa, cwd):
            deny("Gobierno de gates: este comando alcanza Tausa_Labs/gates_telegram por "
                 "comodin, variable o directorio, sin nombrar el archivo. Esos archivos "
                 "solo se consultan con vigilante_gates.py citar|vigilar, "
                 "verificar_aprobacion_telegram.py o registrar_evento_acto.py, en su "
                 "propio tramo. Para excluir el directorio de un barrido, usa "
                 "--exclude-dir, -Exclude, -not -path o un glob con !.")
            return 0
        # TEC-0141 (2026-09-07): cuarta comparacion. Va DESPUES de las tres de
        # nombre para que nombrar conserve su precedencia y su mensaje propio,
        # y ANTES de `blocked` porque es gobierno de gates, no techo duro.
        if _barrido_ancho_sin_declarar(comando_sin_prosa):
            deny("Gobierno de gates: un barrido recursivo que alcanza la raiz del "
                 "workspace debe declarar por escrito que excluye "
                 "Tausa_Labs/gates_telegram. Declara la exclusion en el propio "
                 "comando (saltar ese directorio en el recorrido, --exclude-dir, "
                 "-Exclude) y vuelve a lanzarlo.")
            return 0
        for pattern, reason in blocked:
            if re.search(pattern, command):
                deny(reason)
                return 0
    if _es_accion_publicacion(tool):
        try:
            cuenta = _cuenta_de_publicacion(inp)
        except _MapaFronteraInvalido as exc:
            deny("Techo duro: payload de publicacion de forma no reconocida "
                 f"({exc}); ausencia de forma reconocible tampoco es permiso "
                 "(ADR-0036 S11, criterio 11).")
            return 0
        if cuenta is None:
            deny("Techo duro: una accion de publicacion sin 'account' "
                 "explicito no se permite (ADR-0036 D3/E3, clausula a).")
            return 0
        compania = os.environ.get("TAUSA_COMPANIA_ENCARGO", COMPANIA_POR_DEFECTO)
        try:
            permitidas = _cuentas_permitidas(compania)
        except _MapaFronteraInvalido as exc:
            deny(f"Techo duro: el mapa de frontera no se pudo evaluar ({exc}); "
                 "ausencia de mapa no es permiso (ADR-0036 D3/E3, clausula c).")
            return 0
        if cuenta not in permitidas:
            deny(f"Techo duro: la cuenta '{cuenta}' no esta entre las cuentas "
                 f"registradas de '{compania}' en el mapa de frontera "
                 "(ADR-0036 D3/E3, clausula b).")
            return 0
    if "manage_connections" in tool.lower():
        toolkits = inp.get("toolkits") or []
        # "list" no tiene efectos secundarios (ver descripción del tool); el resto
        # ("add" es el default si no se declara, "rename", "remove") sí los tiene.
        if any(str(item.get("action", "add")) != "list" for item in toolkits):
            deny("Techo duro: crear, renombrar o retirar conexiones exige firma.")
    return 0


if __name__ == "__main__":
    # G2 (TEC-0175): en zona Orca, deny sale con 2 y un fallo de la guarda
    # tambien; fuera de la zona, exactamente igual que antes.
    try:
        _rc = main()
    except Exception as exc:
        if _ZONA_ACTIVA or _en_zona_orca(""):
            sys.stderr.write("G2 worker Orca: la guarda fallo ("
                             + type(exc).__name__ + "); se bloquea por defecto.\n")
            raise SystemExit(2)
        raise
    if _ZONA_ACTIVA and _ULTIMA_RAZON:
        try:
            sys.stderr.write(_ULTIMA_RAZON + "\n")
        except Exception:
            pass
        _rc = 2
    raise SystemExit(_rc)
