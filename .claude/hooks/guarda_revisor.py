#!/usr/bin/env python3
"""PreToolUse: guarda de revisor (TEC-0176, D1; actos TEC-0176-guarda-revisor
a -v4; v5: acto TEC-0178-M1.1, ADR-0042 D3 opción A).

Cableada en .claude/settings.json como PRIMERA entrada PreToolUse, matcher `*`.
Casos del banco: I (probar_plantilla.py).

Lee el marcador `<raíz del checkout>/.tausa/rol`, donde la raíz sale de __file__
(no de CLAUDE_PROJECT_DIR, que no es necesario para decidir):

- no existe `.tausa/`             -> constructor: no hace nada, rc 0, sin leer stdin.
- `rol` dice `constructor`         -> igual.
- `rol` dice `revisor`, está vacío, no se puede leer, es un directorio o un enlace,
  o existe `.tausa/` sin `rol`     -> modo revisor (falla cerrada).

En modo revisor solo pasan herramientas de lectura locales (WebFetch y WebSearch
no: son canal de salida) y los Bash que coinciden EXACTAMENTE con una plantilla
de la gramática del revisor. Todo lo demás se niega con JSON en stdout, motivo
en stderr y rc 2. Cualquier excepción en modo revisor también da rc 2.

v5 (TEC-0178 M1.1). v1 a v4 clasificaban texto de shell con shlex y una lista
blanca de comandos; cuatro rondas de revisión encontraron cuatro familias de
huecos (`#` a mitad de palabra, llaves con cierre entre comillas, comodines que
cambian el número de argumentos, opciones permutadas). v5 no interpreta bash:
el comando ENTERO tiene que coincidir (re.fullmatch) con una de las plantillas
de PLANTILLAS. Fuera de los dos textos '...' de `orca orchestration send`, el
alfabeto posible es de letras, dígitos y `._/:@=%,-` en posiciones fijas,
separadas por un solo espacio: bash no puede expandir, redirigir, encadenar ni
sustituir nada, y el argv resultante se conoce leyendo la gramática. Dentro de
'...' bash no interpreta nada y la comilla simple está excluida.
- Sin normalizar: un espacio doble, inicial o final, o un tabulador, niegan.
- git: `log` (con `--format='%h %ad %s' --date=short` u `--oneline`), `show` y
  `diff` con `--no-ext-diff --no-textconv`, `blame --no-textconv` y
  `rev-parse [--short] HEAD`. Sin `status`: puede ejecutar `core.fsmonitor` y
  filtros `clean` de la config. Sin opciones globales de git.
- orca: `send` de `worker_done` o `escalation` (sin `--to`, `--payload`,
  `--report-path`, `--files-modified`, `--environment`, `--pairing-code`...),
  `check [--peek] [--json]` y `dispatch-show --task <id> --preamble [--json]`.
- La única ruta que entra por Bash es la de `git diff|blame -- RUTA`: sin `/` ni
  `-` inicial, sin segmentos vacíos, `.` o `..`, y nunca bajo `.tausa`.

Limitaciones aceptadas (documentadas, sin código):
- FALLA ABIERTA si falta `python` o si vence el timeout del hook: Claude Code solo
  bloquea con rc 2 o con `deny`. El pre-vuelo p6 prueba `python --version` en el
  worktree antes de lanzar, pero no protege de un fallo a mitad de sesión.
- La guarda y .claude/settings.json viven en el worktree revisado: p6 compara el
  sha256 de los dos con master antes de lanzar al revisor. El `env` de settings
  (PATH, HOME, GIT_*) y el del proceso de Orca gobiernan qué `git` y qué config
  se usan; p6 cubre el primero, el segundo no lo controla el revisor.
- Los drivers y filtros de la config LOCAL o de SISTEMA de git: `--no-ext-diff`
  y `--no-textconv` los cortan en diff, show y blame. `log` sin `-p` no genera
  diffs.
- El largo de `--body` tiene tope LIM sin medir en vivo (ADR-0042 §4.8).
- Leer el marcador con Read o Glob no se niega. Escribirlo, por ninguna vía.
"""

import json
import os
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
DIR_MARCADOR = RAIZ / ".tausa"
MARCADOR = DIR_MARCADOR / "rol"
PREFIJO = "Guarda de revisor"

# Sin WebFetch ni WebSearch: son canal de salida (T5).
HERRAMIENTAS_LECTURA = {"Read", "Grep", "Glob", "LS", "TodoWrite", "ToolSearch"}


# --- Rutas fuera de la raíz (T5, security-auditor 5) ---
_UNIDAD_GITBASH = re.compile(r"^/([A-Za-z])(?=/|$)")
_UNIDAD_WIN = re.compile(r"^[A-Za-z]:")
_TILDE = re.compile(r"(^|[=:])~")
_SEG_COMODIN_PUNTO = re.compile(r"^\.[?*\[]")  # v4: en Bash ya se niega antes; sigue para Glob


def _norm(p) -> Path:
    return Path(os.path.normcase(os.path.normpath(str(p))))


def _dentro(p: Path, raiz: Path) -> bool:
    try:
        p.relative_to(raiz)
        return True
    except ValueError:
        return False


def _a_ruta(texto: str, base: Path):
    """Path absoluta para `texto` (relativa a `base`), o None si es una ruta
    absoluta que no se sabe mapear (se trata como fuera)."""
    m = _UNIDAD_GITBASH.match(texto)
    if m:
        return Path(m.group(1) + ":" + (texto[m.end():] or "/"))
    if texto[:1] in ("/", "\\"):
        return None
    if _UNIDAD_WIN.match(texto):
        if texto[2:3] not in ("/", "\\"):
            return None  # `C:algo`: relativa a la cwd de esa unidad
        return Path(texto)
    return base / texto


def _fuera(texto: str, base: Path):
    """Motivo si `texto` es (o puede expandirse a) una ruta fuera de la raíz."""
    if not texto:
        return None
    if _TILDE.search(texto):
        return f"ruta con ~ (fuera de la raíz): {texto}"
    if any(_SEG_COMODIN_PUNTO.match(s) for s in re.split(r"[\\/]", texto)):
        return f"comodín que puede valer `..`: {texto}"
    ruta = _a_ruta(texto, base)
    raiz = _norm(RAIZ)
    if ruta is None or not _dentro(_norm(ruta), raiz):
        return f"ruta fuera de la raíz del worktree: {texto}"
    motivo = _punto_punto_fisico(ruta, texto)
    if motivo:
        return motivo
    try:
        real = _norm(ruta.resolve())
    except (OSError, RuntimeError, ValueError):
        real = _norm(ruta)
    if not _dentro(real, raiz):
        return f"ruta que resuelve fuera de la raíz del worktree: {texto}"
    return None


def _punto_punto_fisico(ruta: Path, texto: str):
    """v3: `..` detrás de un enlace/unión (bash lo resuelve en el destino, Python
    léxicamente) o de un comodín (bash lo expande antes)."""
    if ".." not in ruta.parts:
        return None
    prefijo = Path(ruta.parts[0])
    for parte in ruta.parts[1:]:
        if parte == "..":
            if any(ch in str(prefijo) for ch in "*?["):
                return f"`..` detrás de un comodín: {texto}"
            try:
                fisica = _norm(prefijo.resolve())
            except (OSError, RuntimeError, ValueError):
                fisica = None
            if fisica != _norm(prefijo):
                return f"`..` detrás de un enlace o unión: {texto}"
        prefijo = prefijo / parte
    return None


def _base(cwd):
    """(base, motivo): la cwd del evento si está dentro de la raíz; RAIZ si no hay."""
    if not cwd:
        return RAIZ, None
    try:
        ruta = _a_ruta(str(cwd), RAIZ)
        base = ruta.resolve() if ruta is not None else None
    except (OSError, RuntimeError, ValueError):
        base = None
    if base is None or not _dentro(_norm(base), _norm(RAIZ)):
        return None, "la cwd de la sesión está fuera de la raíz del worktree"
    return base, None


# --- v5: gramática exacta del revisor (TEC-0178 M1.1; ADR-0042 D3 opción A) ---
LIM = 12000  # tope de largo del comando; ADR-0042 §4.8 sin medir en vivo
SHA = r"[0-9a-f]{7,40}"
REF = rf"(?:{SHA}|HEAD)"
RANGO = rf"{REF}\.\.{REF}"
N = r"[1-9][0-9]{0,2}"
LIN = r"[1-9][0-9]{0,5}"
RUTA = r"(?P<ruta>[A-Za-z0-9._/-]{1,200})"  # se valida aparte (_ruta_mala)
FMT = r"--format='%h %ad %s' --date=short"  # M2.6: sin %ae ni %ce
ID = r"[A-Za-z0-9_-]{1,64}"
HANDLE = r"[A-Za-z0-9_.:@-]{1,80}"
TXT = r"'[^'\x00-\x08\x0b-\x1f\x7f]*'"  # admite \t y \n; niega ' y \r
NOEXT = r"--no-ext-diff --no-textconv"
DESTINO = rf" --task-id {ID} --dispatch-id {ID}(?: --from {HANDLE})? --subject {TXT} --body {TXT}"

PLANTILLAS = (
    ("git-log", rf"git log (?:{FMT}|--oneline)(?: -n {N})?(?: {RANGO}| {REF})?"),
    ("git-show", rf"git show {NOEXT} --stat {FMT} {REF}"),
    ("git-diff", rf"git diff {NOEXT}(?: --stat)? {RANGO}(?: -- {RUTA})?"),
    ("git-blame", rf"git blame --no-textconv -L {LIN},{LIN} {REF} -- {RUTA}"),
    ("git-rev-parse", r"git rev-parse(?: --short)? HEAD"),
    ("orca-done", r"orca orchestration send --type worker_done --outcome (?:succeeded|failed)" + DESTINO),
    ("orca-escala", r"orca orchestration send --type escalation(?: --outcome (?:succeeded|failed))?" + DESTINO),
    ("orca-check", r"orca orchestration check(?: --peek)?(?: --json)?"),
    ("orca-preambulo", rf"orca orchestration dispatch-show --task {ID} --preamble(?: --json)?"),
)
_RX = tuple((nombre, re.compile(patron)) for nombre, patron in PLANTILLAS)


def _ruta_mala(ruta: str):
    segs = ruta.split("/")
    if ruta.startswith(("/", "-")) or "" in segs:
        return f"ruta absoluta, vacía o con //: {ruta}"
    if any(s in (".", "..") for s in segs):
        return f"ruta con . o ..: {ruta}"
    if segs[0].lower() == ".tausa":
        return "el marcador .tausa no se toca desde un revisor"
    return None


def clasificar_bash(cmd, cwd=None):
    """None si `cmd` es EXACTAMENTE una plantilla de la gramática; si no, el motivo."""
    if not isinstance(cmd, str) or not cmd:
        return "comando vacío o ilegible"
    if len(cmd) > LIM:
        return f"comando de más de {LIM} caracteres"
    _, motivo = _base(cwd)
    if motivo:
        return motivo
    for _nombre, rx in _RX:
        m = rx.fullmatch(cmd)
        if m:
            ruta = m.groupdict().get("ruta")
            return _ruta_mala(ruta) if ruta is not None else None
    return ("Bash fuera de la gramática del revisor (ADR-0042 D3): copia literal "
            "una plantilla del --spec; lo demás se describe, no se ejecuta")


# v3: Read, Grep, Glob y LS con el mismo control de raíz que Bash.
CAMPOS_RUTA = {"Read": ("file_path",), "Grep": ("path",),
               "Glob": ("path", "pattern"), "LS": ("path",)}
_LLAVES_PUNTOS = re.compile(r"[{,]\s*\.\.|\.\.\s*[},]")


def _control_herramienta(herramienta: str, entrada, cwd):
    campos = CAMPOS_RUTA.get(herramienta)
    if not campos:
        return None
    if not isinstance(entrada, dict):
        return f"entrada de {herramienta} ilegible"
    base, motivo = _base(cwd)
    if motivo:
        return motivo
    for campo in campos:
        valor = entrada.get(campo)
        if valor is None:
            continue
        if not isinstance(valor, str):
            return f"{herramienta}.{campo} no es texto"
        desde = base
        if herramienta == "Glob" and campo == "pattern":
            if _LLAVES_PUNTOS.search(valor):
                return f"Glob: llaves con `..` en el patrón: {valor}"
            raiz_glob = entrada.get("path")
            if isinstance(raiz_glob, str) and raiz_glob:
                desde = _a_ruta(raiz_glob, base) or base  # `path` ya pasó el control
        motivo = _fuera(valor, desde)
        if motivo:
            return f"{herramienta}: {motivo}"
    return None


def decidir(evento: dict):
    herramienta = evento.get("tool_name", "")
    entrada = evento.get("tool_input") or {}
    if herramienta in HERRAMIENTAS_LECTURA:
        return _control_herramienta(herramienta, entrada, evento.get("cwd"))
    if herramienta == "Bash":
        return clasificar_bash(entrada.get("command"), evento.get("cwd"))
    return f"la herramienta {herramienta or '(sin nombre)'} no es de lectura"


def leer_rol() -> str:
    try:
        if not DIR_MARCADOR.exists() and not DIR_MARCADOR.is_symlink():
            return "ausente"
        if MARCADOR.is_symlink() or not MARCADOR.is_file():
            return "revisor"
        texto = MARCADOR.read_bytes()[:64].decode("utf-8-sig").strip().lower()
    except Exception:
        return "revisor"
    return "constructor" if texto == "constructor" else "revisor"


def negar(motivo: str) -> int:
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    razon = f"{PREFIJO}: {motivo}. Esta sesión es de solo lectura; reporta, no corrijas."
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": "deny",
                                             "permissionDecisionReason": razon}},
                     ensure_ascii=False))
    print(razon, file=sys.stderr)
    return 2


def main() -> int:
    rol = leer_rol()
    if rol in ("ausente", "constructor"):
        return 0
    try:
        evento = json.loads(sys.stdin.buffer.read().decode("utf-8-sig") or "{}")
        if not isinstance(evento, dict):
            return negar("evento ilegible")
        motivo = decidir(evento)
        return negar(motivo) if motivo else 0
    except Exception as exc:  # falla cerrada
        return negar(f"error interno ({exc.__class__.__name__})")


if __name__ == "__main__":
    raise SystemExit(main())
