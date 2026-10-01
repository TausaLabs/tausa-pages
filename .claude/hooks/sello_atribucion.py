#!/usr/bin/env python3
"""Sello de atribución: evidencia mínima de lo que se escribe, sin guardar contenido.

- PostToolUse Edit/Write: un registro por llamada (esquema de siempre).
- Bash y PowerShell (TEC-0176, obs. 2 del Auditor de TEC-0175; PowerShell desde
  TEC-0176/T1b: su `tool_input.command` se trata igual que el de Bash):
  - PreToolUse: foto de lo sucio del checkout (`git status`) con [tamaño, mtime_ns]
    por ruta, en `<estado>/<sesion>/_pre_<tool_use_id>.json`.
  - PostToolUse: repite la foto, la compara y escribe un registro
    `<tool_use_id>__<n>.json` por cada ruta creada, modificada, borrada o
    limpiada (sale de lo sucio y sigue existiendo: commit o checkout). Guarda el
    sha256 del comando, nunca su texto. Sin foto previa, registra todo lo sucio
    con `foto_previa: false`.
  Nunca bloquea: cualquier fallo sale con 0. No ve rutas ignoradas por git.
- Al arrancar (TEC-0176/T1b): borra solo sus propios `_pre_*.json` con más de
  1 hora dentro de `<estado>/<sesion>/` (huérfanos de un Bash que la guarda negó:
  los PreToolUse corren en paralelo y el PostToolUse nunca llega). Nada más.
  TEC-0178 M2.3: lo mismo en las carpetas de las otras sesiones de `<estado>/`
  (una sesión que terminó no vuelve a limpiar la suya), como mucho una vez por
  hora (marca `<estado>/_barrido_pre.marca`) y con un tope de tiempo. Sin
  seguir enlaces.
- Encargo y autor declarados (TEC-0178 M2.3): si nada de lo anterior los trae,
  los lee de `<raíz>/.tausa/encargo` y `<raíz>/.tausa/autor`, que escribe el
  Tech Lead en el worktree antes de lanzar la sesión (junto a `.tausa/rol`).
  Solo un archivo regular, sin enlaces, de una línea corta y con formato
  válido; si no, el sello marca `archivo-invalido` y no usa el valor. Nunca
  se infiere.
- Los `git` internos tienen timeout TIMEOUT_GIT cada uno; los dos juntos quedan
  holgados bajo el timeout 10 del hook en settings.json.
"""
import hashlib
import json
import os
import re
import stat as _stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parent.parent.parent)
HERRAMIENTAS_SHELL = {"Bash", "PowerShell"}
TIMEOUT_GIT = 3  # s por llamada; rev-parse + status = 6 s como máximo, bajo el timeout 10 del hook
PRE_HUERFANO_S = 3600  # un `_pre_` con más de 1 hora es huérfano
_PRE_PROPIO = re.compile(r"^_pre_[A-Za-z0-9_.-]+\.json$")
# TEC-0178 M2.3: barrido de las otras sesiones y declaración en `.tausa/`.
MARCA_BARRIDO = "_barrido_pre.marca"
BARRIDO_CADA_S = 3600
BARRIDO_TOPE_S = 0.5
DIR_TAUSA = ROOT / ".tausa"
MAX_DECLARACION = 128  # bytes
_ENCARGO_VALIDO = re.compile(r"^TEC-\d{4}(?:/[A-Za-z0-9][A-Za-z0-9.-]{0,15})?$")
_AUTOR_VALIDO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def safe(value: object, fallback: str) -> str:
    text = str(value or fallback)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


def declaracion(nombre: str, valido: "re.Pattern[str]"):
    """(valor, estado) de `.tausa/<nombre>`: estado es "ausente", "invalido"
    u "ok". Solo un archivo regular (sin enlaces, tampoco en `.tausa`), de
    una línea de hasta MAX_DECLARACION bytes en UTF-8 y que cumple `valido`."""
    ruta = DIR_TAUSA / nombre
    try:
        if not os.path.lexists(ruta):
            return None, "ausente"
        if _es_enlace(DIR_TAUSA) or not _stat.S_ISREG(ruta.lstat().st_mode):
            return None, "invalido"
        crudo = ruta.read_bytes()
        if len(crudo) > MAX_DECLARACION:
            return None, "invalido"
        valor = crudo.decode("utf-8").lstrip("\ufeff").strip()
    except (OSError, UnicodeDecodeError):
        return None, "invalido"
    return (valor, "ok") if valido.fullmatch(valor) else (None, "invalido")


def atribucion(event: dict) -> tuple[str, str, str | None, str]:
    """Obtiene identidad y encargo explícitamente declarado.

    El contrato PostToolUse de Claude entrega sesión/agente, pero no encargo.
    Por eso nunca se infiere un TEC desde el transcript ni se usa un valor que
    parezca una referencia: un sello sin encargo queda marcado como incompleto.
    Orden: evento, tool_input, entorno y, al final, `.tausa/` (TEC-0178 M2.3).
    """
    entrada = event.get("tool_input") or {}
    autor_evento = (event.get("autor") or event.get("author") or event.get("actor")
                    or event.get("agent_id"))
    if autor_evento:
        autor, fuente_autor = autor_evento, "evento"
    elif os.environ.get("TAUSA_AUTOR"):
        autor, fuente_autor = os.environ["TAUSA_AUTOR"], "entorno"
    else:
        valor, estado = declaracion("autor", _AUTOR_VALIDO)
        if valor:
            autor, fuente_autor = valor, "archivo"
        elif event.get("agent_type"):
            autor = event["agent_type"]
            fuente_autor = "archivo-invalido" if estado == "invalido" else "agent_type"
        else:
            autor = "autor-no-declarado"
            fuente_autor = "archivo-invalido" if estado == "invalido" else "no-declarado"
    encargo = (
        event.get("encargo")
        or event.get("id_encargo")
        or entrada.get("encargo")
        or entrada.get("id_encargo")
        or os.environ.get("TAUSA_ENCARGO")
        or os.environ.get("TAUSA_ID_ENCARGO")
    )
    fuente = (
        "evento" if event.get("encargo") or event.get("id_encargo")
        else "tool_input" if entrada.get("encargo") or entrada.get("id_encargo")
        else "entorno" if os.environ.get("TAUSA_ENCARGO") or os.environ.get("TAUSA_ID_ENCARGO")
        else "no-declarado"
    )
    if not encargo:
        valor, estado = declaracion("encargo", _ENCARGO_VALIDO)
        if valor:
            encargo, fuente = valor, "archivo"
        elif estado == "invalido":
            fuente = "archivo-invalido"
    return str(autor), fuente_autor, str(encargo) if encargo else None, fuente


def escribir_json(target: Path, datos: dict) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(datos, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    os.replace(temp, target)


def registro_base(event: dict, tool: str) -> dict:
    autor, fuente_autor, encargo, fuente_encargo = atribucion(event)
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "runtime": "claude-code",
        "autor": autor,
        "fuente_autor": fuente_autor,
        "encargo": encargo,
        "encargo_declarado": encargo is not None,
        "fuente_encargo": fuente_encargo,
        "session_id": event.get("session_id"),
        "agent_id": event.get("agent_id"),
        "agent_type": event.get("agent_type") or "claude-code-main",
        "tool_name": tool,
        "tool_use_id": event.get("tool_use_id"),
    }


def foto_git(state: Path):
    """{ruta_relativa: {"xy": código de status, "stat": [tamaño, mtime_ns] | None}}
    de lo sucio del checkout, o (None, None) si ROOT no es un repo git."""
    def git(*args):
        return subprocess.run(["git", "--no-optional-locks", "-C", str(ROOT), *args],
                              capture_output=True, timeout=TIMEOUT_GIT, check=False)
    top = git("rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return None, None
    raiz = Path(top.stdout.decode("utf-8", "replace").strip())
    r = git("status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames")
    if r.returncode != 0:
        return None, None
    try:
        estado_rel = state.resolve().relative_to(raiz.resolve()).as_posix() + "/"
    except (ValueError, OSError):
        estado_rel = None
    foto = {}
    for entrada in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if len(entrada) < 4:
            continue
        xy, ruta = entrada[:2], entrada[3:]
        if estado_rel and (ruta + "/").startswith(estado_rel):
            continue  # los propios registros del sello
        try:
            st = (raiz / ruta).stat()
            stat = [st.st_size, st.st_mtime_ns]
        except OSError:
            stat = None
        foto[ruta] = {"xy": xy, "stat": stat}
    return raiz, foto


def _es_enlace(ruta: Path) -> bool:
    """Symlink o unión de Windows (punto de reanálisis): no se sigue (M2.3)."""
    try:
        st = ruta.lstat()
    except OSError:
        return False
    return _stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def limpiar_pre_huerfanos(dir_sesion: Path) -> int:
    """Borra solo los `_pre_*.json` (archivos regulares, no enlaces) con más de
    PRE_HUERFANO_S segundos dentro de `dir_sesion`. Devuelve cuántos borró."""
    if _es_enlace(dir_sesion) or not dir_sesion.is_dir():
        return 0
    ahora, borrados = time.time(), 0
    for ruta in dir_sesion.iterdir():
        if not _PRE_PROPIO.match(ruta.name):
            continue
        try:
            st = ruta.lstat()
            if _stat.S_ISREG(st.st_mode) and ahora - st.st_mtime > PRE_HUERFANO_S:
                ruta.unlink()
                borrados += 1
        except OSError:
            continue
    return borrados


def barrer_otras_sesiones(state: Path, session: str) -> int:
    """TEC-0178 M2.3: `limpiar_pre_huerfanos` en las otras carpetas de sesión
    de `state` (no enlaces), como mucho una vez cada BARRIDO_CADA_S según la
    marca y hasta BARRIDO_TOPE_S segundos. Devuelve cuántos borró."""
    if _es_enlace(state) or not state.is_dir():
        return 0
    marca = state / MARCA_BARRIDO
    try:
        st = marca.lstat()
        if not _stat.S_ISREG(st.st_mode) or time.time() - st.st_mtime < BARRIDO_CADA_S:
            return 0
    except FileNotFoundError:
        pass
    marca.write_text("", encoding="utf-8")  # la marca va antes: un fallo no repite el barrido
    inicio, borrados = time.monotonic(), 0
    for dir_sesion in state.iterdir():
        if time.monotonic() - inicio > BARRIDO_TOPE_S:
            break
        if dir_sesion.name == session:
            continue
        try:
            borrados += limpiar_pre_huerfanos(dir_sesion)
        except OSError:
            continue
    return borrados


def sello_bash(event: dict, state: Path, session: str, action: str, tool: str = "Bash") -> int:
    pre = state / session / f"_pre_{action}.json"
    raiz, foto = foto_git(state)
    if foto is None:
        return 0
    if event.get("hook_event_name") == "PreToolUse":
        escribir_json(pre, {"raiz": str(raiz), "foto": foto})
        return 0
    previa = None
    if pre.exists():
        try:
            previa = json.loads(pre.read_text(encoding="utf-8")).get("foto")
        except (OSError, ValueError, AttributeError):
            previa = None
    cambios = []
    if previa is None:
        for ruta, datos in sorted(foto.items()):
            cambio = ("creado" if datos["xy"] == "??" else
                      "borrado" if datos["stat"] is None else "modificado")
            cambios.append((ruta, cambio))
    else:
        for ruta, datos in sorted(foto.items()):
            antes = previa.get(ruta)
            if antes is not None and antes.get("stat") == datos["stat"]:
                continue
            if datos["stat"] is None:
                cambio = "borrado"
            elif antes is None and datos["xy"] == "??":
                cambio = "creado"
            else:
                cambio = "modificado"
            cambios.append((ruta, cambio))
        for ruta in sorted(set(previa) - set(foto)):
            cambios.append((ruta, "limpiado" if (raiz / ruta).exists() else "borrado"))
    comando = str((event.get("tool_input") or {}).get("command", ""))
    comando_sha = hashlib.sha256(comando.encode("utf-8", "surrogatepass")).hexdigest()
    for n, (ruta, cambio) in enumerate(cambios, start=1):
        record = registro_base(event, tool)
        record.update({
            "file_path": str(raiz / ruta),
            "cambio": cambio,
            "comando_sha256": comando_sha,
            "foto_previa": previa is not None,
        })
        escribir_json(state / session / f"{action}__{n}.json", record)
    pre.unlink(missing_ok=True)
    return 0


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    if not isinstance(event, dict):
        return 0
    tool = event.get("tool_name")
    state = Path(os.environ.get("TAUSA_HOOK_STATE_DIR", ROOT / ".tmp" / "auditoria"))
    session = safe(event.get("session_id"), "sin-sesion")
    action = safe(event.get("tool_use_id"), "sin-tool-use")
    try:
        limpiar_pre_huerfanos(state / session)
    except Exception:  # el sello nunca bloquea
        pass
    try:
        barrer_otras_sesiones(state, session)
    except Exception:  # el sello nunca bloquea
        pass
    if tool in HERRAMIENTAS_SHELL:
        try:
            return sello_bash(event, state, session, action, tool)
        except Exception:  # el sello nunca bloquea
            return 0
    if tool not in {"Edit", "Write"} or event.get("hook_event_name") == "PreToolUse":
        return 0
    record = registro_base(event, tool)
    record["file_path"] = (event.get("tool_input") or {}).get("file_path")
    escribir_json(state / session / f"{action}.json", record)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
