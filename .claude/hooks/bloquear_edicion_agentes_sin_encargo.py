#!/usr/bin/env python3
"""PreToolUse: impide editar agentes TOML sin un encargo TEC activo."""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parent.parent.parent)
ACTIVE = ROOT / "Obsidian" / "Tausa_Labs_Corp" / "02_Encargos" / "Activos"
TEC = re.compile(r"^TEC-\d{4}$")


def deny(reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}, ensure_ascii=False))


def active_encargo(value: str | None) -> bool:
    if not isinstance(value, str) or not TEC.fullmatch(value):
        return False
    try:
        return any(p.is_file() for p in ACTIVE.glob(value + " *.md"))
    except OSError:
        return False


def governed(path_value: object) -> bool:
    if not isinstance(path_value, str):
        return False
    try:
        path = Path(path_value)
        if not path.is_absolute():
            path = ROOT / path
        path = path.resolve()
        base = (ROOT / "execution" / "agentes").resolve()
        return path.parent == base and path.suffix.lower() == ".toml"
    except (OSError, ValueError):
        return False


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, TypeError):
        return 0
    if event.get("tool_name") not in {"Edit", "Write"}:
        return 0
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict) or not governed(tool_input.get("file_path")):
        return 0
    value = os.environ.get("TAUSA_ENCARGO") or os.environ.get("TAUSA_ID_ENCARGO")
    if not active_encargo(value):
        deny("Edición bloqueada: execution/agentes/*.toml exige TAUSA_ENCARGO válido y activo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
