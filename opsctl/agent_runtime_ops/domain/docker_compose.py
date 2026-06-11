from __future__ import annotations

from pathlib import Path
import re


def compose_project_name(slot: str) -> str:
    return f"openclaw-{slot}"


def docker_compose_command(slot: str, compose_path: Path, *args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        compose_project_name(slot),
        "-f",
        str(compose_path),
        *args,
    ]


def required_compose_variables(rendered_text: str) -> set[str]:
    return set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", rendered_text))


def env_file_keys(path: Path) -> set[str]:
    from .runtime_paths import safe_managed_file

    safe_managed_file(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    keys: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            keys.add(key)
    return keys
