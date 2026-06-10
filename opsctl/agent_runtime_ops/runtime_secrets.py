from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from .yamlio import load_yaml


PROVIDER_SECRET_KEYS = {
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "ELEVENLABS_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "PERPLEXITY_API_KEY",
    "TOGETHER_API_KEY",
    "XAI_API_KEY",
}

INTERNAL_RUNTIME_SECRET_KEYS = {
    "API_SERVER_KEY",
}

RUNTIME_SECRET_KEYS = PROVIDER_SECRET_KEYS | INTERNAL_RUNTIME_SECRET_KEYS

SECRET_ENV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")


@dataclass(frozen=True)
class RuntimeSecretFile:
    path: Path
    owner_mode: str


def parse_secret_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        try:
            parts = shlex.split(value, posix=True)
            return parts[0] if parts else ""
        except ValueError:
            return value.strip("'\"")
    return value


def parse_secret_env_text(text: str, *, source: str = "<env>") -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.lstrip("\ufeff")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = SECRET_ENV_RE.match(line)
        if not match:
            raise ValueError(f"unsupported env syntax in {source}:{line_number}")
        key, raw_value = match.group(1), match.group(2)
        values[key] = parse_secret_value(raw_value)
    return values


def validate_provider_secret_values(values: dict[str, str]) -> dict[str, str]:
    return validate_runtime_secret_values(values)


def validate_runtime_secret_values(values: dict[str, str]) -> dict[str, str]:
    unknown = sorted(set(values) - RUNTIME_SECRET_KEYS)
    if unknown:
        raise ValueError("unsupported runtime secret key(s): " + ",".join(unknown))
    supported = {key: value for key, value in values.items() if value}
    if not supported:
        raise ValueError("no supported runtime secret keys found")
    return supported


def quote_secret_env_value(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def render_upserted_secret_env(existing_text: str, values: dict[str, str]) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for raw_line in existing_text.splitlines():
        match = SECRET_ENV_RE.match(raw_line)
        if not match:
            out.append(raw_line)
            continue
        key = match.group(1)
        if key in values:
            out.append(f"{key}={quote_secret_env_value(values[key])}")
            seen.add(key)
        else:
            out.append(raw_line)
    for key in sorted(values):
        if key not in seen:
            out.append(f"{key}={quote_secret_env_value(values[key])}")
    return "\n".join(out) + "\n"


def profile_secret_files(profile, slot: str) -> list[RuntimeSecretFile]:
    contract = load_yaml(profile.path / "env.contract.yaml")
    raw_files = contract.get("secret_files") or []
    files: list[RuntimeSecretFile] = []
    for item in raw_files:
        if not isinstance(item, str):
            continue
        path = Path(item.format(slot=slot))
        owner_mode = "runtime" if f"/home/{slot}/.hermes/" in path.as_posix() else "root"
        files.append(RuntimeSecretFile(path=path, owner_mode=owner_mode))
    return files


def primary_profile_secret_file(profile, slot: str) -> RuntimeSecretFile:
    files = profile_secret_files(profile, slot)
    if not files:
        raise ValueError(f"profile has no secret_files contract: {profile.name}")
    return files[0]
