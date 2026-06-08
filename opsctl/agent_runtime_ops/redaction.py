from __future__ import annotations

import re


SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|password|passwd|credential|secret(?:[_-]?[a-z0-9]+)?)=([^\s]+)"
)
GOOGLE_API_KEY_RE = re.compile(r"AIza[0-9A-Za-z_-]{20,}")
SAFE_STATUS_VALUES = {
    "absent",
    "fail",
    "false",
    "missing",
    "no",
    "none",
    "ok",
    "present",
    "stored",
    "true",
    "yes",
}


def _redact_assignment(match: re.Match[str]) -> str:
    key = match.group(1)
    value = match.group(2)
    normalized = value.strip("'\"").lower()
    if normalized in SAFE_STATUS_VALUES:
        return match.group(0)
    return f"{key}=<redacted>"


def redact(text: str) -> str:
    redacted = SECRET_ASSIGNMENT_RE.sub(_redact_assignment, text)
    return GOOGLE_API_KEY_RE.sub("<redacted>", redacted)
