from __future__ import annotations

import re


SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password|passwd|credential|secret(?:[_-]?[a-z0-9]+)?)=([^\s]+)"),
    re.compile(r"AIza[0-9A-Za-z_-]{20,}"),
]


def redact(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: m.group(0).split("=", 1)[0] + "=<redacted>" if "=" in m.group(0) else "<redacted>", redacted)
    return redacted
