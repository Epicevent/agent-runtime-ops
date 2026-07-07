"""Legacy (pre-managed) NAS fstab generation: inventory and line surgery.

The 2026-07-07 outage exposed a whole generation of per-slot CIFS entries
predating the managed marker: noauto, credentials declared under legacy
paths (/home/<slot>/.openclaw-nas/...), invisible to the official credential
stores — so no boot device or verdict covered them. These helpers make that
generation visible and migratable. Credential VALUES are never read here;
only paths and presence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..host.fstab import managed_fstab_marker

_SLOT_TARGET_RE = re.compile(r"^/home/(?P<slot>[A-Za-z0-9_-]+)/nas_docs/")
_CRED_OPT_RE = re.compile(r"(?:^|,)credentials=([^,]*)")


def _fstab_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


@dataclass(frozen=True)
class LegacyFstabEntry:
    slot: str
    share: str
    target: str
    credential_path: str
    noauto: bool
    line_number: int  # 0-based index into the fstab's splitlines()


def legacy_fstab_entries(fstab_text: str) -> list[LegacyFstabEntry]:
    """Non-managed cifs entries mounted under a slot's nas_docs.

    Managed pairs (marker + entry) and commented/disabled lines are excluded —
    what remains is exactly the legacy generation."""
    lines = fstab_text.splitlines()
    entries: list[LegacyFstabEntry] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 4 or fields[2] != "cifs":
            continue
        target = _fstab_unescape(fields[1])
        slot_match = _SLOT_TARGET_RE.match(target)
        if not slot_match:
            continue
        share = _fstab_unescape(fields[0])
        if index > 0 and lines[index - 1].strip() == managed_fstab_marker(slot_match.group("slot"), share):
            continue
        credential = _CRED_OPT_RE.search(fields[3])
        entries.append(
            LegacyFstabEntry(
                slot=slot_match.group("slot"),
                share=share,
                target=target,
                credential_path=_fstab_unescape(credential.group(1)) if credential else "",
                noauto="noauto" in fields[3].split(","),
                line_number=index,
            )
        )
    return entries


def remove_fstab_lines(fstab_text: str, line_numbers: set[int]) -> str:
    kept = [line for index, line in enumerate(fstab_text.splitlines()) if index not in line_numbers]
    return "\n".join(kept) + ("\n" if kept else "")
