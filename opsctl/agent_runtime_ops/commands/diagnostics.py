from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from ..domain.common import is_root as _is_root
from ..domain.common import run_text
from ..domain.common import state_root as _state_root
from ..domain.runtime_paths import agent_backup_root
from ..domain.runtime_truth import find_gateway_container_by_binding
from ..redaction import redact
from ..routing import get_runtime_binding, validate_linux_account
from ..yamlio import load_yaml

# Relative age accepted by `docker logs --since`, e.g. 10m, 2h, 1d. Kept strict so
# an operator typo fails cleanly here instead of surfacing a raw docker error.
_SINCE_RE = re.compile(r"^\d+[smhd]$")

# Log signatures of the embedded-agent session-save concurrency wedge
# (openclaw-jitech#35): concurrent lanes / auto-compaction rewrite a session
# `.jsonl` under an in-flight run, then the error path reopens it O_EXCL and
# every prompt fails before reply. These strings, plus a zero-byte session
# tombstone, are the observable symptoms an ops probe can catch — a synthetic
# round-trip cannot, because a single-writer probe session never reproduces the
# concurrent-writer trigger.
_SESSION_WEDGE_SIGNATURES = (
    "EmbeddedAttemptSessionTakeoverError",
    "failed to persist prompt error entry",
    "failed before reply",
    "EEXIST",
)

# Session transcripts live at <root>/<agent>/sessions/*.jsonl inside the
# container. The bug leaves zero-byte tombstones here; a healthy in-use session
# is non-empty.
_CONTAINER_SESSIONS_ROOT = "/home/node/.openclaw/agents"


def _is_under_path(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_diagnostics_dir(
    state_root: Path,
    slot: str,
    value: str | None = None,
) -> Path:
    backup_root = agent_backup_root(state_root, slot).resolve(strict=False)
    if value:
        requested = Path(value)
        if not requested.is_absolute():
            raise ValueError("diagnostics path must be absolute")
        path = requested.resolve(strict=False)
        if path.name != "failed-container":
            path = path / "failed-container"
    else:
        if not backup_root.is_dir():
            raise ValueError(f"backup root not found: {backup_root}")
        backups = sorted(item for item in backup_root.iterdir() if item.is_dir())
        if not backups:
            raise ValueError(f"no backups found for target: {slot}")
        path = backups[-1].resolve(strict=False) / "failed-container"
    path = path.resolve(strict=False)
    if not _is_under_path(path, backup_root):
        raise ValueError("diagnostics path must stay under the target backup root")
    if path.is_symlink():
        raise ValueError(f"diagnostics path must not be symlink: {path}")
    if not path.is_dir():
        raise ValueError(f"diagnostics dir not found: {path}")
    return path


def _load_diagnostics_payload(path: Path) -> dict:
    data = load_yaml(path)
    return data if isinstance(data, dict) else {}


def _format_command_list(value) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    if value in {None, ""}:
        return "empty"
    return str(value)


def _redacted_tail(text: str, *, lines: int, chars: int = 12000) -> str:
    redacted = redact(text or "")
    parts = redacted.splitlines()
    if lines > 0:
        redacted = "\n".join(parts[-lines:])
    return redacted[-chars:]


def _print_block(name: str, text: str) -> None:
    print(f"{name}_begin")
    if text:
        print(text)
    print(f"{name}_end")


def _print_inspect_summary(diag_dir: Path) -> None:
    path = diag_dir / "inspect.json"
    if not path.is_file():
        print("inspect_status=missing")
        return
    payload = _load_diagnostics_payload(path)
    print(f"inspect_returncode={payload.get('returncode')}")
    if payload.get("returncode") != 0:
        stderr = _redacted_tail(str(payload.get("stderr") or payload.get("stdout") or ""), lines=20)
        _print_block("inspect_error", stderr)
        return
    try:
        rows = json.loads(str(payload.get("stdout") or "[]"))
        info = rows[0] if isinstance(rows, list) and rows else {}
    except Exception as exc:
        print(f"inspect_parse_status=fail reason={exc}")
        return
    state = info.get("State") if isinstance(info, dict) else {}
    config = info.get("Config") if isinstance(info, dict) else {}
    health = state.get("Health") if isinstance(state, dict) else {}
    print("inspect_status=ok")
    print(f"container_id={str(info.get('Id') or '')[:12]}")
    print(f"container_name={info.get('Name') or ''}")
    print(f"container_image={config.get('Image') or ''}")
    print(f"container_running={state.get('Running')}")
    print(f"container_pid={state.get('Pid')}")
    print(f"container_exit_code={state.get('ExitCode')}")
    print(f"container_health={(health or {}).get('Status') if isinstance(health, dict) else 'none'}")
    print(f"container_entrypoint={_format_command_list(config.get('Entrypoint'))}")
    print(f"container_cmd={_format_command_list(config.get('Cmd'))}")
    print(f"container_working_dir={config.get('WorkingDir') or ''}")


def cmd_diagnostics_logs(args: argparse.Namespace) -> int:
    """On-demand tail of a live gateway container's logs.

    `diagnostics show` only reads snapshots captured during a failed/rolled-back
    apply, so a container that stays up while only its model calls fail (see
    agent-runtime-ops#16) has nothing to show. This tails the running container
    directly, redacting secrets, so an operator can see provider errors without a
    prior failure snapshot.
    """
    if not _is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl diagnostics logs TARGET",
            file=sys.stderr,
        )
        return 2
    try:
        slot = str(args.slot)
        validate_linux_account(slot)
        tail_lines = max(1, min(int(getattr(args, "tail", 200)), 2000))
        since = getattr(args, "since", None) or None
        if since is not None:
            since = str(since)
            if not _SINCE_RE.match(since):
                raise ValueError("--since must be a relative age like 10m, 2h, 1d")
        binding = get_runtime_binding(slot, _state_root(args))
    except Exception as exc:
        print("diagnostics_logs_status=fail")
        print(f"reason={exc}")
        return 1

    container, lookup = find_gateway_container_by_binding(binding)
    if not container:
        print("diagnostics_logs_status=fail")
        print(f"target={slot}")
        print(f"reason=container_not_found lookup={lookup}")
        return 1

    command = ["docker", "logs", "--tail", str(tail_lines)]
    if since:
        command += ["--since", since]
    command.append(container)
    result = run_text(command, timeout=30)

    print("diagnostics_logs_status=ok")
    print(f"target={slot}")
    print(f"container={container[:12]}")
    print(f"lookup={lookup}")
    print("secret_value_printed=no")
    print(f"logs_returncode={result.returncode}")
    text = "\n".join(part for part in (result.stdout or "", result.stderr or "") if part)
    _print_block("logs_tail", _redacted_tail(text, lines=tail_lines, chars=60000))
    return 0


def cmd_diagnostics_session_health(args: argparse.Namespace) -> int:
    """Detect the embedded-agent session-save wedge (openclaw-jitech#35) on a slot.

    Read-only symptom detector: counts zero-byte session tombstones inside the
    running container and scans recent logs for the wedge signatures. Catches an
    outage that leaves gateway/model/`check --live` all green while every customer
    prompt fails before reply. No synthetic prompt, no paid model call, no
    customer-session mutation.
    """
    if not _is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl diagnostics session-health TARGET",
            file=sys.stderr,
        )
        return 2
    try:
        slot = str(args.slot)
        validate_linux_account(slot)
        since = str(getattr(args, "since", None) or "6h")
        if not _SINCE_RE.match(since):
            raise ValueError("--since must be a relative age like 10m, 2h, 1d")
        binding = get_runtime_binding(slot, _state_root(args))
    except Exception as exc:
        print("session_health_status=fail")
        print(f"reason={exc}")
        return 1

    container, lookup = find_gateway_container_by_binding(binding)
    if not container:
        print("session_health_status=fail")
        print(f"target={slot}")
        print(f"reason=container_not_found lookup={lookup}")
        return 1

    # 1) Zero-byte session tombstones (the "history disappeared" symptom).
    find_script = (
        f"find {_CONTAINER_SESSIONS_ROOT} "
        "-path '*/sessions/*.jsonl' -type f -printf '%s\\t%p\\n' 2>/dev/null"
    )
    exec_result = run_text(["docker", "exec", container, "sh", "-c", find_script], timeout=30)
    exec_ok = exec_result.returncode == 0
    total_sessions = 0
    tombstones: list[str] = []
    if exec_ok:
        for line in exec_result.stdout.splitlines():
            if "\t" not in line:
                continue
            size_str, path = line.split("\t", 1)
            try:
                size = int(size_str)
            except ValueError:
                continue
            total_sessions += 1
            if size == 0:
                tombstones.append(path.rsplit("/", 1)[-1])

    # 2) Wedge log signatures within the window.
    logs_result = run_text(["docker", "logs", "--since", since, container], timeout=30)
    log_text = "\n".join(part for part in (logs_result.stdout or "", logs_result.stderr or "") if part)
    signature_hits = {sig: log_text.count(sig) for sig in _SESSION_WEDGE_SIGNATURES}
    total_hits = sum(signature_hits.values())

    degraded = bool(tombstones) or total_hits > 0
    print(f"session_health_status={'degraded' if degraded else 'ok'}")
    print(f"target={slot}")
    print(f"container={container[:12]}")
    print(f"lookup={lookup}")
    print(f"session_scan_ok={'yes' if exec_ok else 'no'}")
    print(f"session_total={total_sessions}")
    print(f"zero_byte_tombstones={len(tombstones)}")
    for name in tombstones[:20]:
        print(f"tombstone={name}")
    print(f"log_window={since}")
    for sig in _SESSION_WEDGE_SIGNATURES:
        print(f"log_signature[{sig}]={signature_hits[sig]}")
    print(f"log_signature_total={total_hits}")
    return 0


def cmd_diagnostics_show(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl diagnostics show TARGET", file=sys.stderr)
        return 2
    try:
        slot = str(args.slot)
        validate_linux_account(slot)
        diag_dir = _resolve_diagnostics_dir(
            _state_root(args),
            slot,
            getattr(args, "dir", None),
        )
        tail_lines = max(1, min(int(getattr(args, "tail", 120)), 300))
    except Exception as exc:
        print("diagnostics_status=fail")
        print(f"reason={exc}")
        return 1

    print("diagnostics_status=ok")
    print(f"target={slot}")
    print(f"diagnostics_dir={diag_dir}")
    print("secret_value_printed=no")
    lookup_path = diag_dir / "lookup.txt"
    if lookup_path.is_file():
        print(redact(lookup_path.read_text(encoding="utf-8", errors="replace").strip()))
    _print_inspect_summary(diag_dir)
    for stem in ("ports", "top", "logs"):
        path = diag_dir / f"{stem}.txt"
        if not path.is_file():
            print(f"{stem}_status=missing")
            continue
        payload = _load_diagnostics_payload(path)
        print(f"{stem}_returncode={payload.get('returncode')}")
        text = "\n".join(part for part in (str(payload.get("stdout") or ""), str(payload.get("stderr") or "")) if part)
        _print_block(f"{stem}_tail", _redacted_tail(text, lines=tail_lines))
    return 0
