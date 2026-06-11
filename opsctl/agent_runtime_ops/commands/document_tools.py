from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import sys
import os

from ..apache import parse_apache_route
from ..domain.common import is_root as _is_root
from ..domain.common import run_text as _run_text
from ..domain.common import state_root as _state_root
from ..domain.image_specs import recipe_label
from ..domain.runtime_truth import _find_gateway_container_by_binding, _labels_from_container_info
from ..routing import get_runtime_binding, load_runtime_bindings


_DOCUMENT_TOOLS_PROBE_SCRIPT = r"""
check_cmd() {
  name="$1"
  key="$2"
  path="$(command -v "$name" 2>/dev/null || true)"
  if [ -n "$path" ]; then
    echo "cmd_${key}=yes"
    echo "cmd_${key}_path=$path"
  else
    echo "cmd_${key}=no"
    echo "cmd_${key}_path="
  fi
}
for item in \
  "file:file" "rg:rg" "jq:jq" "yq:yq" "7z:7z" "7zz:7zz" \
  "libreoffice:libreoffice" "soffice:soffice" "pandoc:pandoc" \
  "pdftotext:pdftotext" "pdfinfo:pdfinfo" "tesseract:tesseract" "ocrmypdf:ocrmypdf" \
  "xlsx2csv:xlsx2csv" "in2csv:in2csv" "ssconvert:ssconvert" "antiword:antiword" "catdoc:catdoc" \
  "python3:python3" "node:node" "npm:npm" "clawhub:clawhub" \
  "hwp5txt:hwp5txt" "hwp5proc:hwp5proc" \
  "openclaw-hwp-text:openclaw_hwp_text" "openclaw-document-tools:openclaw_document_tools" \
  "read-hwp:read_hwp" "hwp-read:hwp_read" "hwp2txt:hwp2txt"; do
  check_cmd "${item%%:*}" "${item#*:}"
done

if locale charmap 2>/dev/null | grep -qi UTF-8; then
  echo "locale_utf8=yes"
else
  echo "locale_utf8=no"
fi
if locale -a 2>/dev/null | grep -Eiq "^ko_KR(\.utf8|\.UTF-8)?$"; then
  echo "locale_ko_kr=yes"
else
  echo "locale_ko_kr=no"
fi
if command -v fc-list >/dev/null 2>&1 && [ "$(fc-list :lang=ko 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ]; then
  echo "korean_fonts=yes"
else
  echo "korean_fonts=no"
fi
if command -v tesseract >/dev/null 2>&1 && tesseract --list-langs 2>/dev/null | grep -qx kor; then
  echo "tesseract_kor=yes"
else
  echo "tesseract_kor=no"
fi
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
mods = ["docx", "pandas", "openpyxl", "pptx", "lxml", "bs4", "pypdf", "pdfplumber", "fitz", "olefile"]
missing = []
for mod in mods:
    try:
        __import__(mod)
        print(f"python_{mod}=yes")
    except Exception:
        print(f"python_{mod}=no")
        missing.append(mod)
print("python_document_modules=" + ("yes" if not missing else "no"))
print("python_document_modules_missing=" + (",".join(missing) if missing else "none"))
PY
else
  for mod in docx pandas openpyxl pptx lxml bs4 pypdf pdfplumber fitz olefile; do
    echo "python_${mod}=no"
  done
  echo "python_document_modules=no"
  echo "python_document_modules_missing=python3"
fi

if [ -f /workspace/AGENTS.md ] && grep -q openclaw-hwp-text /workspace/AGENTS.md 2>/dev/null && grep -q /workspace/nas_docs /workspace/AGENTS.md 2>/dev/null; then
  echo "hermes_agents_guidance=yes"
else
  echo "hermes_agents_guidance=no"
fi
if [ -f /workspace/CLAUDE.md ] && grep -q openclaw-hwp-text /workspace/CLAUDE.md 2>/dev/null && grep -q /workspace/nas_docs /workspace/CLAUDE.md 2>/dev/null; then
  echo "hermes_claude_guidance=yes"
else
  echo "hermes_claude_guidance=no"
fi
if [ -f /workspace/GEMINI.md ] && grep -q openclaw-hwp-text /workspace/GEMINI.md 2>/dev/null && grep -q /workspace/nas_docs /workspace/GEMINI.md 2>/dev/null; then
  echo "hermes_gemini_guidance=yes"
else
  echo "hermes_gemini_guidance=no"
fi
if [ -f /home/node/.openclaw/workspace/AGENTS.md ] && grep -q openclaw-hwp-text /home/node/.openclaw/workspace/AGENTS.md 2>/dev/null && grep -q /home/node/nas_docs /home/node/.openclaw/workspace/AGENTS.md 2>/dev/null; then
  echo "openclaw_agents_guidance=yes"
else
  echo "openclaw_agents_guidance=no"
fi
if [ -f /home/node/.openclaw/workspace/CLAUDE.md ] && grep -q openclaw-hwp-text /home/node/.openclaw/workspace/CLAUDE.md 2>/dev/null && grep -q /home/node/nas_docs /home/node/.openclaw/workspace/CLAUDE.md 2>/dev/null; then
  echo "openclaw_claude_guidance=yes"
else
  echo "openclaw_claude_guidance=no"
fi
if [ -f /home/node/.openclaw/workspace/GEMINI.md ] && grep -q openclaw-hwp-text /home/node/.openclaw/workspace/GEMINI.md 2>/dev/null && grep -q /home/node/nas_docs /home/node/.openclaw/workspace/GEMINI.md 2>/dev/null; then
  echo "openclaw_gemini_guidance=yes"
else
  echo "openclaw_gemini_guidance=no"
fi
"""


def _parse_probe_key_values(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in text.splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        key = key.strip()
        if re.match(r"^[A-Za-z0-9_.-]+$", key):
            data[key] = value.strip()
    return data


def _document_tool_payload_status(data: dict[str, str]) -> str:
    required = ["openclaw_hwp_text", "openclaw_document_tools", "read_hwp", "hwp_read", "hwp2txt"]
    present = [key for key in required if data.get(f"cmd_{key}") == "yes"]
    if len(present) == len(required):
        return "baseline"
    if present:
        return "partial"
    return "missing"


def _hwp_readiness(data: dict[str, str]) -> str:
    helper = data.get("cmd_openclaw_hwp_text") == "yes"
    aliases = all(data.get(f"cmd_{key}") == "yes" for key in ["read_hwp", "hwp_read", "hwp2txt"])
    hwp5 = data.get("cmd_hwp5txt") == "yes" and data.get("cmd_hwp5proc") == "yes"
    fallback = data.get("python_olefile") == "yes" and (
        data.get("cmd_libreoffice") == "yes" or data.get("cmd_soffice") == "yes"
    )
    if helper and aliases and hwp5 and fallback:
        return "full"
    if helper and (hwp5 or fallback):
        return "partial"
    if helper:
        return "weak"
    return "none"


def _workspace_guidance_status(family: str, data: dict[str, str]) -> str:
    if family == "hermes":
        keys = ["hermes_agents_guidance", "hermes_claude_guidance", "hermes_gemini_guidance"]
    elif family == "openclaw":
        keys = ["openclaw_agents_guidance", "openclaw_claude_guidance", "openclaw_gemini_guidance"]
    else:
        return "unknown"
    return "present" if all(data.get(key) == "yes" for key in keys) else "missing"


_DOCUMENT_TOOL_REQUIRED_COMMAND_KEYS = [
    "file",
    "rg",
    "jq",
    "yq",
    "7z",
    "7zz",
    "libreoffice",
    "soffice",
    "pandoc",
    "pdftotext",
    "pdfinfo",
    "tesseract",
    "ocrmypdf",
    "xlsx2csv",
    "in2csv",
    "ssconvert",
    "antiword",
    "catdoc",
    "python3",
    "node",
    "npm",
    "clawhub",
    "hwp5txt",
    "hwp5proc",
    "openclaw_hwp_text",
    "openclaw_document_tools",
    "read_hwp",
    "hwp_read",
    "hwp2txt",
]


def _document_tools_failure_reasons(result: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    if result.get("probe_status") != "ok":
        reasons.append(f"probe_status={result.get('probe_status', '')}")
        if result.get("reason"):
            reasons.append(f"reason={result.get('reason')}")
        return reasons
    missing_commands = [key for key in _DOCUMENT_TOOL_REQUIRED_COMMAND_KEYS if result.get(f"cmd_{key}") != "yes"]
    if missing_commands:
        reasons.append("missing_commands=" + ",".join(missing_commands))
    for key in ["locale_utf8", "locale_ko_kr", "korean_fonts", "tesseract_kor", "python_document_modules"]:
        if result.get(key) != "yes":
            reasons.append(f"{key}={result.get(key, '')}")
    if result.get("document_tool_payload") != "baseline":
        reasons.append(f"document_tool_payload={result.get('document_tool_payload', '')}")
    if result.get("hwp_readiness") != "full":
        reasons.append(f"hwp_readiness={result.get('hwp_readiness', '')}")
    if result.get("workspace_guidance_status") != "present":
        reasons.append(f"workspace_guidance_status={result.get('workspace_guidance_status', '')}")
    return reasons


def _document_tools_status_for_slot(slot: str, state_root: Path) -> dict[str, str]:
    binding = get_runtime_binding(slot, state_root)
    apache_route = parse_apache_route(binding.linux_account)
    container, lookup = _find_gateway_container_by_binding(binding)
    result: dict[str, str] = {
        "target": binding.linux_account,
        "family": binding.family,
        "runtime_class": binding.runtime_class,
        "public_host": binding.public_host,
        "apache_gateway_port": str(apache_route.gateway_port),
        "container_lookup": lookup or "",
        "probe_status": "not_running",
    }
    if not container:
        result["reason"] = lookup or "container_not_found"
        return result

    docker = shutil.which("docker")
    if not docker:
        result["probe_status"] = "fail"
        result["reason"] = "docker_missing"
        return result
    nsenter = shutil.which("nsenter")
    if not nsenter:
        result["probe_status"] = "fail"
        result["reason"] = "nsenter_missing"
        return result

    inspect = _run_text(["docker", "inspect", container])
    if inspect.returncode != 0:
        result["probe_status"] = "fail"
        result["reason"] = (inspect.stderr or inspect.stdout).strip()[:160] or "docker_inspect_failed"
        return result
    try:
        info = json.loads(inspect.stdout)[0]
    except Exception as exc:
        result["probe_status"] = "fail"
        result["reason"] = f"docker_inspect_parse_failed:{exc}"
        return result

    state = info.get("State") or {}
    config = info.get("Config") or {}
    labels = _labels_from_container_info(info)
    pid = int(state.get("Pid") or 0)
    running = str(state.get("Running")).lower() == "true"
    result.update(
        {
            "container": container,
            "container_running": "yes" if running else "no",
            "runtime_profile": recipe_label(labels, f"runtime-profile.{binding.runtime_class}"),
            "canonical_recipe_name": recipe_label(labels, "recipe.name"),
            "product_component": recipe_label(labels, "product-component"),
            "wrapper_component": recipe_label(labels, "wrapper-component"),
            "image": str(config.get("Image") or ""),
        }
    )
    if not running or pid <= 0:
        result["probe_status"] = "not_running"
        result["reason"] = f"pid={pid}"
        return result

    proc = _run_text(
        [nsenter, "-t", str(pid), "-m", "-u", "-i", "-n", "-p", "--", "/bin/sh", "-lc", _DOCUMENT_TOOLS_PROBE_SCRIPT],
        timeout=30,
    )
    if proc.returncode != 0:
        result["probe_status"] = "fail"
        result["reason"] = (proc.stderr or proc.stdout).strip()[:160] or f"probe_returncode={proc.returncode}"
        return result
    probe = _parse_probe_key_values(proc.stdout)
    result.update(probe)
    result["document_tool_payload"] = _document_tool_payload_status(probe)
    result["hwp_readiness"] = _hwp_readiness(probe)
    result["workspace_guidance_status"] = _workspace_guidance_status(binding.family, probe)
    result["probe_status"] = "ok"
    failure_reasons = _document_tools_failure_reasons(result)
    result["document_tools_ready"] = "no" if failure_reasons else "yes"
    if failure_reasons:
        result["failure_reasons"] = ";".join(failure_reasons)
    return result


def cmd_document_tools_status(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl document-tools status ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        all_targets = bool(getattr(args, "all", False))
        slot_arg = getattr(args, "slot", None)
        if all_targets and slot_arg:
            raise ValueError("provide either TARGET or --all, not both")
        if not all_targets and not slot_arg:
            raise ValueError("provide TARGET or --all")
        if all_targets:
            slots = [binding.linux_account for binding in load_runtime_bindings(state_root) if binding.enabled]
        else:
            slots = [str(slot_arg)]
        results = [_document_tools_status_for_slot(slot, state_root) for slot in slots]
    except Exception as exc:
        print("document_tools_status=fail")
        print(f"reason={exc}")
        return 1

    for result in results:
        if len(results) > 1:
            keys = [
                "target",
                "family",
                "runtime_class",
                "runtime_profile",
                "canonical_recipe_name",
                "probe_status",
                "document_tool_payload",
                "hwp_readiness",
                "document_tools_ready",
                "workspace_guidance_status",
                "locale_utf8",
                "locale_ko_kr",
                "korean_fonts",
                "cmd_libreoffice",
                "cmd_soffice",
                "cmd_hwp5txt",
                "cmd_hwp5proc",
                "cmd_openclaw_document_tools",
                "cmd_openclaw_hwp_text",
            ]
            if result.get("failure_reasons"):
                keys.append("failure_reasons")
            print(" ".join(f"{key}={result.get(key, '')}" for key in keys))
        else:
            for key, value in result.items():
                print(f"{key}={value}")
    failed = [item for item in results if _document_tools_failure_reasons(item)]
    print(f"document_tools_status={'ok' if not failed else 'fail'} count={len(results)} failed={len(failed)}")
    return 0 if not failed else 1
