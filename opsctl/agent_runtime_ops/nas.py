from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import re
from pathlib import Path

from .paths import state_path
from .state import load_desired_slot
from .yamlio import load_yaml

SMB_SHARE_RE = re.compile(r"^//([^/\\]+)/([^/\\]+)$")
CUSTOMER_SLOT_RE = re.compile(r"^oc[0-9]+$")
SAFE_SHARE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


@dataclass(frozen=True)
class SmbShare:
    source: str
    host: str
    share: str


@dataclass(frozen=True)
class NasPolicyDecision:
    slot: str
    share: SmbShare
    allowed: bool
    reason: str
    matched_grant: str | None
    max_mounts: str | int | None
    mountpoint: Path


def parse_smb_share(source: str) -> SmbShare:
    match = SMB_SHARE_RE.match(source.strip())
    if not match:
        raise ValueError("share must have the form //HOST/SHARE")
    host, share = match.group(1), match.group(2)
    return SmbShare(source=f"//{host}/{share}", host=host.lower(), share=share)


def host_component(host: str) -> str:
    return "host-" + hashlib.sha256(host.lower().encode("utf-8")).hexdigest()[:12]


def share_component(share: str) -> str:
    if SAFE_SHARE_COMPONENT_RE.match(share) and share not in {".", ".."}:
        return share
    return "share-" + hashlib.sha256(share.encode("utf-8")).hexdigest()[:12]


def nas_root(slot: str) -> Path:
    if not CUSTOMER_SLOT_RE.match(slot):
        raise ValueError(f"NAS customer mount is only allowed for ocN slots: {slot}")
    return Path("/home") / slot / "nas_docs"


def mountpoint_for_share(slot: str, share: SmbShare) -> Path:
    root = nas_root(slot)
    mountpoint = root / host_component(share.host) / share_component(share.share)
    resolved_root = root.resolve(strict=False)
    resolved_parent = mountpoint.parent.resolve(strict=False)
    if resolved_parent != resolved_root / host_component(share.host):
        raise ValueError(f"mountpoint escaped NAS root: {mountpoint}")
    return mountpoint


def _grant_patterns(policy_data: dict, slot: str) -> tuple[bool, list[str], str | int | None]:
    defaults = policy_data.get("defaults") if isinstance(policy_data.get("defaults"), dict) else {}
    accounts = policy_data.get("accounts") if isinstance(policy_data.get("accounts"), dict) else {}
    account = accounts.get(slot)
    if not isinstance(account, dict):
        return bool(defaults.get("auto_approve", False)), [], None
    auto_approve = bool(account.get("auto_approve", defaults.get("auto_approve", False)))
    raw_grants = account.get("grants") or []
    grants: list[str] = []
    if isinstance(raw_grants, list):
        for item in raw_grants:
            if isinstance(item, dict) and isinstance(item.get("allow"), str):
                grants.append(item["allow"])
            elif isinstance(item, str):
                grants.append(item)
    return auto_approve, grants, account.get("max_mounts")


def _source_matches(pattern: str, share: SmbShare) -> bool:
    if pattern == "*":
        return True
    parsed = parse_smb_share(pattern.replace("\\", "/")) if pattern.startswith("//") and "*" not in pattern else None
    if parsed is not None:
        return parsed.host == share.host and parsed.share == share.share
    if pattern.startswith("//"):
        normalized = f"//{share.host}/{share.share}"
        pattern_host_lower = re.sub(r"^//([^/]+)/", lambda m: f"//{m.group(1).lower()}/", pattern)
        return fnmatch.fnmatchcase(normalized, pattern_host_lower)
    return False


def check_nas_policy(slot: str, source: str, state_root: Path) -> NasPolicyDecision:
    desired = load_desired_slot(slot, state_root)
    slot_class = desired.lane_data.get("slot_class")
    if slot_class != "customer":
        share = parse_smb_share(source)
        return NasPolicyDecision(slot, share, False, f"slot_class_not_customer:{slot_class}", None, None, Path(""))

    share = parse_smb_share(source)
    mountpoint = mountpoint_for_share(slot, share)
    policy = load_yaml(state_path(state_root, "nas-policy.yaml"))
    auto_approve, grants, max_mounts = _grant_patterns(policy, slot)
    if not auto_approve:
        return NasPolicyDecision(slot, share, False, "auto_approve_disabled", None, max_mounts, mountpoint)
    for pattern in grants:
        if _source_matches(pattern, share):
            return NasPolicyDecision(slot, share, True, "grant_matched", pattern, max_mounts, mountpoint)
    return NasPolicyDecision(slot, share, False, "grant_not_matched", None, max_mounts, mountpoint)
