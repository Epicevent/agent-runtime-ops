from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import re
from pathlib import Path

from .paths import state_path
from .routing import get_runtime_binding, validate_linux_account
from .yamlio import load_yaml

SMB_SHARE_RE = re.compile(r"^//([^/\\]+)/([^/\\]+)$")
SAFE_SHARE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
AGENT_NAS_DIR = ".agent-runtime-nas"


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


_WRITABLE_SHARE_RE = re.compile(r"OC\d+", re.IGNORECASE)


def share_is_writable(share: SmbShare) -> bool:
    """OCn shares hold agent-generated artifacts and mount read-write.
    Customer-data shares (kakao-work, hanpass_groupware, …) stay ro-enforced
    at the operating-tool level by design — this is the only writable class."""
    return _WRITABLE_SHARE_RE.fullmatch(share.share) is not None


_VIEW_SOURCE_RE = re.compile(r"^(?P<base>//[^\[\]]+?)\[(?P<subpath>/[^\[\]]*)\]$")


def parse_cifs_mount_source(source: str) -> tuple[SmbShare, str | None]:
    """Parse a findmnt CIFS SOURCE: //HOST/SHARE or //HOST/SHARE[/subpath].

    The bracket form is the kernel's notation for a bind mount of a subtree —
    the kw-NAS per-view binds appear this way in the live mount inventory.
    Policy is decided on the underlying share; the subpath must stay inside it
    (no empty or dot components), so a view can never widen a grant.
    """
    text = source.strip()
    match = _VIEW_SOURCE_RE.match(text)
    if not match:
        return parse_smb_share(text), None
    subpath = match.group("subpath")
    parts = subpath.split("/")[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"view subpath escapes the share: {subpath}")
    return parse_smb_share(match.group("base")), subpath


def host_component(host: str) -> str:
    return "host-" + hashlib.sha256(host.lower().encode("utf-8")).hexdigest()[:12]


def share_component(share: str) -> str:
    if SAFE_SHARE_COMPONENT_RE.match(share) and share not in {".", ".."}:
        return share
    return "share-" + hashlib.sha256(share.encode("utf-8")).hexdigest()[:12]


def nas_root(slot: str) -> Path:
    return Path("/home") / validate_linux_account(slot) / "nas_docs"


def workspace_root(slot: str) -> Path:
    # What the container sees: a single stable path, bound (bind mount) to the
    # assigned writable mount under nas_rw. Lives OUTSIDE the read-only
    # nas_docs tree, so the container's recursive read_only cannot freeze it.
    return Path("/home") / validate_linux_account(slot) / "workspace"


def nas_rw_root(slot: str) -> Path:
    # Writable (OCn) shares mount here, one place PER SOURCE — same shape as
    # corpus under nas_docs. Two hosts exposing the same share name (old NAS /
    # new NAS during a migration) each get their own spot instead of fighting
    # over a single hardcoded path.
    return Path("/home") / validate_linux_account(slot) / "nas_rw"


def _nested_mountpoint(root: Path, share: SmbShare) -> Path:
    mountpoint = root / host_component(share.host) / share_component(share.share)
    resolved_root = root.resolve(strict=False)
    resolved_parent = mountpoint.parent.resolve(strict=False)
    if resolved_parent != resolved_root / host_component(share.host):
        raise ValueError(f"mountpoint escaped NAS root: {mountpoint}")
    return mountpoint


def mountpoint_for_share(slot: str, share: SmbShare) -> Path:
    if share_is_writable(share):
        return _nested_mountpoint(nas_rw_root(slot), share)
    return _nested_mountpoint(nas_root(slot), share)


def agent_nas_dir(slot: str) -> Path:
    return Path("/home") / slot / AGENT_NAS_DIR


def request_dir(slot: str) -> Path:
    return agent_nas_dir(slot) / "requests"


def history_dir(slot: str, status: str) -> Path:
    return agent_nas_dir(slot) / "history" / status


def customer_credential_path(slot: str, share: SmbShare) -> Path:
    return agent_nas_dir(slot) / "credentials" / host_component(share.host) / f"{share_component(share.share)}.cred"


def root_credential_path(slot: str, share: SmbShare) -> Path:
    return Path("/root") / "agent-runtime-ops" / "nas-credentials" / slot / host_component(share.host) / f"{share_component(share.share)}.cred"


def request_path(slot: str, share: SmbShare) -> Path:
    return request_dir(slot) / f"{host_component(share.host)}--{share_component(share.share)}.env"


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
    binding = get_runtime_binding(slot, state_root)
    # A view (bind mount of a share subtree) is policed as its underlying share:
    # the grant that allows //HOST/SHARE allows every view inside it, and the
    # subpath validation above guarantees a view cannot reach outside the share.
    share, view_subpath = parse_cifs_mount_source(source)
    view_suffix = "_view" if view_subpath else ""
    if binding.runtime_class != "customer":
        return NasPolicyDecision(binding.linux_account, share, False, f"runtime_class_not_customer:{binding.runtime_class}", None, None, Path(""))

    mountpoint = mountpoint_for_share(binding.linux_account, share)
    policy = load_yaml(state_path(state_root, "nas-policy.yaml"))
    auto_approve, grants, max_mounts = _grant_patterns(policy, binding.linux_account)
    if not auto_approve:
        return NasPolicyDecision(slot, share, False, "auto_approve_disabled", None, max_mounts, mountpoint)
    for pattern in grants:
        if _source_matches(pattern, share):
            return NasPolicyDecision(binding.linux_account, share, True, f"grant_matched{view_suffix}", pattern, max_mounts, mountpoint)
    return NasPolicyDecision(binding.linux_account, share, False, f"grant_not_matched{view_suffix}", None, max_mounts, mountpoint)
