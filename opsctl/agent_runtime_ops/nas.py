from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import re
from pathlib import Path, PurePosixPath

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


def canonical_shared_credential_path(share: SmbShare, policy: dict) -> Path | None:
    """공유 코퍼스(kakao/그룹웨어 등 read-only)는 슬롯마다 다른 비밀이 아니라
    ONE 공유 인프라 읽기계정으로 붙는다. 그 credential 은 슬롯이 아니라 스토리지에
    있다 — root 소유 /etc/samba/credentials/*.cred, nas-policy.yaml corpus_credentials
    에 share→cred 로 선언(시스템 fstab 이 이미 쓰는 그 파일과 일치). 매핑 없으면 None.

    권한 경계는 슬롯(컴퓨트)이 아니라 스토리지에 둔다는 원칙의 구현. per-slot 복사본은
    틀 오류(inherited)였고, 이 함수가 그 공유 진실을 opsctl 에 잇는다."""
    mapping = policy.get("corpus_credentials") if isinstance(policy, dict) else None
    if not isinstance(mapping, dict):
        return None
    for pattern, cred in mapping.items():
        if isinstance(cred, str) and cred and _source_matches(str(pattern), share):
            return Path(cred)
    return None


def shared_credential_for_share(share: SmbShare, state_root: Path) -> Path | None:
    """nas-policy.yaml 을 읽어 이 share 의 공유 credential 경로를 돌려준다(있으면)."""
    policy = load_yaml(state_path(state_root, "nas-policy.yaml"))
    return canonical_shared_credential_path(share, policy)


def canonical_shared_master_path(share: SmbShare, policy: dict) -> Path | None:
    """Return the root-declared, already-mounted corpus source for *share*.

    Some corpora are already mounted once for a host collector.  Reusing that
    mount avoids inventing or copying a second NAS credential into every slot;
    the slot still receives only the grant-selected read-only bind mounts.

    This is deliberately an exact share mapping, not a wildcard.  A broad
    pattern must never redirect an unrelated corpus to a privileged host path.
    The value is private root-owned policy, not a CLI supplied path.
    """
    mapping = policy.get("corpus_master_mounts") if isinstance(policy, dict) else None
    if not isinstance(mapping, dict) or share.source not in mapping:
        return None
    raw = mapping.get(share.source)
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"corpus_master_mounts entry for {share.source} must be a non-empty absolute path")
    text = raw.strip()
    if "\x00" in text or "\\" in text:
        raise ValueError(f"corpus_master_mounts entry for {share.source} is not a canonical POSIX path")
    value = PurePosixPath(text)
    if not value.is_absolute() or value == PurePosixPath("/") or any(part in {"", ".", ".."} for part in value.parts[1:]):
        raise ValueError(f"corpus_master_mounts entry for {share.source} must be a confined absolute path")
    return Path(value.as_posix())


def shared_master_for_share(share: SmbShare, state_root: Path) -> Path | None:
    """Load the exact shared master mapping from private nas-policy.yaml."""
    policy = load_yaml(state_path(state_root, "nas-policy.yaml"))
    return canonical_shared_master_path(share, policy)


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
