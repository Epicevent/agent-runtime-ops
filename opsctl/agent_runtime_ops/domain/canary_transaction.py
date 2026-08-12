"""Content-bound, single-use apply/rollback admission for product canaries.

This is deliberately smaller than the runtime backup transaction.  The backup
transaction protects files; this marker protects the product/wrapper identity
that may be verified during one canary and its one rollback.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from pathlib import Path

from ..host.files import atomic_write_text, fsync_parent
from .common import now_iso


SCHEMA = "agent-runtime-canary-transaction/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TX_ID = re.compile(r"[0-9a-f]{64}\Z")
_SAFE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")


def _path(state_root: Path, slot: str) -> Path:
    if not _SAFE.fullmatch(slot):
        raise ValueError("invalid canary slot")
    return state_root / "canary-transactions" / slot / "transaction.json"


def _receipt_path(state_root: Path, slot: str, transaction_id: str) -> Path:
    if not _TX_ID.fullmatch(transaction_id):
        raise ValueError("invalid canary transaction id")
    return _path(state_root, slot).parent / f"{transaction_id}.receipt.json"


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{field} must be a canonical sha256 digest")
    return value


def _load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("canary transaction is unreadable") from exc
    if not isinstance(value, dict):
        raise ValueError("canary transaction must be an object")
    expected = {
        "backup_metadata_sha256",
        "backup_name",
        "candidate_product_digest",
        "candidate_wrapper_digest",
        "created_at",
        "family",
        "prestate_product_digest",
        "prestate_wrapper_digest",
        "schema",
        "slot",
        "transaction_id",
    }
    if set(value) != expected or value.get("schema") != SCHEMA:
        raise ValueError("canary transaction schema mismatch")
    if not isinstance(value.get("slot"), str) or not _SAFE.fullmatch(value["slot"]):
        raise ValueError("canary transaction slot invalid")
    if not isinstance(value.get("family"), str) or value["family"] not in {"hermes", "openclaw"}:
        raise ValueError("canary transaction family invalid")
    if not isinstance(value.get("transaction_id"), str) or not _TX_ID.fullmatch(value["transaction_id"]):
        raise ValueError("canary transaction id invalid")
    for key in ("candidate_product_digest", "candidate_wrapper_digest", "prestate_product_digest", "prestate_wrapper_digest"):
        _require_digest(value.get(key), key)
    if not isinstance(value.get("backup_name"), str) or not value["backup_name"]:
        raise ValueError("canary transaction backup identity invalid")
    if not isinstance(value.get("backup_metadata_sha256"), str) or not _DIGEST.fullmatch(value["backup_metadata_sha256"]):
        raise ValueError("canary transaction backup digest invalid")
    if not isinstance(value.get("created_at"), str) or not value["created_at"]:
        raise ValueError("canary transaction timestamp invalid")
    return value


def begin(
    state_root: Path,
    *,
    slot: str,
    family: str,
    candidate_product_digest: str,
    candidate_wrapper_digest: str,
    prestate_product_digest: str,
    prestate_wrapper_digest: str,
    backup_name: str,
    backup_metadata_sha256: str,
) -> dict[str, str]:
    """Seal one candidate/prestate pair; a second open transaction is rejected."""
    if family not in {"hermes", "openclaw"}:
        raise ValueError("canary family invalid")
    for key, value in {
        "candidate_product_digest": candidate_product_digest,
        "candidate_wrapper_digest": candidate_wrapper_digest,
        "prestate_product_digest": prestate_product_digest,
        "prestate_wrapper_digest": prestate_wrapper_digest,
        "backup_metadata_sha256": backup_metadata_sha256,
    }.items():
        _require_digest(value, key)
    path = _path(state_root, slot)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ValueError("canary transaction already exists")
    payload = {
        "backup_metadata_sha256": backup_metadata_sha256,
        "backup_name": backup_name,
        "candidate_product_digest": candidate_product_digest,
        "candidate_wrapper_digest": candidate_wrapper_digest,
        "created_at": now_iso(),
        "family": family,
        "prestate_product_digest": prestate_product_digest,
        "prestate_wrapper_digest": prestate_wrapper_digest,
        "schema": SCHEMA,
        "slot": slot,
        "transaction_id": secrets.token_hex(32),
    }
    atomic_write_text(path, json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n", mode=0o600)
    return {key: str(value) for key, value in payload.items()}


def load(state_root: Path, slot: str) -> dict[str, object]:
    path = _path(state_root, slot)
    if not path.exists() or path.is_symlink():
        raise ValueError("canary transaction absent")
    return _load(path)


def require_candidate(state_root: Path, slot: str, *, product_digest: str, wrapper_digest: str) -> dict[str, object]:
    tx = load(state_root, slot)
    if tx["candidate_product_digest"] != _require_digest(product_digest, "product_digest"):
        raise ValueError("candidate product digest mismatch")
    if tx["candidate_wrapper_digest"] != _require_digest(wrapper_digest, "wrapper_digest"):
        raise ValueError("candidate wrapper digest mismatch")
    return tx


def require_prestate(state_root: Path, slot: str, *, product_digest: str, wrapper_digest: str) -> dict[str, object]:
    tx = load(state_root, slot)
    if tx["prestate_product_digest"] != _require_digest(product_digest, "product_digest"):
        raise ValueError("rollback product digest mismatch")
    if tx["prestate_wrapper_digest"] != _require_digest(wrapper_digest, "wrapper_digest"):
        raise ValueError("rollback wrapper digest mismatch")
    return tx


def finish(state_root: Path, slot: str, *, outcome: str, result_product_digest: str, result_wrapper_digest: str) -> Path:
    """Persist a content-free terminal receipt and consume the open exception."""
    if outcome not in {"candidate_succeeded", "rollback_succeeded"}:
        raise ValueError("invalid canary terminal outcome")
    tx = load(state_root, slot)
    _require_digest(result_product_digest, "result_product_digest")
    _require_digest(result_wrapper_digest, "result_wrapper_digest")
    if outcome == "candidate_succeeded":
        require_candidate(state_root, slot, product_digest=result_product_digest, wrapper_digest=result_wrapper_digest)
    else:
        require_prestate(state_root, slot, product_digest=result_product_digest, wrapper_digest=result_wrapper_digest)
    receipt = {
        "candidate_product_digest": tx["candidate_product_digest"],
        "candidate_wrapper_digest": tx["candidate_wrapper_digest"],
        "outcome": outcome,
        "prestate_product_digest": tx["prestate_product_digest"],
        "prestate_wrapper_digest": tx["prestate_wrapper_digest"],
        "receipt_digest": "sha256:" + hashlib.sha256(
            json.dumps({"id": tx["transaction_id"], "outcome": outcome}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "schema": "agent-runtime-canary-receipt/v1",
        "slot": slot,
        "transaction_id": tx["transaction_id"],
    }
    path = _receipt_path(state_root, slot, str(tx["transaction_id"]))
    atomic_write_text(path, json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n", mode=0o640)
    tx_path = _path(state_root, slot)
    tx_path.unlink()
    fsync_parent(tx_path)
    return path
