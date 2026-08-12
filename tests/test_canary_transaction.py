from pathlib import Path

import pytest

from agent_runtime_ops.domain.canary_transaction import begin, finish, require_candidate, require_prestate


P = "sha256:" + "1" * 64
W = "sha256:" + "2" * 64
PP = "sha256:" + "3" * 64
PW = "sha256:" + "4" * 64
B = "sha256:" + "5" * 64


def _begin(tmp_path: Path) -> dict[str, str]:
    return begin(
        tmp_path,
        slot="oc20",
        family="hermes",
        candidate_product_digest=P,
        candidate_wrapper_digest=W,
        prestate_product_digest=PP,
        prestate_wrapper_digest=PW,
        backup_name="20260812T010203+0000",
        backup_metadata_sha256=B,
    )


def test_candidate_and_rollback_are_bound_to_one_transaction(tmp_path: Path) -> None:
    tx = _begin(tmp_path)
    assert require_candidate(tmp_path, "oc20", product_digest=P, wrapper_digest=W)["transaction_id"] == tx["transaction_id"]
    with pytest.raises(ValueError, match="candidate product digest mismatch"):
        require_candidate(tmp_path, "oc20", product_digest=PP, wrapper_digest=W)
    receipt = finish(tmp_path, "oc20", outcome="candidate_succeeded", result_product_digest=P, result_wrapper_digest=W)
    assert receipt.exists()
    with pytest.raises(ValueError, match="canary transaction absent"):
        require_prestate(tmp_path, "oc20", product_digest=PP, wrapper_digest=PW)


def test_rollback_accepts_only_sealed_prestate_and_consumes_exception(tmp_path: Path) -> None:
    _begin(tmp_path)
    with pytest.raises(ValueError, match="rollback wrapper digest mismatch"):
        require_prestate(tmp_path, "oc20", product_digest=PP, wrapper_digest=W)
    receipt = finish(tmp_path, "oc20", outcome="rollback_succeeded", result_product_digest=PP, result_wrapper_digest=PW)
    assert receipt.read_text(encoding="utf-8").find('"outcome":"rollback_succeeded"') >= 0


def test_duplicate_open_transaction_and_cross_slot_are_rejected(tmp_path: Path) -> None:
    _begin(tmp_path)
    with pytest.raises(ValueError, match="already exists"):
        _begin(tmp_path)
    with pytest.raises(ValueError, match="absent"):
        require_candidate(tmp_path, "oc16", product_digest=P, wrapper_digest=W)
