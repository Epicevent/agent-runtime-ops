"""Tests for the product-attested selftest contract mechanism.

The mechanism is family-agnostic and dormant until a canonical recipe declares a
`selftest_contract`. To keep these tests independent of whether any shipped recipe
declares one (today none do -- the OpenClaw recipe block ships in a later, image-
coordinated iteration), they build a synthetic recipe-with-contract fixture.

Covers:
  - canonical recipe -> selftest labels (name+digest) + scoped digest + validation
  - image_specs trust chain verifies the selftest labels and exposes the contract
  - run_image_selftest_contract maps the in-image JSON result and gates required checks
"""
from __future__ import annotations

import json

import pytest
import yaml

from agent_runtime_ops.canonical_recipes import (
    canonical_label_values,
    load_canonical_recipe,
    normalized_selftest_contract,
    selftest_contract_digest,
    validate_canonical_recipe,
)
from agent_runtime_ops.paths import RUNTIME_RECIPE_ROOT
from agent_runtime_ops.domain import image_specs
from agent_runtime_ops.domain.image_specs import (
    image_recipe_from_wrapper_image,
    image_spec_selftest_contract,
)
from agent_runtime_ops.domain.selftest_contract import run_image_selftest_contract


PREFIX = "com.epicevent.agent-runtime."
PRODUCT_IMAGE = "ghcr.io/epicevent/openclaw-jitech@sha256:" + "1" * 64
WRAPPER_IMAGE = "ghcr.io/epicevent/agent-runtime-openclaw@sha256:" + "2" * 64

CONTRACT = {
    "name": "openclaw-selftest-v1",
    "command": ["node", "dist/index.js", "selftest", "--json"],
    "required_checks": [
        "selftest_gateway_ready_ok",
        "selftest_model_roundtrip_ok",
        "selftest_executor_nas_roundtrip_ok",
    ],
    "timeout_seconds": 120,
}


@pytest.fixture
def contract_recipe(tmp_path):
    """A real openclaw-control recipe with a selftest_contract block added, loaded
    from a temp recipe root so it exercises the full load->label->validate pipeline."""
    data = yaml.safe_load((RUNTIME_RECIPE_ROOT / "openclaw-control.yaml").read_text(encoding="utf-8"))
    data["selftest_contract"] = dict(CONTRACT)
    root = tmp_path / "recipes"
    root.mkdir()
    (root / "openclaw-control.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return load_canonical_recipe("openclaw-control", recipe_root=root)


# --------------------------------------------------------------------------- #
# canonical recipe: labels, digest, validation
# --------------------------------------------------------------------------- #

def test_recipe_with_contract_emits_selftest_labels(contract_recipe):
    labels = canonical_label_values(contract_recipe)
    assert labels["selftest.name"] == "openclaw-selftest-v1"
    assert labels["selftest.digest"].startswith("sha256:")
    # command/required/timeout are bound by the digest, not carried as labels
    assert "selftest.command" not in labels


def test_selftest_digest_is_deterministic_and_scoped():
    base = {"selftest_contract": dict(CONTRACT), "source_output_target": "/app/dist/control-ui"}
    again = {"selftest_contract": dict(CONTRACT), "source_output_target": "/app/dist/control-ui"}
    assert selftest_contract_digest(base) == selftest_contract_digest(again)
    # scoped to the contract block: an unrelated field change must not move it
    unrelated = {**base, "source_output_target": "/somewhere/else"}
    assert selftest_contract_digest(unrelated) == selftest_contract_digest(base)
    # a contract change does move it
    changed = {**base, "selftest_contract": {**CONTRACT, "timeout_seconds": 99}}
    assert selftest_contract_digest(changed) != selftest_contract_digest(base)


def test_recipes_without_contract_have_empty_selftest_labels():
    for name in ("hermes-workspace", "openclaw-control"):
        labels = canonical_label_values(load_canonical_recipe(name))
        assert labels["selftest.name"] == ""
        assert labels["selftest.digest"] == ""
        assert [n for ok, n, _ in validate_canonical_recipe(load_canonical_recipe(name)) if not ok] == []


def test_validation_passes_for_valid_contract(contract_recipe):
    assert [name for ok, name, _ in validate_canonical_recipe(contract_recipe) if not ok] == []


@pytest.mark.parametrize(
    "contract",
    [
        {"name": "x", "command": [], "required_checks": ["a"], "timeout_seconds": 10},
        {"name": "x", "command": ["node"], "required_checks": [], "timeout_seconds": 10},
        {"name": "", "command": ["node"], "required_checks": ["a"], "timeout_seconds": 10},
        {"name": "x", "command": ["node"], "required_checks": ["a"], "timeout_seconds": 0},
        {"name": "x", "command": ["node"], "required_checks": ["a"]},
    ],
)
def test_normalized_contract_rejects_malformed(contract):
    assert normalized_selftest_contract(contract) is None


def test_validation_flags_malformed_contract(contract_recipe):
    broken = dict(contract_recipe.data)
    broken["selftest_contract"] = {"name": "x", "command": [], "required_checks": [], "timeout_seconds": 0}
    broken_recipe = contract_recipe.__class__(
        name=contract_recipe.name, path=contract_recipe.path, data=broken, digest=contract_recipe.digest
    )
    failures = [name for ok, name, _ in validate_canonical_recipe(broken_recipe) if not ok]
    assert "canonical_selftest_contract_valid" in failures


# --------------------------------------------------------------------------- #
# image_specs trust chain: wrapper labels -> verified contract
# --------------------------------------------------------------------------- #

def _valid_labels(recipe) -> dict[str, str]:
    labels = {PREFIX + key: value for key, value in canonical_label_values(recipe).items() if value}
    labels[PREFIX + "recipe.schema"] = "v1"
    labels[PREFIX + "product-image"] = PRODUCT_IMAGE
    labels[PREFIX + "ops-repo-commit"] = "0" * 40
    return labels


def test_wrapper_image_exposes_verified_selftest_contract(monkeypatch, contract_recipe):
    monkeypatch.setattr(image_specs, "load_canonical_recipe", lambda _name: contract_recipe)
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: _valid_labels(contract_recipe))
    recipe = image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)
    contract = recipe["selftest_contract"]
    assert contract["name"] == "openclaw-selftest-v1"
    assert contract["command"] == ["node", "dist/index.js", "selftest", "--json"]
    assert contract["digest"].startswith("sha256:")
    assert image_spec_selftest_contract({"image_recipe": recipe}) == contract


def test_tampered_selftest_digest_is_rejected(monkeypatch, contract_recipe):
    labels = _valid_labels(contract_recipe)
    labels[PREFIX + "selftest.digest"] = "sha256:" + "0" * 64
    monkeypatch.setattr(image_specs, "load_canonical_recipe", lambda _name: contract_recipe)
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: labels)
    with pytest.raises(ValueError, match="selftest.digest"):
        image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)


def test_tampered_selftest_name_is_rejected(monkeypatch, contract_recipe):
    labels = _valid_labels(contract_recipe)
    labels[PREFIX + "selftest.name"] = "evil-contract"
    monkeypatch.setattr(image_specs, "load_canonical_recipe", lambda _name: contract_recipe)
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: labels)
    with pytest.raises(ValueError, match="selftest.name"):
        image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)


# --------------------------------------------------------------------------- #
# run_image_selftest_contract: mapping + required-check gating
# --------------------------------------------------------------------------- #

class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_proc(monkeypatch, proc):
    monkeypatch.setattr(
        "agent_runtime_ops.domain.selftest_contract.run_text",
        lambda argv, timeout=0: proc,
    )


def _find(results, name):
    return next(((ok, detail) for ok, n, detail in results if n == name), None)


def test_selftest_all_required_pass(monkeypatch):
    payload = {
        "ok": True,
        "checks": [
            {"name": "selftest_gateway_ready_ok", "ok": True, "detail": "ready"},
            {"name": "selftest_model_roundtrip_ok", "ok": True, "detail": "OK"},
            {"name": "selftest_executor_nas_roundtrip_ok", "ok": True, "detail": "3 entries"},
            {"name": "selftest_plugins_loaded_ok", "ok": True, "detail": "adv", "severity": "advisory"},
        ],
    }
    _patch_proc(monkeypatch, _Proc(0, json.dumps(payload)))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_contract_ok")[0] is True
    assert _find(results, "selftest_plugins_loaded_ok") is not None


def test_selftest_failed_required_fails_contract(monkeypatch):
    payload = {
        "checks": [
            {"name": "selftest_gateway_ready_ok", "ok": True},
            {"name": "selftest_model_roundtrip_ok", "ok": False, "detail": "timeout"},
            {"name": "selftest_executor_nas_roundtrip_ok", "ok": True},
        ]
    }
    _patch_proc(monkeypatch, _Proc(0, json.dumps(payload)))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_contract_ok")[0] is False
    assert _find(results, "selftest_model_roundtrip_ok")[0] is False


def test_selftest_missing_required_backfilled(monkeypatch):
    payload = {"checks": [{"name": "selftest_gateway_ready_ok", "ok": True}]}
    _patch_proc(monkeypatch, _Proc(0, json.dumps(payload)))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_executor_nas_roundtrip_ok") == (False, "missing_from_selftest")
    assert _find(results, "selftest_contract_ok")[0] is False


def test_selftest_nonzero_exit_fails_all_required(monkeypatch):
    _patch_proc(monkeypatch, _Proc(1, "", "boom"))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert all(not ok for ok, name, _ in results if name in CONTRACT["required_checks"])
    assert _find(results, "selftest_contract_ok")[0] is False


def test_selftest_parse_failure_fails(monkeypatch):
    _patch_proc(monkeypatch, _Proc(0, "not json"))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_contract_ok")[0] is False
