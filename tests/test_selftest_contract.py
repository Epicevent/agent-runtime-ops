"""Tests for the self-contained, image-defined selftest contract.

The product image carries the selftest invocation in a plain-string label
(`com.epicevent.agent-runtime.selftest.command`, inherited by the wrapper). The
required checks come from the selftest's OWN JSON output. So the contract is fully
contained in the image; opsctl reads the command from the image, runs it, and gates
on the output's required_checks. Trust is anchored by the root-approved image digest
(`opsctl image approve`), not by the recipe.
"""
from __future__ import annotations

import json

import pytest

from agent_runtime_ops.canonical_recipes import canonical_label_values, load_canonical_recipe
from agent_runtime_ops.domain import image_specs
from agent_runtime_ops.domain.image_specs import (
    image_recipe_from_wrapper_image,
    image_spec_selftest_contract,
)
from agent_runtime_ops.domain.selftest_contract import run_image_selftest_contract


PREFIX = "com.epicevent.agent-runtime."
PRODUCT_IMAGE = "ghcr.io/epicevent/openclaw-jitech@sha256:" + "1" * 64
WRAPPER_IMAGE = "ghcr.io/epicevent/agent-runtime-openclaw@sha256:" + "2" * 64
SELFTEST_COMMAND = "node dist/index.js selftest --json"


# --------------------------------------------------------------------------- #
# image_specs: read the contract command from the image label
# --------------------------------------------------------------------------- #

def _valid_labels() -> dict[str, str]:
    recipe = load_canonical_recipe("openclaw-control")
    labels = {PREFIX + key: value for key, value in canonical_label_values(recipe).items() if value}
    labels[PREFIX + "recipe.schema"] = "v1"
    labels[PREFIX + "product-image"] = PRODUCT_IMAGE
    labels[PREFIX + "ops-repo-commit"] = "0" * 40
    return labels


def test_image_without_selftest_command_has_no_contract(monkeypatch):
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: _valid_labels())
    recipe = image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)
    assert image_spec_selftest_contract({"image_recipe": recipe}) is None


def test_image_with_selftest_command_yields_contract(monkeypatch):
    labels = _valid_labels()
    labels[PREFIX + "selftest.command"] = SELFTEST_COMMAND
    labels[PREFIX + "selftest.name"] = "openclaw-selftest-v1"
    labels[PREFIX + "selftest.timeout"] = "120"
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: labels)
    recipe = image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)
    contract = image_spec_selftest_contract({"image_recipe": recipe})
    assert contract is not None
    assert contract["command"] == ["node", "dist/index.js", "selftest", "--json"]
    assert contract["name"] == "openclaw-selftest-v1"
    assert contract["timeout_seconds"] == 120


# --------------------------------------------------------------------------- #
# run_image_selftest_contract: gate on the OUTPUT's required_checks
# --------------------------------------------------------------------------- #

CONTRACT = {"name": "openclaw-selftest-v1", "command": ["node", "dist/index.js", "selftest", "--json"], "timeout_seconds": 120}
REQUIRED = ["selftest_gateway_ready_ok", "selftest_model_roundtrip_ok", "selftest_executor_nas_roundtrip_ok"]


class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch(monkeypatch, proc):
    monkeypatch.setattr("agent_runtime_ops.domain.selftest_contract.run_text", lambda argv, timeout=0: proc)


def _find(results, name):
    return next(((ok, detail) for ok, n, detail in results if n == name), None)


def test_all_required_from_output_pass(monkeypatch):
    payload = {
        "ok": True,
        "required_checks": REQUIRED,
        "checks": [
            {"name": "selftest_gateway_ready_ok", "ok": True, "detail": "ready"},
            {"name": "selftest_model_roundtrip_ok", "ok": True, "detail": "OK"},
            {"name": "selftest_executor_nas_roundtrip_ok", "ok": True, "detail": "3 entries"},
        ],
    }
    _patch(monkeypatch, _Proc(0, json.dumps(payload)))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_contract_ok")[0] is True
    assert _find(results, "selftest_model_roundtrip_ok")[0] is True


def test_failed_required_from_output_fails_contract(monkeypatch):
    payload = {
        "required_checks": REQUIRED,
        "checks": [
            {"name": "selftest_gateway_ready_ok", "ok": True},
            {"name": "selftest_model_roundtrip_ok", "ok": False, "detail": "timeout"},
            {"name": "selftest_executor_nas_roundtrip_ok", "ok": True},
        ],
    }
    _patch(monkeypatch, _Proc(0, json.dumps(payload)))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_contract_ok")[0] is False
    assert _find(results, "selftest_model_roundtrip_ok")[0] is False


def test_nonzero_exit_with_json_surfaces_per_check_reason(monkeypatch):
    # The product exits non-zero when ok:false, but still prints its JSON verdict on stdout.
    # opsctl must parse it so the FAILING check + reason are visible (not a truncated blob).
    payload = {
        "ok": False,
        "required_checks": REQUIRED,
        "checks": [
            {"name": "selftest_gateway_ready_ok", "ok": True, "detail": "ready"},
            {"name": "selftest_model_roundtrip_ok", "ok": False, "detail": "empty completion: model returned no text"},
            {"name": "selftest_executor_nas_roundtrip_ok", "ok": True, "detail": "ok"},
        ],
    }
    _patch(monkeypatch, _Proc(1, json.dumps(payload)))
    results = run_image_selftest_contract("cid", CONTRACT)
    model = _find(results, "selftest_model_roundtrip_ok")
    assert model is not None and model[0] is False
    assert "empty completion" in model[1]  # the reason survives for diagnosis
    assert _find(results, "selftest_gateway_ready_ok")[0] is True
    assert _find(results, "selftest_contract_ok")[0] is False


def test_missing_required_from_output_backfilled(monkeypatch):
    payload = {"required_checks": REQUIRED, "checks": [{"name": "selftest_gateway_ready_ok", "ok": True}]}
    _patch(monkeypatch, _Proc(0, json.dumps(payload)))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_executor_nas_roundtrip_ok") == (False, "missing_from_selftest")
    assert _find(results, "selftest_contract_ok")[0] is False


def test_nonzero_exit_fails_contract(monkeypatch):
    _patch(monkeypatch, _Proc(1, "", "boom"))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_contract_ok")[0] is False


def test_parse_failure_fails_contract(monkeypatch):
    _patch(monkeypatch, _Proc(0, "not json"))
    results = run_image_selftest_contract("cid", CONTRACT)
    assert _find(results, "selftest_contract_ok")[0] is False


def test_no_command_fails(monkeypatch):
    results = run_image_selftest_contract("cid", {"name": "x", "command": []})
    assert _find(results, "selftest_contract_ok")[0] is False
