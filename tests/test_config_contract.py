"""Tests for the self-contained, image-defined config contract.

The product image carries its own config validate/migrate invocations in plain-string
labels (`config-validate.command` / `config-migrate.command`, inherited by the wrapper).
opsctl reads them and runs the product's own commands to (a) gate a rollout on the
on-disk config being valid for the target image before recreate, and (b) migrate the
config on demand via the product's `doctor --fix`. opsctl never reimplements the schema;
trust is anchored by the root-approved image digest.
"""
from __future__ import annotations

import json

import pytest

from agent_runtime_ops.canonical_recipes import canonical_label_values, load_canonical_recipe
from agent_runtime_ops.domain import image_specs
from agent_runtime_ops.domain.image_specs import (
    config_contract_from_image_labels,
    image_recipe_from_wrapper_image,
    image_spec_config_contract,
)
from agent_runtime_ops.domain import config_contract
from agent_runtime_ops.domain.config_contract import (
    CONFIG_VALID_CHECK,
    run_config_migrate_in_image,
    run_config_validate_in_container,
    run_config_validate_in_image,
)


PREFIX = "com.epicevent.agent-runtime."
PRODUCT_IMAGE = "ghcr.io/epicevent/openclaw-jitech@sha256:" + "1" * 64
WRAPPER_IMAGE = "ghcr.io/epicevent/agent-runtime-openclaw@sha256:" + "2" * 64
VALIDATE_COMMAND = "node dist/index.js config validate --json"
MIGRATE_COMMAND = "node dist/index.js doctor --non-interactive --fix --no-workspace-suggestions"


# --------------------------------------------------------------------------- #
# image_specs: read the config contract from the image labels
# --------------------------------------------------------------------------- #

def _valid_labels() -> dict[str, str]:
    recipe = load_canonical_recipe("openclaw-control")
    labels = {PREFIX + key: value for key, value in canonical_label_values(recipe).items() if value}
    labels[PREFIX + "recipe.schema"] = "v1"
    labels[PREFIX + "product-image"] = PRODUCT_IMAGE
    labels[PREFIX + "ops-repo-commit"] = "0" * 40
    return labels


def test_image_without_config_command_has_no_contract(monkeypatch):
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: _valid_labels())
    recipe = image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)
    assert image_spec_config_contract({"image_recipe": recipe}) is None


def test_image_with_config_commands_yields_contract(monkeypatch):
    labels = _valid_labels()
    labels[PREFIX + "config.name"] = "openclaw-config-v1"
    labels[PREFIX + "config-validate.command"] = VALIDATE_COMMAND
    labels[PREFIX + "config-validate.timeout"] = "120"
    labels[PREFIX + "config-migrate.command"] = MIGRATE_COMMAND
    labels[PREFIX + "config-migrate.timeout"] = "180"
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: labels)
    recipe = image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)
    contract = image_spec_config_contract({"image_recipe": recipe})
    assert contract is not None
    assert contract["name"] == "openclaw-config-v1"
    assert contract["validate_command"] == ["node", "dist/index.js", "config", "validate", "--json"]
    assert contract["migrate_command"][:3] == ["node", "dist/index.js", "doctor"]
    assert contract["validate_timeout_seconds"] == 120
    assert contract["migrate_timeout_seconds"] == 180


def test_config_contract_from_image_labels_bootstrap(monkeypatch):
    # Bootstrap path: read the contract straight from a target product image's labels,
    # without full recipe validation (the running image may predate the contract).
    labels = {
        PREFIX + "config.name": "openclaw-config-v1",
        PREFIX + "config-validate.command": VALIDATE_COMMAND,
        PREFIX + "config-migrate.command": MIGRATE_COMMAND,
    }
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: labels)
    contract = config_contract_from_image_labels(PRODUCT_IMAGE)
    assert contract is not None
    assert contract["validate_command"][0] == "node"
    assert contract["migrate_command"][2] == "doctor"
    # an image with no config labels yields None
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: {"other": "x"})
    assert config_contract_from_image_labels(PRODUCT_IMAGE) is None


def test_validate_only_image_has_empty_migrate(monkeypatch):
    labels = _valid_labels()
    labels[PREFIX + "config-validate.command"] = VALIDATE_COMMAND
    monkeypatch.setattr(image_specs, "image_recipe_labels_from_wrapper", lambda _img: labels)
    recipe = image_recipe_from_wrapper_image(WRAPPER_IMAGE, family="openclaw", product_image=PRODUCT_IMAGE)
    contract = image_spec_config_contract({"image_recipe": recipe})
    assert contract is not None
    assert contract["migrate_command"] == []
    assert contract["validate_timeout_seconds"] == 120  # default
    assert contract["migrate_timeout_seconds"] == 180  # default


# --------------------------------------------------------------------------- #
# config_contract: validate/migrate invocation + result interpretation
# --------------------------------------------------------------------------- #

CONTRACT = {
    "name": "openclaw-config-v1",
    "validate_command": ["node", "dist/index.js", "config", "validate", "--json"],
    "migrate_command": ["node", "dist/index.js", "doctor", "--non-interactive", "--fix"],
    "validate_timeout_seconds": 120,
    "migrate_timeout_seconds": 180,
}


class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _capture(monkeypatch, proc):
    seen = {}

    def fake_run_text(argv, timeout=0):
        seen["argv"] = argv
        seen["timeout"] = timeout
        return proc

    monkeypatch.setattr(config_contract, "run_text", fake_run_text)
    return seen


def test_validate_in_container_valid(monkeypatch):
    seen = _capture(monkeypatch, _Proc(0, json.dumps({"valid": True, "path": "/x"})))
    ok, detail = run_config_validate_in_container("cid", CONTRACT)
    assert ok is True
    assert seen["argv"][:3] == ["docker", "exec", "cid"]
    assert seen["argv"][3] == "node"


def test_validate_in_container_invalid_reports_issue_paths(monkeypatch):
    payload = {"valid": False, "issues": [{"path": "agents.defaults", "message": "Invalid input"}]}
    _capture(monkeypatch, _Proc(1, json.dumps(payload)))
    ok, detail = run_config_validate_in_container("cid", CONTRACT)
    assert ok is False
    assert "agents.defaults" in detail


def test_validate_in_image_mounts_readonly_and_overrides_entrypoint(monkeypatch):
    seen = _capture(monkeypatch, _Proc(0, json.dumps({"valid": True})))
    ok, _ = run_config_validate_in_image("img@sha256:abc", _FakePath("/home/oc14/.openclaw"), CONTRACT, run_as="968:968")
    assert ok is True
    argv = seen["argv"]
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "968:968" in argv
    assert "/home/oc14/.openclaw:/home/node/.openclaw:ro" in argv
    assert "--entrypoint" in argv and argv[argv.index("--entrypoint") + 1] == "node"


def test_validate_falls_back_to_exit_code_when_not_json(monkeypatch):
    _capture(monkeypatch, _Proc(0, "not json output"))
    ok, detail = run_config_validate_in_container("cid", CONTRACT)
    assert ok is True
    _capture(monkeypatch, _Proc(1, "boom"))
    ok, detail = run_config_validate_in_container("cid", CONTRACT)
    assert ok is False


def test_validate_tolerates_leading_log_line(monkeypatch):
    out = '[info] loading\n{"valid": false, "issues": [{"path": "x"}]}'
    _capture(monkeypatch, _Proc(0, out))
    ok, detail = run_config_validate_in_container("cid", CONTRACT)
    assert ok is False
    assert "x" in detail


def test_migrate_in_image_mounts_rw_and_runs_as_slot(monkeypatch):
    seen = _capture(monkeypatch, _Proc(0, "Updated config"))
    ok, detail = run_config_migrate_in_image("img@sha256:abc", _FakePath("/home/oc14/.openclaw"), CONTRACT, run_as="968:968")
    assert ok is True
    argv = seen["argv"]
    assert "--user" in argv and argv[argv.index("--user") + 1] == "968:968"
    assert "/home/oc14/.openclaw:/home/node/.openclaw" in argv  # read-write, no :ro
    assert argv[argv.index("--entrypoint") + 1] == "node"
    assert "doctor" in argv


def test_migrate_fails_on_nonzero(monkeypatch):
    _capture(monkeypatch, _Proc(1, "", "fix exploded"))
    ok, detail = run_config_migrate_in_image("img@sha256:abc", _FakePath("/x"), CONTRACT, run_as="1:1")
    assert ok is False
    assert "fix exploded" in detail


def test_no_command_fails_safe(monkeypatch):
    ok, detail = run_config_validate_in_container("cid", {"name": "x"})
    assert ok is False
    ok, detail = run_config_migrate_in_image("img", _FakePath("/x"), {"name": "x"}, run_as="1:1")
    assert ok is False


class _FakePath:
    """Minimal stand-in so the f-string mount path renders without a real filesystem."""

    def __init__(self, value: str):
        self._value = value

    def __str__(self) -> str:
        return self._value


def test_config_valid_check_name_is_stable():
    assert CONFIG_VALID_CHECK == "config_disk_valid_for_running_image_ok"
