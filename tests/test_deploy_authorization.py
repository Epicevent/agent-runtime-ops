"""Developer self-deploy scoping.

A developer account may deploy only to its own dev-* slots; production (oc*) deploys stay
operator/root-only. sudoers cannot scope by `--target` value, so opsctl enforces the
boundary in `_authorize_deploy_target` (defense-in-depth on top of the scoped sudoers grant).
"""

from __future__ import annotations

import pytest

from agent_runtime_ops.commands import diagnostics, rollout
from agent_runtime_ops.domain import common


def test_is_dev_slot_boundary():
    assert common.is_dev_slot("dev-oc") is True
    assert common.is_dev_slot("dev-oc-img") is True
    assert common.is_dev_slot("dev-hermes-img") is True
    assert common.is_dev_slot("oc3") is False
    assert common.is_dev_slot("oc14") is False
    assert common.is_dev_slot("") is False
    assert common.is_dev_slot(None) is False


def test_sudo_user_reads_sudo_user_only(monkeypatch):
    # authorization must not fall back to USER (a local/CI user must not read as the caller)
    monkeypatch.setenv("SUDO_USER", "openclawdev")
    monkeypatch.setenv("USER", "root")
    assert common.sudo_user() == "openclawdev"
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert common.sudo_user() == ""  # not via sudo -> empty (a real root shell)


@pytest.mark.parametrize("operator", sorted(common.OPERATOR_ACCOUNTS))
def test_operator_may_deploy_any_target(monkeypatch, operator):
    monkeypatch.setenv("SUDO_USER", operator)
    assert rollout._authorize_deploy_target("image-canary", "oc14") is None
    assert rollout._authorize_deploy_target("image-canary", "dev-oc-img") is None


def test_direct_root_shell_unrestricted(monkeypatch):
    # no SUDO_USER/USER (a real root shell) -> treated as operator, unrestricted
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("USER", raising=False)
    assert rollout._authorize_deploy_target("image-canary", "oc14") is None


def test_developer_scoped_to_dev_slots(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "openclawdev")
    # own dev slots: allowed
    assert rollout._authorize_deploy_target("image-dev-apply", "dev-oc") is None
    assert rollout._authorize_deploy_target("image-canary", "dev-oc-img") is None
    # production: refused with a message
    denial = rollout._authorize_deploy_target("image-canary", "oc14")
    assert denial is not None
    assert "openclawdev" in denial and "oc14" in denial


@pytest.mark.parametrize("operator", sorted(common.OPERATOR_ACCOUNTS))
def test_operator_may_run_live_diagnostics_on_customer(monkeypatch, operator):
    monkeypatch.setenv("SUDO_USER", operator)
    assert diagnostics._authorize_live_diagnostics_target("oc20") is None


def test_direct_root_may_run_live_diagnostics_on_customer(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert diagnostics._authorize_live_diagnostics_target("oc20") is None


def test_developer_live_diagnostics_are_dev_only(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "atelier")
    assert diagnostics._authorize_live_diagnostics_target("dev-hermes-img") is None
    denial = diagnostics._authorize_live_diagnostics_target("oc20")
    assert denial is not None
    assert "atelier" in denial and "oc20" in denial
