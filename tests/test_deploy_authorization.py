"""Developer self-deploy scoping.

A developer account may deploy only to its own dev-* slots; production (oc*) deploys stay
operator/root-only. sudoers cannot scope by `--target` value, so opsctl enforces the
boundary in `_authorize_deploy_target` (defense-in-depth on top of the scoped sudoers grant).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_runtime_ops.commands import rollout
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


def test_capsule_staging_flag_is_dev_only(monkeypatch, capsys):
    monkeypatch.setattr(rollout, "_is_root", lambda: True)
    monkeypatch.setattr(rollout, "_direct_image_spec_from_args", lambda args: {})
    monkeypatch.setattr(rollout, "_append_action_log", lambda *args: None)
    args = SimpleNamespace(
        slot="oc14",
        wrapper_image="wrapper@sha256:" + "1" * 64,
        product_image="product@sha256:" + "2" * 64,
        retrieval_runtime_capsule_sha256="sha256:" + "3" * 64,
        stage_retrieval_runtime_capsule=True,
        retrieval_enabled=True,
        state_root="C:/tmp/agent-runtime-state",
    )
    assert rollout.cmd_rollout_image_canary(args) == 1
    assert "requires a dev-* target" in capsys.readouterr().out


def test_dev_canary_stages_capsule_inside_typed_apply(monkeypatch, capsys):
    monkeypatch.setattr(rollout, "_is_root", lambda: True)
    monkeypatch.setattr(rollout, "_direct_image_spec_from_args", lambda args: {})
    capsule = SimpleNamespace(slot="dev-oc-img", family="openclaw")
    staged = []
    published = []
    monkeypatch.setattr(
        rollout,
        "prepare_dev_runtime_capsule",
        lambda slot, digest: (
            staged.append((slot, digest)) or SimpleNamespace(capsule=capsule)
        ),
    )
    monkeypatch.setattr(
        rollout,
        "publish_prepared_dev_runtime_capsule",
        lambda slot, prepared: published.append((slot, prepared)) or capsule,
    )
    desired = SimpleNamespace(
        slot="dev-oc-img",
        family="openclaw",
        runtime_class="customer",
        image_spec={},
    )
    profile = SimpleNamespace(name="openclaw-customer")
    monkeypatch.setattr(
        rollout,
        "_desired_with_hermes_p1_canary",
        lambda *args, **kwargs: (desired, profile, capsule),
    )
    monkeypatch.setattr(rollout, "_require_retrieval_approval", lambda *args: None)
    monkeypatch.setattr(rollout, "_ensure_runtime_dir", lambda *args: None)
    monkeypatch.setattr(rollout, "_image_spec_canonical_record", lambda *args: {})

    def apply(**kwargs):
        kwargs["prepare_runtime_env"]()
        return 0

    monkeypatch.setattr(
        rollout, "_prepare_runtime_env_for_direct_image", lambda *args: None
    )
    monkeypatch.setattr(rollout, "publish_runtime_capsule_inputs", lambda *args: None)
    monkeypatch.setattr(rollout, "_apply_desired_slot", apply)
    digest = "sha256:" + "3" * 64
    args = SimpleNamespace(
        slot="dev-oc-img",
        wrapper_image="wrapper@sha256:" + "1" * 64,
        product_image="product@sha256:" + "2" * 64,
        retrieval_runtime_capsule_sha256=digest,
        stage_retrieval_runtime_capsule=True,
        retrieval_enabled=True,
        allow_first_apply=False,
        state_root="C:/tmp/agent-runtime-state",
    )
    assert rollout.cmd_rollout_image_canary(args) == 0
    assert staged == [("dev-oc-img", digest)]
    assert len(published) == 1 and published[0][0] == "dev-oc-img"
    assert f"retrieval_capsule_staged={digest}" in capsys.readouterr().out
