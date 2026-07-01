"""config migrate now SHOWS what it changes (a diff), so an operator reviews the change
instead of trusting doctor blindly. Secret-looking values are redacted in the diff.
"""
from __future__ import annotations

from agent_runtime_ops.domain.config_contract import config_json_diff


def test_added_removed_changed_and_nested():
    before = {"a": 1, "b": {"x": 1, "y": 2}, "gone": True}
    after = {"a": 1, "b": {"x": 9, "y": 2}, "added": "new"}
    lines = config_json_diff(before, after)
    joined = "\n".join(lines)
    assert "- gone = true" in joined            # removed
    assert "+ added = new" in joined            # added
    assert "~ b.x: 1 -> 9" in joined            # changed, nested path
    assert "b.y" not in joined                  # unchanged not shown


def test_secret_values_are_redacted():
    before = {"provider": {"api_key": "OLD-SECRET"}, "password": "p1"}
    after = {"provider": {"api_key": "NEW-SECRET"}, "password": "p2"}
    joined = "\n".join(config_json_diff(before, after))
    assert "OLD-SECRET" not in joined and "NEW-SECRET" not in joined
    assert "p1" not in joined and "p2" not in joined
    assert "<redacted>" in joined
    assert "provider.api_key" in joined         # the KEY change is still visible, just not the value


def test_llm_incident_is_visible():
    # the real bug: doctor removed agents.defaults.llm (leaving the rest) and set no model.
    before = {"agents": {"defaults": {"llm": {"provider": "openai-codex"}, "keep": 1}}, "model": {"primary": ""}}
    after = {"agents": {"defaults": {"keep": 1}}, "model": {"primary": ""}}
    lines = config_json_diff(before, after)
    joined = "\n".join(lines)
    assert "- agents.defaults.llm" in joined     # operator SEES exactly the removed key
    # model.primary is still empty in both -> the operator can see no model was set to replace it


def test_no_change_empty_diff():
    cfg = {"a": {"b": 1}}
    assert config_json_diff(cfg, dict(cfg)) == []
