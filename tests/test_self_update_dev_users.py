from pathlib import Path

import pytest

from agent_runtime_ops.commands.update import _normalize_dev_users_arg


def test_self_update_dev_users_are_normalized_for_the_installer() -> None:
    assert _normalize_dev_users_arg("openclawdev,atelier") == "openclawdev atelier"
    assert _normalize_dev_users_arg(None) is None


@pytest.mark.parametrize("value", ["", "atelier,atelier", "atelier,root user", "atelier,$bad"])
def test_self_update_dev_users_reject_ambiguous_or_invalid_principals(value: str) -> None:
    with pytest.raises(ValueError, match="unique comma-separated"):
        _normalize_dev_users_arg(value)


def test_self_update_passes_explicit_users_to_the_installer_environment() -> None:
    source = Path("opsctl/agent_runtime_ops/commands/update.py").read_text(encoding="utf-8")
    assert 'env["AGENT_RUNTIME_DEV_USERS"] = dev_users' in source
    assert source.index('env["AGENT_RUNTIME_DEV_USERS"] = dev_users') < source.index(
        'subprocess.run(["bash", str(repo / "install.sh"), "install"], check=True, env=env)'
    )
