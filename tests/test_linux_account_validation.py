from agent_runtime_ops.mcp.validation import linux_account as validate_mcp_linux_account
from agent_runtime_ops.routing import validate_linux_account


def test_linux_account_validation_accepts_real_underscore_accounts() -> None:
    for account in ("remote_usr2", "ro_groupware"):
        assert validate_linux_account(account) == account
        assert validate_mcp_linux_account(account, error_type=ValueError) == account


def test_linux_account_validation_keeps_existing_safety_boundary() -> None:
    for account in ("", "Root", "-bad", "bad.name", "a" * 33):
        for validator in (validate_linux_account, validate_mcp_linux_account):
            try:
                if validator is validate_mcp_linux_account:
                    validator(account, error_type=ValueError)
                else:
                    validator(account)
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted unsafe account: {account!r}")
