from __future__ import annotations

from agent_runtime_ops.root_actions.execution import (
    ExecutionPolicy,
    ExecutionPolicyRegistry,
    OperationAvailability,
    OperationHandlerRegistry,
)


TEST_EXECUTION_POLICIES = ExecutionPolicyRegistry(
    (
        ExecutionPolicy("audit.verify", 1, OperationAvailability.ENABLED, None),
        ExecutionPolicy(
            "projection.staging_selftest",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "agent_loop.campaign_run",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
        ExecutionPolicy(
            "nas.observe_groupware_runtime",
            1,
            OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
            "disabled_unverified_authority",
        ),
    )
)


def make_test_handler_registry(*handlers: object) -> OperationHandlerRegistry:
    return OperationHandlerRegistry(handlers, policies=TEST_EXECUTION_POLICIES)
